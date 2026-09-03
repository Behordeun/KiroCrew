"""Share ledger — the local record of every live presigned share.

A presigned URL is self-contained: once minted, S3 honours it until it
expires and there is nothing to revoke server-side. What the Access section
can honestly show is therefore a LEDGER: what was shared, when it stops
working, and (approximately) with whom — written at mint time, pruned as
entries expire. "Forget" removes the record; it does not (cannot) kill the
link early, and the UI copy says so.

The ledger stores metadata only — never the URL itself. The URL embeds a
signature that IS the access grant; persisting it would turn the app data
dir into a credential store. It is returned once, to the human who asked.

Storage: ``<app data dir>/shares.json``, atomic-write + sidecar lock, same
pattern as the deploy pending store.
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import uuid
from pathlib import Path
from typing import Any, Optional

from kiro_crew.apps.manager import app_data_dir
from kiro_crew.atomic_write import atomic_write
from kiro_crew.platform_compat import file_lock

logger = logging.getLogger(__name__)

APP_NAME = "aws-control"
_MAX_SHARES = 200
_NOTE_MAX = 120


def _store_path() -> Path:
    return app_data_dir(APP_NAME) / "shares.json"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _load() -> list[dict[str, Any]]:
    """Every recorded share, or ``[]`` when there is nothing readable.

    A DISPLAY read: :func:`list_shares` must render on a store it could not
    load rather than failing the Access section. See :func:`_load_for_update`
    for why a mutation may not stand on the same answer.

    An absent file is silent -- that is a store with no shares yet, not a fault.
    Anything else is logged, because the state this degrades into looks exactly
    like health: an empty Access section renders as "nothing is shared", which
    for a ledger of live presigned URLs is the one wrong answer nobody would
    question.
    """
    try:
        data = json.loads(_store_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        logger.warning(
            "aws-control shares: ledger unreadable; the Access section will render empty",
            exc_info=True,
        )
        return []
    if not isinstance(data, list):
        # The same degradation reached without a parse failure -- same silence
        # problem, same log line.
        logger.warning(
            "aws-control shares: ledger root is not an array; the Access section "
            "will render empty"
        )
        return []
    return data


def _load_for_update() -> list[dict[str, Any]]:
    """The ledger a read-modify-write is allowed to publish over.

    Both mutations below rewrite the WHOLE file from what they read, so an
    empty base is not "nothing to carry forward" -- it is "forget every share
    already recorded". Only a MISSING file makes that true. An unreadable one
    (a transient EACCES/EIO, a scanner holding the handle on Windows) is a
    ledger we still have, and this one is the only local record of live
    PRESIGNED URLs: they are bearer grants that cannot be revoked, so a
    truncated ledger under-reports access that is still working. The error
    propagates and the mutation is abandoned instead.

    Corruption propagates too (#7805, mirroring #7794): a document that failed
    to parse carries nothing to merge into, but "cannot merge into" is not
    "safe to destroy". A truncated file still holds most of its records
    verbatim, and replacing it discards the operator's only chance to recover
    them by hand -- silently, while a refusal costs one skipped mutation and a
    visible error. Two shapes that never reach ``json.loads``'s own raise are
    folded into the same refusal: a byte stream that is not UTF-8 (which
    arrives as ``UnicodeDecodeError`` -- a ``ValueError`` but NOT a
    ``JSONDecodeError``, so left unwrapped it would slip past every corruption
    clause at the callers), and valid JSON whose root is not an array (which
    parses without raising, so normalizing it to ``[]`` would destroy a
    document nobody could read -- the same loss, reached without a parse
    failure).

    Plain ``json.JSONDecodeError`` rather than ops-mission-control's named
    ``CorruptDocumentError``: that type lives in another app and apps do not
    import each other.

    The per-ROW check exists because this reader's return value is not written
    back verbatim: both mutations pipe it through :func:`_prune`, whose damage
    path silently DROPS any row it cannot read an ``expiresAt`` from -- a
    non-object row, a missing stamp, a mangled one -- and the whole-file
    rewrite then takes those rows with it. That is the same coercion loss the
    secret store's strict reader refuses, arriving one call later. So every
    row must hold the one field the retention pass needs to make a
    keep/expire decision; a row it would drop for DAMAGE refuses the mutation,
    while the deliberate expiry drop (a parseable stamp in the past) stays
    what it is: retention, not loss. The refusal names the row's index and
    nothing else -- entry content must not ride on an exception that crosses
    into responses and logs.
    """
    try:
        data = json.loads(_store_path().read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except UnicodeDecodeError as exc:
        raise json.JSONDecodeError(
            f"share ledger is not valid UTF-8: {exc.reason}",
            exc.object.decode("utf-8", "replace")[:120],
            0,
        ) from exc
    if not isinstance(data, list):
        raise json.JSONDecodeError("share ledger root is not a JSON array", str(data)[:120], 0)
    for index, entry in enumerate(data):
        damaged = not isinstance(entry, dict)
        if not damaged:
            try:
                dt.datetime.fromisoformat(entry["expiresAt"])
            except (KeyError, ValueError, TypeError):
                damaged = True
        if damaged:
            raise json.JSONDecodeError(
                f"share ledger entry {index} has no readable expiresAt, so the "
                "retention pass would silently drop it",
                "",
                0,
            )
    return data


def _save(entries: list[dict[str, Any]]) -> None:
    path = _store_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, json.dumps(entries, indent=1))


def _prune(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop entries whose link is already dead."""
    now = _now()
    alive: list[dict[str, Any]] = []
    for entry in entries:
        try:
            expires = dt.datetime.fromisoformat(entry["expiresAt"])
        except (KeyError, ValueError, TypeError):
            continue
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=dt.timezone.utc)
        if expires > now:
            alive.append(entry)
    return alive


def record_share(
    *, account: str, section: str, key: str, expires_secs: int, note: str = ""
) -> dict[str, Any]:
    """Append one share record (called at mint time). Returns the record."""
    entry = {
        "id": str(uuid.uuid4()),
        "account": account,
        "section": section,
        "key": key,
        "createdAt": _now().isoformat(timespec="seconds"),
        "expiresAt": (_now() + dt.timedelta(seconds=expires_secs)).isoformat(timespec="seconds"),
        "note": note[:_NOTE_MAX],
    }
    lock_path = _store_path().with_suffix(".lock")
    _store_path().parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as fd:
        with file_lock(fd.fileno(), exclusive=True, required=True):
            entries = _prune(_load_for_update())
            entries.append(entry)
            _save(entries[-_MAX_SHARES:])
    return entry


def list_shares(account: str = "") -> list[dict[str, Any]]:
    """Live shares, newest first; optionally scoped to one account."""
    entries = _prune(_load())
    if account:
        entries = [e for e in entries if e.get("account") == account]
    return sorted(entries, key=lambda e: e.get("createdAt", ""), reverse=True)


def forget_share(share_id: str) -> Optional[dict[str, Any]]:
    """Remove one record from the ledger (the link itself lives to expiry)."""
    lock_path = _store_path().with_suffix(".lock")
    _store_path().parent.mkdir(parents=True, exist_ok=True)
    with open(lock_path, "w") as fd:
        with file_lock(fd.fileno(), exclusive=True, required=True):
            entries = _prune(_load_for_update())
            kept = [e for e in entries if e.get("id") != share_id]
            removed = next((e for e in entries if e.get("id") == share_id), None)
            _save(kept)
    return removed
