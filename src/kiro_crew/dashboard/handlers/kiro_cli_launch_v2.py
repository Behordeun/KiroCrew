"""The Kiro CLI harness side of "Open in kiro-cli": kiro-cli's v2 session envelope.

A Kiro CLI harness chat's conversation is ``~/.kiro/sessions/cli/<sid>.json``
(the envelope) and ``<sid>.jsonl`` (the log). ``kiro-cli chat --resume-id``
runs the agent the envelope names (``session_state.agent_name``) whatever
``--agent`` says, and keeps the tools it trusts (``session_state.permissions``)
trusted, so the open points the envelope at its launch copy and empties those
grants for the hold, and the release puts both back.

A sandboxed agent can write ``~/.kiro/sessions``, so the envelope is read and
rewritten only through a pinned descriptor of the ``cli`` folder
(:func:`_pinned_cli_dir`), the same pin the v3 store
(:mod:`.kiro_cli_launch_v3`) uses for its session folder. Split from
:mod:`.kiro_cli_launch` (the file-line cap), which re-exports every name here.
"""

from __future__ import annotations

import contextlib
import copy
import errno
import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger("kiro_crew.dashboard.handlers.kiro_cli_launch")


def _unusable(message: str) -> OSError:
    from kiro_crew.dashboard.handlers.kiro_cli_launch import _SessionFileUnusable

    return _SessionFileUnusable(message)


#: The largest session envelope (``<sid>.json``) an open rewrites; kiro-cli's own
#: are a few KB.
_ENVELOPE_MAX_BYTES = 4 * 1024 * 1024


def _open_pinned_file(pin: Any, name: str):
    """Binary reader of regular file *name* in pinned folder *pin*
    (:class:`kiro_crew.platform_compat.PinnedDirectory`). Blocking. The open
    is the pin's own descriptor-relative one (``dir_fd`` on POSIX, by path
    under a rename-proof handle on Windows), so a name resolved from here
    cannot reach outside the folder that was pinned; it refuses a link and
    does not wait on a FIFO, and the descriptor is then checked
    (:func:`_checked_session_fd`)."""
    try:
        fd = pin._open_file(name)  # noqa: SLF001 - the pin's own leaf open
    except IsADirectoryError as exc:
        raise _unusable(f"{name} in {pin.path} is a folder") from exc
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK, errno.ENOTDIR):
            raise _unusable(f"{name} in {pin.path} is a link") from exc
        raise
    from kiro_crew.dashboard.handlers.kiro_cli_launch import _checked_session_fd

    return _checked_session_fd(fd, os.path.join(pin.path, name))


def _write_pinned_file(pin: Any, name: str, text: str) -> None:
    """Replace *name* in pinned folder *pin* with *text*, owner-only. Blocking.
    Through the pin's descriptor where the platform can rename through one
    (POSIX); on Windows the pin keeps the folder from being renamed or replaced
    while it is held, so its path is stable."""
    from kiro_crew import platform_compat
    from kiro_crew.atomic_write import atomic_write

    parent_fd = pin._fd if platform_compat.IS_POSIX else None  # noqa: SLF001
    atomic_write(Path(pin.path) / name, text, mode=0o600, parent_dir_fd=parent_fd)


@contextlib.contextmanager
def _pinned_cli_dir():
    """kiro-cli's v2 session folder (``~/.kiro/sessions/cli``), pinned through
    its parent. Blocking. A sandboxed agent can write ``~/.kiro/sessions``, so
    a ``cli`` that is a link or not a folder raises :class:`_SessionFileUnusable`
    rather than being followed: the envelope this module rewrites must land in
    that folder and nowhere else. Raises ``FileNotFoundError`` when it is not
    there."""
    from kiro_crew import platform_compat
    from kiro_crew.config.paths import kiro_sessions_dir

    cli = kiro_sessions_dir()
    try:
        top = platform_compat.pinned_directory(cli.parent)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _unusable(f"{cli.parent} is a link or not a folder") from exc
    with top:
        if top.is_link(cli.name):
            raise _unusable(f"{cli} is a link")
        try:
            pin = top.child(cli.name)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise _unusable(f"{cli} is a link or not a folder") from exc
        with pin:
            yield pin


def _read_envelope_in(pin: Any, sid: str) -> tuple[Path, dict]:
    """``(path, envelope)`` for session *sid*'s envelope in the pinned v2
    folder. Blocking. Raises ``OSError`` when it is missing, not a regular file
    (a symlink is refused, not followed) or too big, ``ValueError`` when it does
    not read as an envelope with a ``session_state`` object."""
    name = f"{sid}.json"
    path = Path(pin.path) / name
    with _open_pinned_file(pin, name) as fh:
        if os.fstat(fh.fileno()).st_size > _ENVELOPE_MAX_BYTES:
            raise _unusable(f"kiro-cli session envelope {path} is too big")
        raw = fh.read(_ENVELOPE_MAX_BYTES + 1)
    envelope = _json_document(raw, path)
    if not isinstance(envelope, dict) or not isinstance(envelope.get("session_state"), dict):
        raise ValueError(f"kiro-cli session envelope {path} has no session_state object")
    return path, envelope


def _read_envelope(sid: str) -> tuple[Path, dict]:
    """:func:`_read_envelope_in` for a read that writes nothing. Blocking."""
    with _pinned_cli_dir() as pin:
        return _read_envelope_in(pin, sid)


def _json_document(raw: bytes, path: str | Path) -> object:
    """*raw* parsed as JSON. Raises ``ValueError`` for anything that is not,
    one nested past the parser's depth included: a session file is written by
    whatever runs in the chat's sandbox, and a ``RecursionError`` escaping here
    would skip every handler that puts the open back."""
    try:
        return json.loads(raw)
    except RecursionError as exc:
        raise ValueError(f"kiro-cli session file {path} is nested too deeply") from exc


def _write_envelope(pin: Any, path: Path, envelope: dict) -> None:
    """Rewrite the envelope at *path* through the pinned folder it was read from."""
    _write_pinned_file(pin, path.name, json.dumps(envelope))


def _empty_session_grants(permissions: object, project_dir: str) -> None:
    """Empty, in place, the session-level grants of a kiro-cli envelope's
    ``permissions``, at any depth: every list but a ``denied*`` one, and every
    true flag but a ``denied*`` one. Reading *project_dir* -- the open's own
    validated folder, never the envelope's ``cwd``, which an agent can write --
    stays allowed. Denials are kept, and nothing an agent wrote can name a
    grant under a key this does not know."""
    if not isinstance(permissions, dict):
        return
    wanted = os.path.normpath(project_dir) if project_dir else ""
    for key, value in permissions.items():
        if isinstance(key, str) and key.startswith("denied"):
            continue
        if isinstance(value, dict):
            _empty_session_grants(value, project_dir)
        elif isinstance(value, list):
            permissions[key] = (
                [wanted]
                if key == "allowed_read_paths"
                and wanted
                and any(isinstance(p, str) and os.path.normpath(p) == wanted for p in value)
                else []
            )
        elif value is True:
            permissions[key] = False


def _read_session_agent(sid: str) -> dict:
    """What kiro-cli session *sid*'s envelope names and trusts now: the state
    :func:`_point_session_agent` replaces and :func:`_restore_session_agent`
    puts back. Blocking. Raises ``OSError`` or ``ValueError`` when the envelope
    cannot be read."""
    state = _read_envelope(sid)[1]["session_state"]
    return {
        "agent_name": state.get("agent_name"),
        "permissions": copy.deepcopy(state.get("permissions")),
    }


def _point_session_agent(sid: str, agent: str | None, project_dir: str) -> None:
    """Point kiro-cli session *sid* at *agent* for one open and empty its
    session-level grants. Blocking. Raises ``OSError`` or ``ValueError`` when
    the envelope cannot be read or written.

    ``kiro-cli chat --resume-id`` runs the agent the session's envelope names
    (``session_state.agent_name``, the agent the chat last ran) whatever
    ``--agent`` says, and keeps the tools trusted in the session
    (``session_state.permissions``) trusted. So the launch copy reaches the
    terminal only through the envelope, and Crew's session-level grants come
    out of it for the hold. *agent* ``None`` leaves kiro-cli its default agent.
    *project_dir* is the open's validated folder, the one read grant kept.
    """
    with _pinned_cli_dir() as pin:
        path, envelope = _read_envelope_in(pin, sid)
        state = envelope["session_state"]
        state["agent_name"] = agent
        _empty_session_grants(state.get("permissions"), project_dir)
        _write_envelope(pin, path, envelope)


def _restore_session_agent(sid: str, saved: object) -> None:
    """Put back what :func:`_point_session_agent` changed in session *sid*'s
    envelope: the agent it named and its session-level grants. Grants kiro-cli
    added in the terminal go with the hold. Blocking. Raises ``OSError`` when
    the envelope cannot be read or rewritten, for a later retry. An envelope
    kiro-cli removed, or left as something that is not one, has nothing to
    put back."""
    from kiro_crew.dashboard.handlers.kiro_cli_launch import _SID_RE, _SessionFileUnusable

    if not isinstance(saved, dict) or not isinstance(sid, str) or not _SID_RE.match(sid):
        return
    try:
        with _pinned_cli_dir() as pin:
            try:
                path, envelope = _read_envelope_in(pin, sid)
            except FileNotFoundError:
                return
            except (ValueError, _SessionFileUnusable):
                logger.warning("kiro-cli: session %s's envelope does not read as one", sid)
                return
            state = envelope["session_state"]
            state["agent_name"] = saved.get("agent_name")
            if saved.get("permissions") is not None:
                state["permissions"] = saved["permissions"]
            _write_envelope(pin, path, envelope)
    except FileNotFoundError:
        return
