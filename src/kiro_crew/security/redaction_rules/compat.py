"""The credential rule table in pass 1's place, in the old plan's shape.

:func:`kiro_crew.security.redaction._credential_redaction_plan` is the one plan
every credential entry point splices (``redact_credentials``,
``redact_credentials_with_records``, ``pass_compose``). With the internal
switch (:func:`use_rule_table`) ON it calls :func:`credential_plan_via_table`, which
turns the table's resolved hits into pass 1's spans, warnings and rules, then runs
the old passes 2-4 (base64-encoded credentials, bare secret keys with their link,
SRI, ARN and ``code_text`` exemptions, ``token=`` parameters with their companion
prefix seam) after it exactly as they ran after pass 1. Only pass 1 moves.

Shapes kept
-----------
* spans are ``(start, end, tag)``, sorted and disjoint, tag
  :data:`~kiro_crew.security.redaction.REDACTED_CREDENTIAL_TAG`;
* one ``Redacted credential pattern (N chars)`` warning per table span, in text
  order, before every pass 2-4 warning;
* ``rules`` maps each span's start to ``(rule, label)`` with the OLD rule names
  (``github_token``, ``aws_secret_access_key``, ...): the source cards read them
  (``credential_sources._AWS_TEMPLATE_KEYS``) and refuse a dotted id. The label
  is the AWS field the value sat under, as pass 1 reported it, and it is part of
  the replaced span as it was in pass 1.

Identifier hits (AWS access key IDs, Twilio account SIDs) are resolved and kept.
A hit inside a private-key block is folded into the block, which is replaced
whole. A name-keyed value that encloses a ``token=`` parameter is replaced
around that parameter, which pass 4 handles.

Fail-closed
-----------
Any error building the table's part of the plan, or loading the table at all,
yields one span over the WHOLE text with
:data:`~kiro_crew.security.redaction.REDACTION_UNAVAILABLE_TAG`, one value-free
warning, rule :data:`~kiro_crew.security.redaction.REDACTION_UNAVAILABLE_RULE`,
a log line naming only the error's type, and one count on
:data:`FAIL_CLOSED_METRIC`. It never raises and never returns the raw text.

The removed values
------------------
The credential-source cards need each removed value to find which tool output it
came from. They get it the way they always have: ``CredentialMatch.value`` from
``redact_credentials_with_records``, an in-memory field its callers fingerprint
and drop; it is never stored, logged or sent. The table's own records, the
warnings, the log line and the metric carry no value.

Switch
------
:func:`use_rule_table` reads a module flag that only code sets
(:func:`publish_use_rule_table`; the table tests turn it on). It is OFF by
default and there is no user setting for it yet, so the credential plan runs
pass 1 and nothing table-related runs unless a caller turns it on.
"""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Collection

import kiro_crew.security.redaction as redaction
from kiro_crew.security.redaction_rules.detectors import detect
from kiro_crew.security.redaction_rules.model import NAME_DETECTORS, Detector, Hit
from kiro_crew.security.redaction_rules.redact import _PLACEHOLDER_RE, hits
from kiro_crew.security.redaction_rules.rules import RuleTable, load_table

logger = logging.getLogger(__name__)

#: Counted once per fail-closed plan. No attributes: nothing about the text.
FAIL_CLOSED_METRIC = "kirocrew.security.redaction.fail_closed"

_Span = tuple[int, int, str]
_Plan = tuple[list[_Span], list[str], dict[int, tuple[str, str]]]

#: Table rule id -> the rule name pass 1 recorded for the same value. A rule the
#: old pass had no name for is ``credential_pattern``, its catch-all.
_OLD_RULE: dict[str, str] = {
    "github.classic": "github_token",
    "github.fine_grained": "github_token",
    "github.unverified": "github_token",
    "slack.token_unverified": "slack_token",
    "gitlab.pat_unverified": "gitlab_token",
    "stripe.key_unverified": "stripe_key",
    "sendgrid.key_unverified": "sendgrid_key",
    "openai.key_unverified": "openai_key",
    "anthropic.key_unverified": "anthropic_key",
    "npm.token_unverified": "npm_token",
    "pypi.token_unverified": "pypi_token",
    "digitalocean.token_unverified": "digitalocean_token",
    "google.oauth_client_secret_unverified": "google_oauth_secret",
    "jwt.unverified": "jwt",
    "link_token.unverified": "jwt",
    "pem.private_key_unterminated": "private_key",
    "slack.token": "slack_token",
    "stripe.key": "stripe_key",
    "openai.key": "openai_key",
    "anthropic.key": "anthropic_key",
    "google.oauth_client_secret": "google_oauth_secret",
    "telegram.token": "telegram_bot_token",
    "discord.token": "discord_bot_token",
    "gitlab.pat": "gitlab_token",
    "npm.token": "npm_token",
    "pypi.token": "pypi_token",
    "sendgrid.key": "sendgrid_key",
    "digitalocean.token": "digitalocean_token",
    "pem.private_key": "private_key",
    "pgp.private_key": "private_key",
    "url.userinfo_password": "url_userinfo",
    "jwt": "jwt",
    "jwe": "jwt",
    "link_token": "jwt",
    "aws.secret_access_key": "aws_secret_access_key",
    "url.credential_param": "token_parameter",
}

#: The row that matches an AWS field name glued to a longer run, label included.
_GLUED_AWS_RULE = "aws.secret_field_glued"

#: The AWS field labels pass 1 named, matched as the text right before a value.
#: Same key spellings and separator shape as ``redaction._AWS_LABEL_RULES``.
_AWS_LABEL_BEFORE: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(rf"(?:{keys})[\"']?\s{{0,8}}[:=]\s{{0,8}}[\"']?$"), rule)
    for keys, rule in (
        ("SecretAccessKey|aws_secret_access_key", "aws_secret_access_key"),
        ("SessionToken|aws_session_token", "aws_session_token"),
        ("AccessKeyId|aws_access_key_id", "aws_access_key_id"),
    )
)
#: How far back a label may start: the longest key, quotes and blanks.
_LABEL_LOOKBACK = 48

#: A ``token=`` parameter head (separator, name, equals, any spelling pass 4
#: reads) ending where a value starts. Pass 4 owns that value, including the
#: ``${`` placeholder it keeps, which its own value regex never matches.
_TOKEN_PARAM_HEAD_RE = re.compile(
    rf"{redaction._TOKEN_PARAM_SEP_RE}(?ai:{redaction._TOKEN_PARAM_NAME_RE})"
    rf"{redaction._TOKEN_PARAM_EQ_RE}\Z"
)
#: How far back that head may start: every letter as an HTML reference.
_TOKEN_PARAM_HEAD_LOOKBACK = 200


def is_token_param_placeholder(text: str, start: int) -> bool:
    """Whether a ``${`` placeholder at ``start`` is a ``token=`` value, which pass 4 keeps."""
    if not text.startswith("${", start):
        return False
    head = text[max(0, start - _TOKEN_PARAM_HEAD_LOOKBACK) : start]
    return _TOKEN_PARAM_HEAD_RE.search(head) is not None


def _aws_label(text: str, start: int) -> tuple[str, str] | None:
    """``(rule, label)`` when an AWS field label ends right at ``start``."""
    head = text[max(0, start - _LABEL_LOOKBACK) : start]
    for pattern, rule in _AWS_LABEL_BEFORE:
        m = pattern.search(head)
        if m is not None and (m.start() == 0 or not _is_key_char(head[m.start() - 1])):
            return rule, m.group()
    return None


def _is_code_literal(text: str, hit: Hit) -> bool:
    """The value is a code table pass 3 spares in code: an ordered alphabet or a data URI.

    A table of symbols often ends its letters and digits with punctuation
    (``...xyz0123456789#$%&``), which pass 3 never reads as part of a key, so
    trailing characters that are neither letters nor digits are set aside first.
    """
    value = text[hit.start : hit.end]
    core = value.rstrip("".join(c for c in set(value) if not c.isalnum()))
    return bool(core) and redaction._is_code_literal(text, hit.start, core)


def _is_key_char(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _rule_and_span(hit: Hit, text: str) -> tuple[str, str, int]:
    """The old ``(rule, label)`` for ``hit`` and where its replaced span starts."""
    if hit.rule_id == _GLUED_AWS_RULE:
        # The legacy spelling, label in the match: name it as pass 1 did.
        rule, label = redaction._pass1_rule(text[hit.start : hit.end])
        return rule, label, hit.start
    if hit.detector in (Detector.LABELLED, Detector.KEY_ID_PAIR):
        aws = _aws_label(text, hit.start)
        if aws is not None:
            rule, label = aws
            return rule, label, hit.start - len(label)
    return _OLD_RULE.get(hit.rule_id, "credential_pattern"), "", hit.start


# ── Switch ──

_USE_RULE_TABLE = False
_PUBLISH_LOCK = threading.Lock()


def publish_use_rule_table(enabled: bool) -> None:
    """Set what :func:`use_rule_table` answers. Code only; no user setting reads it yet."""
    global _USE_RULE_TABLE
    with _PUBLISH_LOCK:
        _USE_RULE_TABLE = bool(enabled)


def use_rule_table() -> bool:
    """Whether the credential plan uses the rule table (True) or pass 1 (False)."""
    return _USE_RULE_TABLE


# ── Table ──

#: Set once a load fails, so a broken table costs one failed read per process
#: rather than one per call; every plan then fails closed.
_LOAD_FAILED = False


def _table() -> RuleTable:
    global _LOAD_FAILED
    if _LOAD_FAILED:
        raise RuntimeError("credential rule table unavailable")
    try:
        return load_table()
    except Exception:
        _LOAD_FAILED = True
        raise


def check_table_health() -> bool:
    """Load the table now; False (logged, plans fail closed) if it cannot load.

    Nothing calls this at gateway start while the switch is off; it reports a
    broken table before the first message once something does.
    """
    try:
        _table()
    except Exception as exc:
        # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure -- logs the exception type only, never the text or a value
        logger.error(
            "credential rule table failed to load (%s); credential redaction will "
            "replace whole texts until it is fixed",
            type(exc).__name__,
        )
        return False
    return True


# ── Plan ──

_counting = threading.local()


def _count_fail_closed() -> None:
    """One count on :data:`FAIL_CLOSED_METRIC`, best effort and never re-entered."""
    if getattr(_counting, "active", False):
        return
    _counting.active = True
    try:
        from kiro_crew.metrics.provider import get_recorder

        get_recorder().counter(
            FAIL_CLOSED_METRIC,
            description="Credential redaction replaced a whole text because its rule table failed.",
        )
    except Exception:  # telemetry must never break redaction
        pass
    finally:
        _counting.active = False


def _fail_closed(text: str, exc: BaseException) -> _Plan:
    # nosemgrep: python.lang.security.audit.logging.logger-credential-leak.python-logger-credential-disclosure -- logs the exception type only, never the text or a value
    logger.warning("credential redaction failed (%s); whole text replaced", type(exc).__name__)
    _count_fail_closed()
    return (
        [(0, len(text), redaction.REDACTION_UNAVAILABLE_TAG)],
        ["Redaction unavailable: whole text replaced"],
        {0: redaction.REDACTION_UNAVAILABLE_RECORD},
    )


#: The rows that match a whole private-key block. Everything between a block's
#: armour lines is key material, so the block is replaced whole.
_KEY_BLOCK_RULES = ("pem.private_key", "pgp.private_key", "pem.private_key_unterminated")

#: Characters trimmed from the edges of what is left of a name-keyed value once
#: a ``token=`` parameter is cut out of it.
_PIECE_EDGE = " \t,;"


_block_tables: dict[int, tuple[RuleTable, RuleTable]] = {}


def _block_table(table: RuleTable) -> RuleTable:
    """``table`` cut down to its key-block rows (built once per loaded table)."""
    held = _block_tables.get(id(table))
    if held is not None and held[0] is table:
        return held[1]
    rows = tuple(r for r in table.rules if r.id in _KEY_BLOCK_RULES)
    blocks = RuleTable(rules=rows, allow=table.allow, label_exclude=table.label_exclude)
    _block_tables.clear()
    _block_tables[id(table)] = (table, blocks)
    return blocks


def _key_blocks(text: str, table: RuleTable, resolved: list[Hit]) -> list[Hit]:
    """Every private-key block in ``text``, outermost first, as hits.

    The resolution keeps the more certain detector where hits overlap, so a
    vendor key written inside a block (a token in a PGP ``Comment:`` line) would
    otherwise win its few characters and leave the rest of the block in the
    clear. The blocks are found by the table's own detector over its key-block
    rows, so they are exactly the hits the resolution dropped. Nothing is
    scanned again when every resolved hit is already a block. A block that cuts
    across an existing placeholder is skipped, as the resolution skips it.
    """
    if "PRIVATE" not in text or all(h.rule_id in _KEY_BLOCK_RULES for h in resolved):
        return []
    placeholders = [m.span() for m in _PLACEHOLDER_RE.finditer(text)]
    blocks = [
        block
        for block in detect(_block_table(table), text)
        if not any(
            block.start < e and s < block.end and not (block.start <= s and e <= block.end)
            for s, e in placeholders
        )
    ]
    blocks.sort(key=lambda h: (h.start, -h.end))
    outer: list[Hit] = []
    for block in blocks:
        if not outer or block.start >= outer[-1].end:
            outer.append(block)
    return outer


def _with_key_blocks(resolved: list[Hit], blocks: list[Hit]) -> list[Hit]:
    """``resolved`` with every hit a key block overlaps folded into that block."""
    if not blocks:
        return resolved
    out: list[Hit] = []
    pending = list(resolved)
    for block in blocks:
        start, end = block.start, block.end
        rest: list[Hit] = []
        for hit in pending:
            if hit.start < end and start < hit.end:
                start, end = min(start, hit.start), max(end, hit.end)
            else:
                rest.append(hit)
        pending = rest
        out.append(Hit(block.rule_id, block.tier, block.detector, start, end))
    out.extend(pending)
    out.sort(key=lambda h: (h.start, h.end))
    # Folding a straddling hit can make two blocks meet; join them.
    joined: list[Hit] = []
    for hit in out:
        if joined and hit.start < joined[-1].end:
            last = joined[-1]
            joined[-1] = Hit(
                last.rule_id, last.tier, last.detector, last.start, max(last.end, hit.end)
            )
        else:
            joined.append(hit)
    return joined


def _outside_token_params(hit: Hit, text: str, params: list[tuple[int, int]]) -> list[Hit]:
    """The pieces of a name-keyed ``hit`` outside every ``token=`` parameter it overlaps.

    A ``token=`` parameter's value is pass 4's, with its companion prefix seam,
    template-placeholder edge and stream deferral, so the table leaves that
    parameter alone. The rest of an enclosing value (``password=abc&token=...``)
    is still this hit's and is still replaced.
    """
    pieces: list[Hit] = []
    cursor = hit.start
    for p_start, p_end in params:
        if p_end <= cursor or p_start >= hit.end:
            continue
        pieces.append(Hit(hit.rule_id, hit.tier, hit.detector, cursor, max(cursor, p_start)))
        cursor = max(cursor, p_end)
    pieces.append(Hit(hit.rule_id, hit.tier, hit.detector, cursor, max(cursor, hit.end)))
    kept: list[Hit] = []
    for piece in pieces:
        value = text[piece.start : piece.end]
        lead = len(value) - len(value.lstrip(_PIECE_EDGE))
        trail = len(value) - len(value.rstrip(_PIECE_EDGE))
        start, end = piece.start + lead, piece.end - trail
        if start < end:
            kept.append(Hit(hit.rule_id, hit.tier, hit.detector, start, end))
    return kept


def _table_pass(text: str) -> _Plan:
    """Pass 1's ``(taken, warnings, rules)``, from the rule table's hits."""
    taken: list[_Span] = []
    warnings: list[str] = []
    rules: dict[int, tuple[str, str]] = {}
    token_params: list[tuple[int, int]] | None = None
    code_text = not redaction.bare_secret_pass_enabled()
    table = _table()
    resolved = hits(text, table)
    for found in _with_key_blocks(resolved, _key_blocks(text, table, resolved)):
        if not found.tier.redacts:
            continue
        if code_text and found.detector in NAME_DETECTORS and _is_code_literal(text, found):
            # Inside `redaction_switch.code_text()` an ordered alphabet or a data
            # URI payload is code as its author wrote it, whatever name it sits
            # under, as the legacy passes left it.
            continue
        pieces = [found]
        if found.detector in NAME_DETECTORS:
            if is_token_param_placeholder(text, found.start):
                # A `${` placeholder under `token=` is pass 4's to keep.
                continue
            if token_params is None:
                token_params = [m.span() for m in redaction._TOKEN_PARAM_RE.finditer(text)]
            if any(s < found.end and found.start < e for s, e in token_params):
                pieces = _outside_token_params(found, text, token_params)
        for hit in pieces:
            rule, label, start = _rule_and_span(hit, text)
            if (taken and start < taken[-1][1]) or hit is not pieces[0]:
                # A label never reaches into an earlier span, and only the first
                # piece of a split value sits right after its label: keep the
                # value alone.
                rule, label, start = _OLD_RULE.get(hit.rule_id, "credential_pattern"), "", hit.start
            taken.append((start, hit.end, redaction.REDACTED_CREDENTIAL_TAG))
            rules[start] = (rule, label)
            warnings.append(f"Redacted credential pattern ({hit.end - start} chars)")
    return taken, warnings, rules


def credential_plan_via_table(
    text: str,
    defer_token_param: bool = False,
    judged_sri_values: Collection[str] = (),
) -> _Plan:
    """The credential plan with the rule table in pass 1's place. Never raises.

    Arguments and result are ``redaction._credential_redaction_plan``'s; the
    owner-view bypass is decided by that caller before this runs.
    """
    try:
        if not isinstance(text, str):
            raise TypeError("text must be a str")
        taken, warnings, rules = _table_pass(text)
        return redaction._later_passes(
            text,
            taken,
            warnings,
            rules,
            defer_token_param=defer_token_param,
            judged_sri_values=judged_sri_values,
        )
    except Exception as exc:
        return _fail_closed(text if isinstance(text, str) else "", exc)
