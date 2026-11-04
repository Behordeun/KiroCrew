"""The credential rule table's callers with the internal switch ON.

Each test turns the switch on (or moves it) with a fixture, states its input and
the output it expects, and restores the switch afterwards:

* the display caches and stored verdicts name the engine that computed them, so
  a switch change never serves an answer the other engine produced;
* a vendor key written inside a private-key block does not shrink the block's
  redaction;
* a ``token=`` parameter inside an enclosing ``password=`` value leaves the rest
  of that value redacted;
* a field-name key under a credential key in a recorded frame stays legible.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path

import pytest

from kiro_crew.acp import _frame_record
from kiro_crew.dashboard import chat_utils, display_battery
from kiro_crew.dashboard import display_verdicts as dv
from kiro_crew.dashboard.chat_utils import _prepare_messages
from kiro_crew.security.redaction import redact_credentials
from kiro_crew.security.redaction_rules import compat

KEY = "dashboard_chat-1-1700000000"
#: A word the stand-in battery below redacts only while the rule table runs.
WORD = "codeword-6612"
GH = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
TAG = "[REDACTED: credential]"


@pytest.fixture
def table_on() -> Iterator[None]:
    before = compat.use_rule_table()
    compat.publish_use_rule_table(True)
    try:
        yield
    finally:
        compat.publish_use_rule_table(before)


@pytest.fixture
def switch() -> Iterator[None]:
    """Starts OFF; the test moves it. Restored afterwards."""
    before = compat.use_rule_table()
    compat.publish_use_rule_table(False)
    try:
        yield
    finally:
        compat.publish_use_rule_table(before)


@pytest.fixture
def engine_battery(monkeypatch: pytest.MonkeyPatch) -> Iterator[dict[str, int]]:
    """A credential pass that redacts ``WORD`` only under the rule table; counts calls."""
    calls = {"n": 0}
    real = display_battery.redact_credentials

    def by_engine(text: str):  # type: ignore[no-untyped-def]
        calls["n"] += 1
        if compat.use_rule_table():
            text = text.replace(WORD, "[REDACTED]")
        return real(text)

    monkeypatch.setattr(display_battery, "redact_credentials", by_engine)
    chat_utils._clear_display_redaction_cache()
    yield calls
    chat_utils._clear_display_redaction_cache()


# ── display caches ──────────────────────────────────────────────────────────


def test_a_switch_change_is_not_served_from_the_process_cache(switch, engine_battery):
    """Input ``"see codeword-6612 now"``; off it is kept, on it is redacted, off kept again."""
    text = f"see {WORD} now"
    dv.disable_for_tests()
    assert chat_utils._redact_for_display(text) == text
    compat.publish_use_rule_table(True)
    assert chat_utils._redact_for_display(text) == "see [REDACTED] now"
    compat.publish_use_rule_table(False)
    assert chat_utils._redact_for_display(text) == text


def test_a_switch_change_is_not_served_from_the_preview_caches(switch, engine_battery):
    """The same string object previewed under each engine gets each engine's preview."""
    text = f"see {WORD} now"
    assert chat_utils._redacted_preview(text, 100) == text
    compat.publish_use_rule_table(True)
    assert chat_utils._redacted_preview(text, 100) == "see [REDACTED] now"
    compat.publish_use_rule_table(False)
    assert chat_utils._redacted_preview(text, 100) == text


def test_a_switch_moved_while_the_battery_runs_caches_nothing(switch, engine_battery, monkeypatch):
    """The answer computed while the switch moved is returned but neither cache keeps it."""
    text = f"see {WORD} now"
    real = display_battery.redact_credentials

    def flips(t: str):  # type: ignore[no-untyped-def]
        out = real(t)
        compat.publish_use_rule_table(True)
        return out

    monkeypatch.setattr(display_battery, "redact_credentials", flips)
    assert chat_utils._redact_for_display(text) == text
    monkeypatch.setattr(display_battery, "redact_credentials", real)
    assert chat_utils._redact_for_display(text) == "see [REDACTED] now"


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    (h / "sessions").mkdir(parents=True)
    (h / "sessions" / f"{KEY}.jsonl").write_text("{}\n", encoding="utf-8")
    monkeypatch.setenv("KIROCREW_HOME", str(h))
    monkeypatch.setattr(dv, "rules_version", lambda: b"v" * 16)
    monkeypatch.setattr(dv, "LOAD_AFTER_MISSES", 0)
    dv.disable_for_tests()
    yield h
    dv.disable_for_tests()
    with dv._written_guard:
        dv._written.clear()


def _render(content: str) -> str:
    rows = [{"role": "assistant", "content": content, "cls": "msg msg-a"}]
    with dv.session(KEY):
        out = _prepare_messages(rows, running=False, live_child="", workspace="ws")
    return json.dumps(out)


@pytest.mark.skipif(os.name == "nt", reason="stored verdicts are POSIX-only")
def test_a_stored_verdict_names_the_engine_that_judged_it(
    switch, engine_battery, home: Path, monkeypatch
):
    """Rendered once with the switch off (stored clean), then on in the same process and
    after a restart: ``codeword-6612`` is redacted both times; off again it is kept."""
    monkeypatch.setattr(chat_utils, "allowed_hosts_for", lambda _ws: frozenset())
    assert dv.enable(home)
    content = f"plain words with {WORD} inside"
    assert WORD in _render(content)
    compat.publish_use_rule_table(True)
    assert WORD not in _render(content)
    dv.disable_for_tests()
    chat_utils._clear_display_redaction_cache()
    assert dv.enable(home)
    assert WORD not in _render(content)
    compat.publish_use_rule_table(False)
    assert WORD in _render(content)


def test_the_engine_mark_is_empty_with_the_switch_off(switch):
    """Off, a cache key is the key it always was; on, it carries a mark."""
    assert dv.engine_mark() == b""
    compat.publish_use_rule_table(True)
    assert dv.engine_mark() != b""


# ── private-key blocks ──────────────────────────────────────────────────────

PGP_BLOCK = (
    "-----BEGIN PGP "
    "PRIVATE KEY BLOCK-----\n"
    f"Comment: {GH}\n"
    "\n"
    "lQOYBGVzZXJzZWNyZXRrZXlibG9ja2RhdGFzZWNyZXRrZXlibG9ja2RhdGE=\n"
    "=abcd\n"
    "-----END PGP PRIVATE KEY BLOCK-----"
)
PEM_BLOCK = (
    "-----BEGIN RSA "
    "PRIVATE KEY-----\n"
    f"{GH}\n"
    "MIIEowIBAAKCAQEAsecretkeymaterialsecretkeymaterialsecretkeymat\n"
    "-----END RSA PRIVATE KEY-----"
)


@pytest.mark.parametrize("block", [PGP_BLOCK, PEM_BLOCK], ids=["pgp-comment", "pem-body"])
def test_a_vendor_key_inside_a_private_key_block_keeps_the_whole_block(table_on, block):
    """``before\\n<block holding a GitHub token>\\nafter`` -> ``before\\n[REDACTED: credential]\\nafter``."""
    out, _ = redact_credentials(f"before\n{block}\nafter")
    assert out == f"before\n{TAG}\nafter"


def test_an_unterminated_block_with_a_vendor_key_runs_to_the_end(table_on):
    """A header with no END line: everything from the header on is replaced (decision 1a)."""
    text = "before\n-----BEGIN RSA " "PRIVATE KEY-----\n" + GH + "\nMIIEowIBAAKCAQEAsecretmaterial"
    out, _ = redact_credentials(text)
    assert out == f"before\n{TAG}"


def test_a_vendor_key_outside_a_block_is_unchanged(table_on):
    """A token next to, not inside, a block keeps its own redaction."""
    out, _ = redact_credentials(f"{GH}\n{PEM_BLOCK}")
    assert out == f"{TAG}\n{TAG}"


# ── token= inside password= ─────────────────────────────────────────────────


def test_a_token_param_inside_a_password_value_keeps_the_password_redacted(table_on):
    """``password=abc&token=abcdef0123456789 next``: the password, the token and the
    rest of the password line are all replaced; the ``&token=`` head stays."""
    out, _ = redact_credentials("password=abc&token=abcdef0123456789 next")
    assert out == f"password={TAG}&token={TAG} {TAG}"


def test_a_query_password_beside_a_token_param_is_unchanged(table_on):
    """``url?password=s3cr3t&token=...`` was already right: both values replaced."""
    out, _ = redact_credentials("url?password=s3cr3t&token=abcdef0123456789xyz next")
    assert out == f"url?password={TAG}&token={TAG} next"


# ── recorded frames ─────────────────────────────────────────────────────────


@pytest.fixture
def frames(monkeypatch):
    _frame_record._reset_for_tests()
    monkeypatch.delenv(_frame_record.ENV_RECORD_FRAMES, raising=False)


def test_a_field_name_key_under_a_credential_key_stays_legible(table_on, frames):
    """``{"Authorization": {"value": "Basic dXNlcjpwYXNz"}}`` keeps the ``value`` key."""
    out = json.loads(_frame_record.scrub_frame({"Authorization": {"value": "Basic dXNlcjpwYXNz"}}))
    assert out == {"Authorization": {"value": TAG}}


def test_a_nested_field_name_key_keeps_the_outer_context(table_on, frames):
    """``{"headers": {"Authorization": {"value": "Bearer sk-..."}}}``: key kept, token replaced."""
    token = "Bearer sk-inner-0123456789abcdef0123456789abcdef"
    out = json.loads(_frame_record.scrub_frame({"headers": {"Authorization": {"value": token}}}))
    assert out == {"headers": {"Authorization": {"value": TAG}}}


def test_a_non_field_key_under_a_credential_key_is_still_replaced(table_on, frames):
    """``{"Authorization": {"Basic dXNlcjpwYXNz": true}}``: the key is the secret."""
    out = json.loads(_frame_record.scrub_frame({"Authorization": {"Basic dXNlcjpwYXNz": True}}))
    assert out == {"Authorization": {TAG: TAG}}


def test_recorded_session_token_keys_keep_the_switch_off_output(switch, frames):
    """The legacy joined-label check redacts a session token used as a key."""
    key = "FQoGZXIvYXdzEJr"
    out = json.loads(_frame_record.scrub_frame({"SessionToken": {key: 1}}))
    assert out == {"SessionToken": {TAG: TAG}}


def test_recorded_password_keys_are_checked_with_their_ancestor(table_on, frames):
    out = json.loads(_frame_record.scrub_frame({"password": {"hunter2": True}}))
    assert out == {"password": {TAG: TAG}}


@pytest.mark.parametrize("keys", [("Authorization", "password"), ("password", "Authorization")])
def test_an_authorization_ancestor_does_not_skip_other_credential_ancestors(table_on, keys):
    assert _frame_record._scrub_dict_key(keys, "hunter2", "") == TAG


@pytest.mark.parametrize("ancestor", ["Authorization", "Proxy-Authorization", "X-Authorization"])
def test_recorded_authorization_field_names_remain_legible(table_on, frames, ancestor):
    out = json.loads(_frame_record.scrub_frame({ancestor: {"value": "opaque-example"}}))
    assert out == {ancestor: {"value": TAG}}
