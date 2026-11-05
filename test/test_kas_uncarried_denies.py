"""A spec's ``deniedCommands`` entry KAS cannot carry is still refused, by Crew's gate.

On KAS each kiro-cli ``deniedCommands`` regex rides the policy as a glob
``deny``. An entry with no glob spelling (``.*\\bcurl\\b.*``) reaches KAS as no
rule, so the projection records it (``kas_spec_denies.uncarried_shell_denies``),
the session handle stamps it on its own agent's permission requests, and the
gate's ``spec-denied-commands`` row refuses a shell call it matches.
"""

from __future__ import annotations

import fnmatch
import logging
from pathlib import Path
from typing import Any

import pytest
from test_kas_spec_builtin_grant import _handle, _permission
from test_tool_call_classification_kas import _kas_builtin_flow

from kiro_crew import permission_floor
from kiro_crew.acp import kas_agents
from kiro_crew.acp._dispatch import attach_kas_custom_agents
from kiro_crew.acp.harness.kas import KasHarness
from kiro_crew.acp.kas_permissions import tools_settings_to_permissions
from kiro_crew.acp.types import AcpEvent
from kiro_crew.acp_backends import ACP_BACKEND_KAS
from kiro_crew.hooks import TOOL_DENY, HookManager, HooksConfig, hook_gate_kwargs
from kiro_crew.platform import context as ctx_mod
from kiro_crew.platform import governance_profiles as gp

_UNCARRIED = r".*\bcurl\b.*"
_CARRIED = "curl.*"


def _settings(*denied: Any) -> dict[str, Any]:
    return {"execute_bash": {"deniedCommands": list(denied)}}


@pytest.fixture(autouse=True)
def _no_profiles(tmp_path: Path, _floor_monkeypatch: pytest.MonkeyPatch):
    profiles = tmp_path / "profiles"
    profiles.mkdir()
    _floor_monkeypatch.setattr(gp, "_PROFILES_DIR", profiles)
    gp.reset_store()
    yield
    gp.reset_store()
    ctx_mod.reset_context()


def _entry(settings: dict[str, Any]) -> dict[str, Any]:
    spec = {"name": "probe", "prompt": "p", "tools": ["execute_bash"], "toolsSettings": settings}
    return kas_agents.to_client_custom_agent("probe", spec, "p")


def _own_request(command: str, settings: dict[str, Any]) -> AcpEvent:
    """The permission event the session handle builds for its own agent's shell
    call, with the record the projection of a spec carrying *settings* registered."""
    handle = _handle(ACP_BACKEND_KAS)
    KasHarness.record_session_projection(
        object.__new__(KasHarness), handle, [_entry(settings)], "probe"
    )
    event = _kas_builtin_flow(
        "run_command", title="Run Command", kind="execute", raw_input={"command": command}
    )
    stamped = handle._build_permission_event(_permission("own-sid"))
    assert stamped is not None
    event.spec_uncarried_denies = getattr(stamped, "spec_uncarried_denies", None)
    return event


def _judge(event: AcpEvent):
    return HookManager(HooksConfig()).on_tool_call(event.title, **hook_gate_kwargs(event))


def test_a_deny_kas_cannot_carry_is_still_refused() -> None:
    settings = _settings(_UNCARRIED)
    # KAS gets no rule for it: the translation names it as lost.
    block, lost = tools_settings_to_permissions(settings)
    assert block is None and "execute_bash.deniedCommands" in lost
    verdict = _judge(_own_request("curl x", settings))
    assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands")
    assert _UNCARRIED in verdict.reason
    # A deny, so an auto-mode job refuses it too instead of running it.
    reason = permission_floor.refusal_for(
        _own_request("curl x", settings), session_key="cron:probe", security_only=False
    )
    assert reason is not None and "deniedCommands" in reason


def test_a_segment_of_a_chained_command_is_refused() -> None:
    verdict = _judge(_own_request("cd /w && curl x", _settings(_UNCARRIED)))
    assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands")


def test_a_command_no_entry_matches_still_runs() -> None:
    verdict = _judge(_own_request("ls -la", _settings(_UNCARRIED)))
    assert verdict.tier != "spec-denied-commands"
    assert verdict.action != TOOL_DENY


def test_an_entry_that_does_not_compile_refuses_every_command(caplog) -> None:
    broken = "curl(("
    with caplog.at_level(logging.WARNING, logger="kiro_crew.platform.spec_denied_commands"):
        verdict = _judge(_own_request("ls -la", _settings(broken)))
    assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands")
    assert "not a regex" in verdict.reason
    assert any("does not compile" in r.getMessage() for r in caplog.records)


def test_leading_inline_flags_preserve_deny_and_nonmatch() -> None:
    settings = _settings(r"(?i).*\bcurl\b.*")
    denied = _judge(_own_request("CURL x", settings))
    assert (denied.action, denied.tier) == (TOOL_DENY, "spec-denied-commands")
    assert "matches its deniedCommands" in denied.reason
    allowed = _judge(_own_request("ls -la", settings))
    assert allowed.action != TOOL_DENY
    assert allowed.tier != "spec-denied-commands"


def test_word_boundaries_are_zero_width_assertions() -> None:
    bounded = _settings(_UNCARRIED)
    for command in ("curl x", "a.curl", "x curl"):
        verdict = _judge(_own_request(command, bounded))
        assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands"), command
    for command in ("curly x", "libcurl x", "curl_x"):
        assert _judge(_own_request(command, bounded)).tier != "spec-denied-commands", command
    inner = _settings(r".*\Bcurl.*")
    denied = _judge(_own_request("libcurl", inner))
    assert (denied.action, denied.tier) == (TOOL_DENY, "spec-denied-commands")
    assert _judge(_own_request("curl x", inner)).tier != "spec-denied-commands"


def test_nested_repetition_is_decided_without_backtracking() -> None:
    """``re`` backtracks exponentially here; the automaton is linear."""
    settings = _settings(r".*(git .*)+push.*")
    command = "echo " + "git " * 40 + "status"
    assert _judge(_own_request(command, settings)).tier != "spec-denied-commands"
    verdict = _judge(_own_request(command + " push", settings))
    assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands")


def test_a_spent_match_budget_refuses(monkeypatch: pytest.MonkeyPatch, caplog) -> None:
    from kiro_crew.platform import spec_denied_commands

    monkeypatch.setattr(spec_denied_commands, "_MAX_MATCH_STEPS", 5)
    with caplog.at_level(logging.WARNING, logger="kiro_crew.platform.spec_denied_commands"):
        verdict = _judge(_own_request("ls -la", _settings(_UNCARRIED)))
    assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands")
    assert "match budget" in verdict.reason
    assert any("spent the match budget" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize(
    "pattern",
    [
        r"[a-z&&[^b]]+",
        r"[a-z&&b]+",
        r"[a-z--b]+",
        r"[a-z~~b]+",
        r"[[:^space:]]+",
        # Rust POSIX and nested classes: no reading both engines share.
        r"curl[[:space:]]+.*",
        r"echo [[:alpha:]]",
        r"echo \[[:space:]]",
        r"echo [\[[:digit:]]",
        r"echo [a[:digit:][:upper:]]",
        r"echo [^[:digit:]]",
        r"echo [][:digit:]]",
        # Rust reads \< \> as word boundaries; Python as literal brackets.
        r"\<curl\>",
        r"curl\>.*",
        # Flags anywhere but the very start, and any other flag.
        r"curl (?i)x",
        r"(?s).*curl.*",
    ],
)
def test_ambiguous_or_unsupported_sets_fail_closed(pattern: str, caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="kiro_crew.platform.spec_denied_commands"):
        for command in ("ls -la", "echo hi"):
            verdict = _judge(_own_request(command, _settings(pattern)))
            assert (verdict.action, verdict.tier) == (TOOL_DENY, "spec-denied-commands")
            assert "not a regex" in verdict.reason
    assert any("does not compile" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize(
    ("pattern", "matching", "nonmatching"),
    [
        (r"echo [:space:]", "echo s", "echo x"),
        (r"[a-z||b]+", "a|b", "A1"),
        (r"echo a|echo b\z", "echo b", "echo bx"),
        (r"(?i)echo [a-c]", "ECHO B", "echo d"),
        (r"(?i)echo [A-C]", "echo b", "echo d"),
    ],
)
def test_class_context_and_whole_command_anchoring(
    pattern: str, matching: str, nonmatching: str
) -> None:
    settings = _settings(pattern)
    denied = _judge(_own_request(matching, settings))
    assert (denied.action, denied.tier) == (TOOL_DENY, "spec-denied-commands")
    assert "matches its deniedCommands" in denied.reason
    assert _judge(_own_request(nonmatching, settings)).tier != "spec-denied-commands"


def test_parity_with_the_deny_kas_carries() -> None:
    """The same command set is refused whether KAS carries the deny (``curl.*``
    as the glob ``curl*``) or Crew's gate holds it (``.*\\bcurl\\b.*``)."""
    block, _lost = tools_settings_to_permissions(_settings(_CARRIED))
    assert block is not None
    (rule,) = block["rules"]
    assert (rule["capability"], rule["effect"]) == ("shell", "deny")
    commands = ["curl x", "curl", "ls -la", "echo hi"]
    kas_refuses = {c for c in commands if any(fnmatch.fnmatchcase(c, g) for g in rule["match"])}
    crew_refuses = {
        c
        for c in commands
        if _judge(_own_request(c, _settings(_UNCARRIED))).tier == "spec-denied-commands"
    }
    assert kas_refuses == crew_refuses == {"curl x", "curl"}
    # A carried entry adds no Crew row: the call takes its usual path.
    assert _judge(_own_request("curl x", _settings(_CARRIED))).tier != "spec-denied-commands"
    from kiro_crew.acp.kas_permissions import CREW_UNCARRIED_DENIES_KEY

    assert CREW_UNCARRIED_DENIES_KEY not in _entry(_settings(_CARRIED))


def test_a_malformed_entry_or_record_fails_closed() -> None:
    from kiro_crew.acp.kas_permissions import CREW_UNCARRIED_DENIES_KEY
    from kiro_crew.acp.kas_spec_denies import (
        UNREADABLE_DENY,
        projected_uncarried_denies,
        switched_uncarried_denies,
        uncarried_shell_denies,
    )

    assert uncarried_shell_denies(_settings("curl(("), None) == ["curl(("]
    assert uncarried_shell_denies(_settings(7), None) == [UNREADABLE_DENY]
    assert uncarried_shell_denies({"shell": {"deniedCommands": "curl.*"}}, None) == [
        UNREADABLE_DENY
    ]
    assert uncarried_shell_denies(_settings(), None) is None
    assert uncarried_shell_denies(None, None) is None
    batch = [
        {"id": "probe", "prompt": "p", CREW_UNCARRIED_DENIES_KEY: [_UNCARRIED, 7]},
        {"id": "broken", "prompt": "p", CREW_UNCARRIED_DENIES_KEY: _UNCARRIED},
        {"id": "other", "prompt": "p"},
    ]
    assert projected_uncarried_denies(batch, "probe") == (_UNCARRIED, UNREADABLE_DENY)
    assert projected_uncarried_denies(batch, "broken") == (UNREADABLE_DENY,)
    assert projected_uncarried_denies(batch, "other") is None
    from kiro_crew.agent_files import kas_wire_agent_id

    assert switched_uncarried_denies(batch, kas_wire_agent_id("other")) is None
    assert switched_uncarried_denies(batch, kas_wire_agent_id("broken")) == (UNREADABLE_DENY,)


@pytest.mark.parametrize("value", ["curl.*", 7, ["execute_bash"]])
def test_a_tools_settings_that_is_not_an_object_is_not_carried(value: Any) -> None:
    """Neither a dict nor ``None``: Crew cannot tell what it denies, so both
    readers say "not carried" and the gate refuses (fail closed)."""
    from kiro_crew.acp.kas_permissions import shell_denies_carried
    from kiro_crew.acp.kas_spec_denies import UNREADABLE_DENY, uncarried_shell_denies

    assert uncarried_shell_denies(value, None) == [UNREADABLE_DENY]
    assert shell_denies_carried(value, None) is False
    assert uncarried_shell_denies(None, None) is None
    assert shell_denies_carried(None, None) is True


def test_the_record_never_reaches_the_wire() -> None:
    from kiro_crew.acp.kas_permissions import CREW_UNCARRIED_DENIES_KEY

    entry = _entry(_settings(_UNCARRIED))
    assert entry[CREW_UNCARRIED_DENIES_KEY] == [_UNCARRIED]
    params: dict[str, Any] = {}
    attach_kas_custom_agents(params, [entry])
    (wire,) = params["_meta"]["kiro"]["customAgents"]
    assert CREW_UNCARRIED_DENIES_KEY not in wire


def test_a_child_request_does_not_carry_the_parent_denies() -> None:
    handle = _handle(ACP_BACKEND_KAS)
    handle.kas_spec_uncarried_denies = (_UNCARRIED,)
    own = handle._build_permission_event(_permission("own-sid"))
    child = handle._build_permission_event(_permission("child-sid"))
    assert own is not None and own.spec_uncarried_denies == (_UNCARRIED,)
    assert child is not None and child.spec_uncarried_denies is None
