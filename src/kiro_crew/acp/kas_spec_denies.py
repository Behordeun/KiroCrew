"""A KAS spec's ``deniedCommands`` that its KAS policy does not carry.

KAS has no regex rule: the projection turns each kiro-cli ``deniedCommands``
regex into a KAS shell ``deny`` glob (``kas_permissions.tools_settings_to_permissions``),
and an entry with no glob spelling (``.*\\bcurl\\b.*``, a group, an alternation),
a redirect, or one a merge dropped reaches KAS as no rule at all. Without more,
KAS would run the command the entry names. So the projection records those
entries as the spec wrote them (:data:`~kiro_crew.acp.kas_permissions.CREW_UNCARRIED_DENIES_KEY`),
the session handle reads them back here for its own agent, and the gate's
``spec-denied-commands`` row refuses a shell call one matches, as kiro-cli does.
Only ever a refusal: nothing here allows a call.
"""

from __future__ import annotations

from typing import Any

from kiro_crew.acp.kas_permissions import (
    _REDIRECT_CHARACTERS,
    _SHELL_SETTINGS_KEYS,
    CREW_UNCARRIED_DENIES_KEY,
    _regex_to_glob,
    carried_shell_denies,
)
from kiro_crew.platform.spec_denied_commands import UNREADABLE_DENY


def uncarried_shell_denies(tools_settings: Any, policy: Any) -> list[str] | None:
    """The ``deniedCommands`` entries of both shell keys that *policy* does not
    carry as a KAS shell ``deny``, or ``None`` when there are none.

    Not carried means what :func:`~kiro_crew.acp.kas_permissions.shell_denies_carried`
    means: no glob spelling, a redirect character KAS never sees, or a glob the
    merge dropped. An entry that is not a string, a value that is not a list, and
    a ``toolsSettings`` that is neither a dict nor ``None`` are recorded as
    :data:`UNREADABLE_DENY` (fail closed: Crew cannot tell what they deny).
    """
    if tools_settings is None:
        return None
    if not isinstance(tools_settings, dict):
        return [UNREADABLE_DENY]
    carried = carried_shell_denies(policy)
    out: list[str] = []
    for key in _SHELL_SETTINGS_KEYS:
        settings = tools_settings.get(key)
        denied = settings.get("deniedCommands") if isinstance(settings, dict) else None
        if denied is None or (isinstance(denied, list) and not denied):
            continue
        if not isinstance(denied, list):
            out.append(UNREADABLE_DENY)
            continue
        for raw in denied:
            if not isinstance(raw, str):
                out.append(UNREADABLE_DENY)
                continue
            pattern = raw.strip()
            if not pattern:
                continue
            glob = _regex_to_glob(pattern)
            if glob is None or set(glob) & _REDIRECT_CHARACTERS or glob not in carried:
                out.append(pattern)
    return list(dict.fromkeys(out)) or None


def _entry_uncarried_denies(entry: Any) -> tuple[str, ...] | None:
    """The :data:`CREW_UNCARRIED_DENIES_KEY` regexes of one projected entry.

    ``None`` when the entry has no such key. A value that is present but not a
    list of strings reads as :data:`UNREADABLE_DENY`, which refuses every
    command: a restriction is never lifted by a malformed record.
    """
    if not isinstance(entry, dict) or CREW_UNCARRIED_DENIES_KEY not in entry:
        return None
    raw = entry[CREW_UNCARRIED_DENIES_KEY]
    if not isinstance(raw, list):
        return (UNREADABLE_DENY,)
    return tuple(dict.fromkeys(p if isinstance(p, str) and p else UNREADABLE_DENY for p in raw))


def projected_uncarried_denies(custom_agents: Any, agent_id: str) -> tuple[str, ...] | None:
    """The uncarried denies of *agent_id*'s registered entry, or ``None``, matched
    like ``kas_agents.projected_shell_allowlist``."""
    from kiro_crew.acp.kas_agents import _registered_entry

    return _entry_uncarried_denies(_registered_entry(custom_agents, agent_id))


def switched_uncarried_denies(custom_agents: Any, mode_id: str) -> tuple[str, ...] | None:
    """Those denies once a KAS mode switch moves the session to *mode_id*."""
    from kiro_crew.acp.kas_agents import _switched_entry

    return _entry_uncarried_denies(_switched_entry(custom_agents, mode_id))
