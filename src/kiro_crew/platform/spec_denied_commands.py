"""Match spec ``deniedCommands`` the backend cannot carry. Only ever refuse.

A leaf shared by the KAS projection and the backend-independent hook gate. Each
entry is read by :mod:`kiro_crew.platform.allowed_commands` (``for_deny=True``),
never by Python's ``re``: only syntax Rust's ``regex`` reads the same way, matched
by a linear automaton under a step budget.
"""

from __future__ import annotations

import logging
from typing import Any

from kiro_crew.platform import allowed_commands

logger = logging.getLogger(__name__)

#: Recorded in place of an entry that is not a regex string (a number, a
#: ``deniedCommands`` that is not a list, a malformed record). The parser refuses
#: it (a ``(?`` group), so the gate refuses every command: a deny the author wrote
#: is never dropped because it could not be read.
UNREADABLE_DENY = "(?#unreadable deniedCommands entry"

#: Automaton steps one call may spend over every entry and segment; once spent,
#: the command is refused.
_MAX_MATCH_STEPS = 1_000_000


def denied_command_reason(command: Any, patterns: tuple[str, ...]) -> str | None:
    """Why *command* is refused by one of *patterns*, or ``None`` when none matches.

    Each pattern must match the whole command line, or one of its segments split
    on ``;``, ``&&``, ``||``, ``|``, ``&``, newlines and command substitution
    (a quote-unaware split, so it can only refuse more). A pattern outside the
    syntax Crew reads like kiro-cli refuses every command (fail closed), and so
    does a call that spends the step budget; both are logged, as is a command the
    host did not recover.
    """
    if not isinstance(command, str):
        return "the command could not be read"
    from kiro_crew.security.shell_normalizer import _CMD_SPLIT_RE

    parts = [command] + [p.strip() for p in _CMD_SPLIT_RE.split(command) if p.strip()]
    budget = [_MAX_MATCH_STEPS]
    for pattern in patterns:
        parsed = allowed_commands.parse(pattern, for_deny=True)
        if parsed is None:
            logger.warning(
                "spec deniedCommands entry %r does not compile as a regex Crew reads "
                "like kiro-cli; refusing the command",
                pattern,
            )
            return (
                f"the deniedCommands entry '{pattern}' is not a regex Crew can read, "
                "so every command is refused until it is fixed"
            )
        for part in parts:
            outcome = allowed_commands.match_within(parsed, part, budget)
            if outcome is None:
                logger.warning(
                    "spec deniedCommands entry %r spent the match budget; refusing the command",
                    pattern,
                )
                return (
                    f"the command could not be checked against its deniedCommands entry "
                    f"'{pattern}' within Crew's match budget, so it is refused"
                )
            if outcome:
                return f"the command matches its deniedCommands entry '{pattern}'"
    return None
