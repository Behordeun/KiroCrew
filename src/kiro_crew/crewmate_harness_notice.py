"""The dashboard alarm that says crewmates cannot follow the Settings harness.

A crewmate with no pin of its own and no stored ``agent.member_acp_backend`` runs on
``agent.acp_backend`` (Settings -> Agent Harness). When that harness is one crewmates
cannot run on, the loader runs them on KAS instead and logs why
(``config.loader_builders._note_member_fallback``, harness-parity H3). The log is for
the operator; this note is for the person, in the bell, and it opens the Agent
Harness panel, which shows the same fact beside the picker.

One crewmate can also run on KAS on its own: its file sets something for its
workers the harness it inherits cannot carry (worker tool limits, ``hooks``,
``permissions``, ``toolsSettings``; ``crewmate_harness.worker_spec_forces_kas``). It gets its own note, which opens its
page on the Bots page.

Sent at gateway start and on every config change that touches either harness field,
once per fact per process: the bell is not refilled on each reload, and a fact that
stops holding and holds again is told again.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from typing import Any
from urllib.parse import quote

logger = logging.getLogger(__name__)

NOTE_KIND = "agent"
NOTE_CHANNEL = "system.agent"
NOTE_URL = "/settings/agent"

#: The facts already announced in this process: ``settings:<harness>`` for every
#: crewmate, ``mate:<crew>:<harness>`` for one.
_announced: set[str] = set()
_lock = threading.Lock()


def fallback_notes(config: Any) -> list[dict[str, str]]:
    """The notes owed now, each marked announced. Blocking.

    A fact that does not hold now is forgotten here, so it is told again when it
    holds again.
    """
    from kiro_crew.crewmate_harness import (
        SOURCE_FALLBACK,
        harness_label,
        inherited_falls_back,
        inherited_harness_source,
        refresh_worker_spec_verdicts,
        worker_spec_kas_fields,
    )

    # Off the loop: what each crewmate's file needs is read into memory here, so the
    # event loop's readers find it from the first session on.
    refresh_worker_spec_verdicts(config)

    source = inherited_harness_source(config)
    owed: list[tuple[str, dict[str, str]]] = []
    holding: set[str] = set()
    if source.source == SOURCE_FALLBACK:
        chosen = harness_label(source.settings_harness)
        used = harness_label(source.harness)
        key = f"settings:{source.settings_harness}"
        holding.add(key)
        owed.append(
            (
                key,
                {
                    "title": f"Bots run on {used}, not {chosen}",
                    "body": (
                        f"Your Agent Harness is {chosen}, which Bots cannot run on. Bot "
                        f"chats and the workers they open run on {used} instead. To choose "
                        "another harness for a Bot, set one in its settings."
                    ),
                    "url": NOTE_URL,
                },
            )
        )
    else:
        inherited = harness_label(source.harness)
        used = harness_label("kas")
        for crew in sorted(getattr(config, "agents", {}) or {}):
            if not getattr(config.agents[crew], "member_id", "") or not inherited_falls_back(
                config, crew
            ):
                continue
            fields = ", ".join(worker_spec_kas_fields(config, crew))
            key = f"mate:{crew}:{source.harness}"
            holding.add(key)
            owed.append(
                (
                    key,
                    {
                        "title": f"{crew} runs on {used}, not {inherited}",
                        "body": (
                            f"{crew} uses settings {inherited} cannot carry ({fields}), "
                            f"so its chat and workers run on {used}. To choose another "
                            "harness, set one in its settings."
                        ),
                        "url": f"/members?member={quote(crew)}",
                    },
                )
            )
    owed.extend(_pin_fallback_notes(config, holding))
    with _lock:
        _announced.intersection_update(holding)
        notes = []
        for key, note in owed:
            if key in _announced:
                continue
            _announced.add(key)
            notes.append({**note, "key": key})
    return notes


def _pin_fallback_notes(config: Any, holding: set[str]) -> list[tuple[str, dict[str, str]]]:
    """A note per Bot pinned to a harness Bots cannot run on; *holding* gains each key."""
    from kiro_crew.crewmate_harness import (
        CrewmateHarnessUnavailable,
        crewmate_pin_for,
        harness_label,
    )

    notes: list[tuple[str, dict[str, str]]] = []
    for crew in sorted(getattr(config, "agents", {}) or {}):
        pin = crewmate_pin_for(config, crew)
        if pin is None:
            continue
        try:
            checked = pin.checked()
        except CrewmateHarnessUnavailable:
            continue
        if not checked.harness_fallback:
            continue
        chosen = harness_label(pin.display_stored)
        used = harness_label(_stored(checked.backend))
        key = f"pin:{crew}:{pin.display_stored}"
        holding.add(key)
        notes.append(
            (
                key,
                {
                    "title": f"{crew} runs on {used}, not {chosen}",
                    "body": (
                        f"{crew} is pinned to {chosen}, which Bots cannot run on, so its "
                        f"chat and workers run on {used}. Pick another harness in its settings."
                    ),
                    "url": f"/members?member={quote(crew)}",
                    # An error: the person picked this harness, and it is not used.
                    "kind": "error",
                },
            )
        )
    return notes


def _stored(backend: str) -> str:
    from kiro_crew.acp_backends import backend_to_stored

    return backend_to_stored(backend)


def _forget(key: str) -> None:
    """Drop *key* from the announced set after a failed delivery."""
    with _lock:
        _announced.discard(key)


async def deliver(state: Any, config: Any | None = None) -> int:
    """Send every owed note to *state*'s bell. Returns how many went out.

    *config* is the config now in force; ``None`` loads it. Never raises: a missing
    alarm leaves the log line and the readouts, which say the same.
    """
    try:
        if config is None:
            from kiro_crew.config.loader import KiroCrewConfig

            config = await asyncio.to_thread(KiroCrewConfig.load)
        notes = await asyncio.to_thread(fallback_notes, config)
    except Exception:  # noqa: BLE001 - the alarm must not take a config apply down
        logger.warning("could not work out the crewmate harness fallback notice", exc_info=True)
        return 0
    sent = 0
    for note in notes:
        try:
            state.notify(
                note.get("kind", NOTE_KIND),
                note["title"],
                note["body"],
                url=note["url"],
                channel=NOTE_CHANNEL,
            )
        except Exception:  # noqa: BLE001 - the alarm must not take a config apply down
            # Not delivered, so not announced: the next config change or start tries again.
            _forget(note["key"])
            logger.warning("could not deliver the crewmate harness fallback notice", exc_info=True)
            continue
        sent += 1
    return sent


#: Strong reference to the boot delivery: the loop holds tasks weakly.
_TASK: "asyncio.Task[int] | None" = None


def schedule(state: Any) -> "asyncio.Task[int]":
    """Run :func:`deliver` once in the background, at gateway start. Call on the loop."""
    global _TASK
    _TASK = asyncio.create_task(deliver(state), name="crewmate-harness-fallback-notice")
    return _TASK
