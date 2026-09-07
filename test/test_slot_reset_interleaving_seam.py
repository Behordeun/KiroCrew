"""The test-only interleaving seam, and the reload-vs-switch race it reaches.

``chat_handlers._test_interleave`` is awaited at four named points across the
session-teardown paths. These tests pin its contract -- unset by default, called
with the point names in the order the code reaches them -- and then use it for the
thing it exists for: driving a reload's teardown into the middle of a switch
handler's commit-then-reset span, deterministically, with no sleep.

That interleaving is the one described in issue #9019, and the test named for it
below asserts TODAY's outcome, not the desired one. See its docstring.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from kiro_crew.dashboard import chat_handlers
from kiro_crew.dashboard.chat import api_chat_slot_model, api_chat_slot_reload
from kiro_crew.dashboard.state import DashboardState, _ChatSlot

# Registry aliases the model guard accepts, matching the ids the sibling
# switch-atomicity tests use.
_MODEL_OLD = "claude-opus-4.8"
_MODEL_NEW = "gpt-5.6-sol"
_SLOT = "s1"
_SESSION_KEY = f"dashboard:{_SLOT}"

# Loop turns a bounded yield will spend before giving up. Turns, not seconds:
# the cap exists only to bound a coroutine that can never make progress, and is
# far above what any interleaving here needs.
_MAX_TURNS = 500


async def _yield_until(predicate: Callable[[], bool]) -> bool:
    """Hand the loop back until *predicate* holds, then report whether it did.

    Scheduler turns, not wall clock. ``asyncio.sleep(0)`` reschedules this
    coroutine behind whatever is already runnable, so how many turns a given
    interleaving needs is a property of the code under test, identical on a busy
    host and an idle one -- unlike a sleep, whose duration decides the outcome.

    Returning a bool rather than asserting is what keeps a caller readable in
    both worlds: a racer that becomes blocked by a future fix reports False here
    and the caller fails on its own assertion, instead of hanging until the
    suite-wide timeout kills it with no explanation.
    """
    for _ in range(_MAX_TURNS):
        if predicate():
            return True
        await asyncio.sleep(0)
    return predicate()


def _make_app(state: DashboardState) -> web.Application:
    # Mirror production: the token_auth middleware sets request["app"] on every
    # authenticated path ("" = dashboard user), and the app-isolation guards on
    # both routes fail closed without it.
    @web.middleware
    async def dashboard_auth_marker(request, handler):
        if "app" not in request:
            request["app"] = ""
        return await handler(request)

    app = web.Application(middlewares=[dashboard_auth_marker])
    app["state"] = state
    app.router.add_post("/api/chat/slots/{slot}/model", api_chat_slot_model)
    app.router.add_post("/api/chat/slots/{slot}/reload", api_chat_slot_reload)
    return app


def _idle_provider() -> MagicMock:
    provider = MagicMock()
    provider.has_active_turn = MagicMock(return_value=False)
    return provider


def _mock_state(slot: _ChatSlot) -> DashboardState:
    state = MagicMock(spec=DashboardState)
    state._slots = {slot.key: slot}
    state.sessions = MagicMock()
    state.sessions.reset = AsyncMock(return_value=True)
    state.sessions.get_provider = MagicMock(return_value=_idle_provider())
    return state


@pytest.fixture
def slot() -> _ChatSlot:
    s = _ChatSlot(_SLOT)
    s.model = _MODEL_OLD
    return s


@pytest.fixture
def state(slot: _ChatSlot) -> DashboardState:
    return _mock_state(slot)


@pytest.fixture(autouse=True)
def _no_eager_spawn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reload re-arms the resume spawn; there is no runtime here to spawn onto."""
    monkeypatch.setattr(chat_handlers, "schedule_eager_spawn", MagicMock(return_value=None))


class TestInterleaveSeamContract:
    """What the seam promises when nothing sets it, and what it reports when set."""

    def test_hook_defaults_to_none(self):
        # Production cost is this attribute being None: each point reads the
        # global, compares, and creates no coroutine.
        assert chat_handlers._test_interleave is None

    @pytest.mark.asyncio
    async def test_unset_hook_leaves_the_teardown_untouched(self, state, slot):
        async with TestClient(TestServer(_make_app(state))) as client:
            resp = await client.post(f"/api/chat/slots/{_SLOT}/reload")
        assert resp.status == 200
        state.sessions.reset.assert_awaited_once_with(_SESSION_KEY, skip_if_busy=True)

    @pytest.mark.asyncio
    async def test_reload_reaches_its_points_in_order(self, state, slot, monkeypatch):
        seen: list[str] = []

        async def _record(point: str) -> None:
            seen.append(point)

        monkeypatch.setattr(chat_handlers, "_test_interleave", _record)
        async with TestClient(TestServer(_make_app(state))) as client:
            resp = await client.post(f"/api/chat/slots/{_SLOT}/reload")

        assert resp.status == 200
        # Reload owns the outer point and reaches the shared chokepoint's two
        # through _reset_slot_session. No switch point: reload commits nothing.
        assert seen == ["reload:pre_reset", "reset:pre_pop", "reset:post_pop"]

    @pytest.mark.asyncio
    async def test_model_switch_reaches_its_points_in_order(self, state, slot, monkeypatch):
        seen: list[str] = []

        async def _record(point: str) -> None:
            seen.append(point)

        monkeypatch.setattr(chat_handlers, "_test_interleave", _record)
        async with TestClient(TestServer(_make_app(state))) as client:
            resp = await client.post(f"/api/chat/slots/{_SLOT}/model", json={"model": _MODEL_NEW})

        assert resp.status == 200
        assert slot.model == _MODEL_NEW
        # switch:post_commit precedes the chokepoint's pair, which is the whole
        # point of where it sits: the new value is already committed and both
        # locks are held while the old session is still alive.
        assert seen == ["switch:post_commit", "reset:pre_pop", "reset:post_pop"]

    @pytest.mark.asyncio
    async def test_a_raising_hook_is_not_swallowed(self, state, slot, monkeypatch):
        """A broken hook must fail its test, not silently skip the interleaving.

        Pins the ABSENCE of a suppress around the points: were one added, the
        teardown would proceed and every seam test would still pass while
        interleaving nothing.
        """

        async def _boom(point: str) -> None:
            raise RuntimeError(f"hook failed at {point}")

        monkeypatch.setattr(chat_handlers, "_test_interleave", _boom)
        async with TestClient(TestServer(_make_app(state))) as client:
            resp = await client.post(f"/api/chat/slots/{_SLOT}/reload")

        assert resp.status == 500
        state.sessions.reset.assert_not_awaited()


class TestReloadRacesSwitchCommitResetSpan:
    """The race in issue #9019, driven through the seam.

    ``api_chat_slot_reload`` tears down the slot's effective session while
    holding neither ``slot._lock`` nor the session-keyed switch lock. The four
    commit-before-reset switch handlers hold both across their commit-then-reset
    span. Nothing orders the two, so a reload's teardown can land inside that
    span -- which is what these tests make happen, deterministically, by
    suspending one racer at a named point and driving the other from there.
    """

    @pytest.mark.asyncio
    async def test_switch_transaction_completes_inside_reloads_unguarded_teardown(
        self, state, slot, monkeypatch
    ):
        """A whole model switch runs while reload sits on its pre-teardown point.

        DEFECT PIN for issue #9019: this asserts the CURRENT outcome, which is
        the wrong one. Reload holds no lock here, so the switch takes both of
        its own locks unopposed, commits the new model, and tears the session
        down -- all inside reload's window -- and reload's own teardown then
        lands on the session that switch just prepared.

        Serializing reload onto the session-keyed lock flips this test: the
        switch would block on that lock instead, so ``switch.done()`` stays
        False and the two assertions marked below fail. That is the intended
        signal to the fix -- invert them and drop the "unguarded" wording.
        """
        order: list[str] = []
        switch: asyncio.Task[object] | None = None

        async with TestClient(TestServer(_make_app(state))) as client:

            async def _interleave(point: str) -> None:
                order.append(point)
                if point != "reload:pre_reset":
                    return
                # Suspended inside reload's teardown. Start the switch here:
                # whether it can proceed while reload is mid-teardown IS the
                # question, so run it to completion and record what happened.
                nonlocal switch
                switch = asyncio.create_task(
                    client.post(f"/api/chat/slots/{_SLOT}/model", json={"model": _MODEL_NEW})
                )
                await _yield_until(lambda: switch is not None and switch.done())

            monkeypatch.setattr(chat_handlers, "_test_interleave", _interleave)
            reload_resp = await client.post(f"/api/chat/slots/{_SLOT}/reload")

            assert switch is not None
            try:
                # DEFECT (#9019): the switch got all the way through while
                # reload's teardown was open. A serialized reload leaves this
                # False.
                assert switch.done(), "switch never completed inside reload's window"
                switch_resp = switch.result()
            finally:
                switch.cancel()
                await asyncio.gather(switch, return_exceptions=True)

            assert switch_resp.status == 200
            assert reload_resp.status == 200

        # DEFECT (#9019): the switch's committed value and its teardown both land
        # between reload's own two points, so reload's pop -- the last entry --
        # destroys the session the switch reported success for. A serialized
        # reload orders every switch entry AFTER reload's pair.
        assert order == [
            "reload:pre_reset",
            "switch:post_commit",
            "reset:pre_pop",
            "reset:post_pop",
            "reset:pre_pop",
            "reset:post_pop",
        ]
        assert slot.model == _MODEL_NEW
        # Two teardowns of ONE session key, unserialized.
        assert state.sessions.reset.await_count == 2
        assert {c.args[0] for c in state.sessions.reset.await_args_list} == {_SESSION_KEY}

    @pytest.mark.asyncio
    async def test_reload_teardown_lands_inside_a_suspended_switch_span(
        self, state, slot, monkeypatch
    ):
        """The same race driven from the other side: switch first, reload second.

        DEFECT PIN for issue #9019, and the direction that shows the harm the
        issue names. The switch is suspended after committing its new model and
        before tearing the old session down, holding both of its locks. Reload
        then runs its ENTIRE teardown from inside that span, because it joins
        neither lock -- so the switch resumes and tears down a session that has
        already been replaced.

        A serialized reload leaves ``reload.done()`` False while the switch is
        suspended, failing the assertion marked below.
        """
        order: list[str] = []
        reload_task: asyncio.Task[object] | None = None
        # Guards against a vacuous pass: proves the hook body ran to its end
        # rather than the yield loop exiting on an early predicate.
        hook_completed = asyncio.Event()

        async with TestClient(TestServer(_make_app(state))) as client:

            async def _interleave(point: str) -> None:
                order.append(point)
                if point != "switch:post_commit":
                    return
                nonlocal reload_task
                reload_task = asyncio.create_task(client.post(f"/api/chat/slots/{_SLOT}/reload"))
                await _yield_until(lambda: reload_task is not None and reload_task.done())
                hook_completed.set()

            monkeypatch.setattr(chat_handlers, "_test_interleave", _interleave)
            switch_resp = await client.post(
                f"/api/chat/slots/{_SLOT}/model", json={"model": _MODEL_NEW}
            )

            assert reload_task is not None
            try:
                # DEFECT (#9019): reload completed a full teardown while the
                # switch held both locks with its commit already applied.
                assert reload_task.done(), "reload never completed inside the switch span"
                reload_resp = reload_task.result()
            finally:
                reload_task.cancel()
                await asyncio.gather(reload_task, return_exceptions=True)

            assert reload_resp.status == 200
            assert switch_resp.status == 200

        assert hook_completed.is_set()
        # DEFECT (#9019): reload's whole teardown pair sits between the switch's
        # commit and the switch's own pop, so the switch reports success for a
        # session reload had already torn down and re-armed.
        assert order == [
            "switch:post_commit",
            "reload:pre_reset",
            "reset:pre_pop",
            "reset:post_pop",
            "reset:pre_pop",
            "reset:post_pop",
        ]
        assert state.sessions.reset.await_count == 2
