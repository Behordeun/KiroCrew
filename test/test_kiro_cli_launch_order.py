"""Opening a chat in kiro-cli: the transcript stays in the order things were said.

After a restart, the turns made in kiro-cli wait in the open's record until a
recovery brings them in. A recovery that fails keeps the record to retry, and
until it succeeds nothing newer may land in the transcript ahead of those older
turns: a send is refused (its draft kept), a queued entry stays queued, and a
turn that got past both is refused at admission. The refusal rows carry their
own gateway-notice tokens, so they are shown in the dashboard's language.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from kiro_crew import kiro_cli_handoff
from kiro_crew.dashboard import chat_utils
from kiro_crew.dashboard import gateway_notice as gn
from kiro_crew.dashboard.handlers import kiro_cli_launch as kcl


@pytest.fixture(autouse=True)
def _records(_floor_monkeypatch, tmp_path):
    kiro_cli_handoff.reset_holds()
    _floor_monkeypatch.setattr(kiro_cli_handoff, "_records_dir", lambda: tmp_path / "opens")
    _floor_monkeypatch.setattr(kcl, "_recovery_locks", {})
    yield
    kiro_cli_handoff.reset_holds()


def _leave_record(key: str) -> None:
    kiro_cli_handoff.record_open(key, {"history_key": key, "created_at": "", "log_offset": 0})


def _recovery(fails: bool):
    """A recovery that finds the record and either keeps it (a transient
    failure) or brings the turns in and removes it."""
    calls = []

    async def recover(state, slot, session_key):
        calls.append(session_key)
        if not fails:
            kiro_cli_handoff.forget_open(session_key)
        return True

    recover.calls = calls
    return recover


def _send_app(state):
    from kiro_crew.dashboard.chat import api_chat

    @web.middleware
    async def _auth(request, handler):
        request["app"] = ""
        request["user"] = "local-app"
        return await handler(request)

    app = web.Application(middlewares=[_auth])
    app["state"] = state
    app.router.add_post("/api/chat/send", api_chat)
    return app


@pytest.mark.asyncio
async def test_a_send_is_refused_while_a_failed_recovery_keeps_the_record(tmp_path, monkeypatch):
    from chat_test_helpers import _make_state

    from kiro_crew.dashboard.state import _ChatSlot

    state = _make_state(tmp_path)
    slot = _ChatSlot("chat-pending")
    slot.append("user", "before kiro-cli", "msg msg-u")
    state._slots[slot.key] = slot
    key = chat_utils.effective_session_key(slot)
    _leave_record(key)
    before = list(slot.messages)
    recover = _recovery(fails=True)
    monkeypatch.setattr(kcl, "recover_left_open", recover)
    async with TestClient(TestServer(_send_app(state))) as client:
        resp = await client.post("/api/chat/send", json={"slot": slot.key, "message": "next"})
        assert resp.status == 409
        assert await resp.json() == {
            "error": kiro_cli_handoff.LEFT_OPEN_PENDING_REFUSAL,
            "code": "kiro_cli_import_pending",
        }
    assert recover.calls == [key], "the send tried the recovery first"
    assert slot.messages == before, "nothing recorded ahead of kiro-cli's turns"
    assert slot.task is None


@pytest.mark.asyncio
async def test_a_send_goes_through_once_the_recovery_brought_the_turns_in(tmp_path, monkeypatch):
    from chat_test_helpers import _make_state

    from kiro_crew.dashboard.state import _ChatSlot

    state = _make_state(tmp_path)
    slot = _ChatSlot("chat-recovered")
    state._slots[slot.key] = slot
    _leave_record(chat_utils.effective_session_key(slot))
    monkeypatch.setattr(kcl, "recover_left_open", _recovery(fails=False))
    # The send is accepted, then stopped at the turn: the point is the 409 is gone.
    monkeypatch.setattr(
        "kiro_crew.dashboard.chat_api.chat_send._schedule_chat_task", MagicMock(), raising=False
    )
    async with TestClient(TestServer(_send_app(state))) as client:
        resp = await client.post("/api/chat/send", json={"slot": slot.key, "message": "next"})
        assert resp.status != 409, await resp.text()


async def _run(state, slot, text):
    from kiro_crew.config.loader import KiroCrewConfig
    from kiro_crew.dashboard.chat_runner import _run_chat

    with (
        patch("kiro_crew.dashboard.chat_runner.KiroCrewConfig.load", return_value=KiroCrewConfig()),
        patch("kiro_crew.autonudge.get_instance", return_value=MagicMock()),
    ):
        await _run_chat(state, slot, text)


def _admission_state(tmp_path):
    from chat_test_helpers import _make_state

    state = _make_state(tmp_path)
    state.broadcast_ws = MagicMock()
    reached = []

    async def get_or_create(*args, **kwargs):
        reached.append(True)
        raise RuntimeError("stop here: the turn reached provider allocation")

    state.sessions.get_or_create = get_or_create
    state.sessions.record_failure = AsyncMock()
    return state, reached


@pytest.mark.asyncio
async def test_a_turn_past_the_send_is_refused_while_the_record_is_pending(tmp_path, monkeypatch):
    state, reached = _admission_state(tmp_path)
    slot = state.get_or_create_slot("chat-admitted")
    slot.append("user", "hello", "msg msg-u")
    _leave_record(chat_utils.effective_session_key(slot))
    monkeypatch.setattr(kcl, "recover_left_open", _recovery(fails=True))
    await _run(state, slot, "hello")
    [row] = [m for m in slot.messages if m["role"] == "error"]
    assert row["content"] == kiro_cli_handoff.LEFT_OPEN_PENDING_REFUSAL
    assert row["meta"][gn.GATEWAY_NOTICE_META_KEY] == gn.GATEWAY_NOTICE_KIRO_CLI_IMPORT_PENDING
    assert reached == [], "the model never answered ahead of kiro-cli's turns"


@pytest.mark.asyncio
async def test_the_held_turn_row_carries_its_notice_token(tmp_path):
    state, reached = _admission_state(tmp_path)
    slot = state.get_or_create_slot("chat-held-token")
    slot.append("user", "hello", "msg msg-u")
    kiro_cli_handoff.hold(chat_utils.effective_session_key(slot), "t")
    await _run(state, slot, "hello")
    [row] = [m for m in slot.messages if m["role"] == "error"]
    assert row["content"] == kiro_cli_handoff.HELD_TURN_REFUSAL
    assert row["meta"][gn.GATEWAY_NOTICE_META_KEY] == gn.GATEWAY_NOTICE_KIRO_CLI_OPEN
    assert reached == []


@pytest.mark.asyncio
async def test_a_queue_waits_while_the_record_is_pending_and_drains_once_it_is_in(
    tmp_path, monkeypatch
):
    from chat_test_helpers import _make_state

    from kiro_crew.dashboard import chat_runner

    state = _make_state(tmp_path)
    slot = state.get_or_create_slot("chat-queued")
    key = chat_utils.effective_session_key(slot)
    _leave_record(key)
    entry = {"id": "q1", "text": "queued while kiro-cli held the chat"}
    slot._queue.append(entry)
    failing = _recovery(fails=True)
    monkeypatch.setattr(kcl, "recover_left_open", failing)
    assert await chat_runner._start_next_queued_turn(state, slot) is False
    assert slot._queue == [entry], "the entry waits, its row unwritten"
    assert failing.calls == [key], "the drain tried the recovery once more"
    monkeypatch.setattr(kcl, "recover_left_open", _recovery(fails=False))
    assert await chat_runner._queue_awaits_kiro_cli_import(state, slot) is False
    assert not kiro_cli_handoff.has_left_open(key)
