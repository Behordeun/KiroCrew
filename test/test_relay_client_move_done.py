"""The relay's ``move-done`` frame on a moved host connection (contract section 4.5).

After a ``reconnect`` the client opens a new connection and keeps the old one for
the requests on it. A request the relay wrote on the old connection just before
it stopped routing there can still be on the wire when the client closes. When
the old connection's ``ready`` listed ``move-done``, the relay says so once
nothing more will come there, and the client closes the old connection only then,
once the HTTP streams opened before it have finished.
"""

from __future__ import annotations

import base64
import json
import logging

import pytest
from relay_client_helpers import (
    FakeCrew,
    FakeRelay,
    make_client,
    ready_frame,
    stop,
    valid_message,
)

from kiro_crew.relay_client.client import STATE_CONNECTED
from kiro_crew.relay_client.connection import RelayTimings
from kiro_crew.relay_client.protocol import (
    MOVE_DONE_WAIT_SECONDS,
    OFFERED_FEATURES,
    FrameError,
    parse_inbound,
)
from kiro_crew.testing.wait import async_wait_until, until_parked


def _agreed_ready() -> dict:
    ready = ready_frame()
    ready["features"] = [*ready["features"], "move-done"]
    return ready


def _connection(client):
    (conn,) = [c for c in client._live if c.ready.is_set()]
    return conn


async def _move(client, relay, old, *, ready=None):
    """Move the client off *old*; return the new leg once the old one drains."""
    old_conn = _connection(client)
    await old.send(valid_message("frames/reconnect", 0))
    new = await relay.next_leg()
    await new.handshake(ready)
    await async_wait_until(lambda: client._draining is old_conn)
    return new, old_conn


async def _start(client, relay, *, ready=None):
    await client.start()
    old = await relay.next_leg()
    hello = await old.handshake(ready)
    await async_wait_until(lambda: client.state == STATE_CONNECTED)
    return old, hello


@pytest.mark.asyncio
async def test_the_hello_offers_move_done() -> None:
    assert "move-done" in OFFERED_FEATURES
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(relay, crew)
        try:
            _, hello = await _start(client, relay)
            assert "move-done" in hello["features"]
        finally:
            await stop(client, ingress)


@pytest.mark.asyncio
async def test_a_request_after_the_new_ready_is_answered_before_move_done_closes() -> None:
    # The race: the relay wrote a request on the old connection just before it
    # stopped routing there, and it arrives after the new connection is ready and
    # after a quiet grace would have closed the old one.
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(relay, crew, timings=RelayTimings(move_grace=0.05))
        try:
            old, _ = await _start(client, relay, ready=_agreed_ready())
            new, old_conn = await _move(client, relay, old, ready=_agreed_ready())
            # The drain waits on move-done, not on the quiet grace.
            await until_parked(old_conn.move_done)
            assert not old.closed.is_set(), "the old connection closed before move-done"

            head = valid_message("frames/request")
            await old.send(head)
            await old.send({"type": "request-end", "id": head["id"]})
            await old.send({"type": "move-done", "lastId": head["id"]})
            response, body = await old.read_response(head["id"])
            assert response["status"] == 200 and json.loads(body)["ok"] is True

            assert await old.wait_closed() == 1000
            assert not new.closed.is_set()
            assert client.move_done_fallbacks == 0
            assert client.state == STATE_CONNECTED
        finally:
            await stop(client, ingress)


@pytest.mark.asyncio
async def test_a_relay_that_did_not_list_move_done_gets_the_quiet_grace() -> None:
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(
            relay, crew, timings=RelayTimings(move_grace=0.05, move_done_wait=3600.0)
        )
        try:
            old, hello = await _start(client, relay)
            assert "move-done" in hello["features"]
            assert "move-done" not in _connection(client).features
            new, _ = await _move(client, relay, old)
            # No move-done ever comes, and none is waited for.
            assert await old.wait_closed() == 1000
            await async_wait_until(lambda: not client._background)
            assert not new.closed.is_set()
            assert client.move_done_fallbacks == 0
        finally:
            await stop(client, ingress)


@pytest.mark.asyncio
async def test_an_agreed_move_done_that_never_comes_falls_back_and_is_counted(caplog) -> None:
    caplog.set_level(logging.WARNING, logger="kiro_crew.relay_client.connection")
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(
            relay, crew, timings=RelayTimings(move_grace=0.05, move_done_wait=0.5)
        )
        try:
            old, _ = await _start(client, relay, ready=_agreed_ready())
            new, old_conn = await _move(client, relay, old, ready=_agreed_ready())
            # Inside the wait the drain is parked on move-done, not on the grace:
            # still open for late requests.
            await until_parked(old_conn.move_done)
            assert not old.closed.is_set()
            assert await old.wait_closed() == 1000
            await async_wait_until(lambda: not client._background)
            assert old_conn.move_done_fell_back
            assert client.move_done_fallbacks == 1
            assert any("no move-done within" in r.getMessage() for r in caplog.records)
            assert not new.closed.is_set()
        finally:
            await stop(client, ingress)


def test_the_move_done_wait_is_five_seconds_by_default() -> None:
    assert MOVE_DONE_WAIT_SECONDS == 5.0
    assert RelayTimings().move_done_wait == MOVE_DONE_WAIT_SECONDS


@pytest.mark.asyncio
async def test_move_done_closes_only_once_the_open_requests_finish() -> None:
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(
            relay, crew, timings=RelayTimings(move_grace=0.05, move_done_wait=3600.0)
        )
        try:
            old, _ = await _start(client, relay, ready=_agreed_ready())
            head = valid_message("frames/request", path="/slow", query="", headers={})
            await old.send(head)
            await old.send({"type": "request-end", "id": head["id"]})
            await async_wait_until(lambda: crew.seen)

            new, old_conn = await _move(client, relay, old, ready=_agreed_ready())
            await old.send({"type": "move-done"})
            await async_wait_until(lambda: old_conn.move_done.is_set())
            # Past move-done the drain is parked on the open request finishing.
            await until_parked(old_conn.http_streams_idle)
            assert not old.closed.is_set(), "closed with a request still open"

            crew.release.set()
            response, body = await old.read_response(head["id"])
            assert response["status"] == 200 and body == b"finished"
            assert await old.wait_closed() == 1000
            assert not new.closed.is_set()
            assert client.move_done_fallbacks == 0
        finally:
            crew.release.set()
            await stop(client, ingress)


@pytest.mark.asyncio
async def test_move_done_before_any_open_request_closes_at_once() -> None:
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(
            relay, crew, timings=RelayTimings(move_grace=3600.0, move_done_wait=3600.0)
        )
        try:
            old, _ = await _start(client, relay, ready=_agreed_ready())
            new, _ = await _move(client, relay, old, ready=_agreed_ready())
            await old.send({"type": "move-done"})
            # Neither the hour-long grace nor the hour-long wait holds it.
            assert await old.wait_closed() == 1000
            assert not new.closed.is_set()
        finally:
            await stop(client, ingress)


@pytest.mark.asyncio
async def test_frames_for_an_open_stream_after_move_done_are_handled() -> None:
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(
            relay, crew, timings=RelayTimings(move_grace=0.05, move_done_wait=3600.0)
        )
        try:
            old, _ = await _start(client, relay, ready=_agreed_ready())
            upload = valid_message(
                "frames/request", id=11, method="POST", path="/upload", query="", headers={}
            )
            await old.send(upload)
            cancelled = valid_message("frames/request", id=13, path="/slow", query="", headers={})
            await old.send(cancelled)
            await old.send({"type": "request-end", "id": cancelled["id"]})
            await async_wait_until(lambda: len(crew.seen) == 1)

            new, old_conn = await _move(client, relay, old, ready=_agreed_ready())
            await old.send({"type": "move-done", "lastId": 13})
            await async_wait_until(lambda: old_conn.move_done.is_set())

            # The body of a request opened before move-done still arrives and is sent on.
            data = base64.b64encode(b"after move-done").decode("ascii")
            await old.send(
                {"type": "request-chunk", "id": upload["id"], "data": data, "base64": True}
            )
            await old.send({"type": "request-end", "id": upload["id"]})
            response, body = await old.read_response(upload["id"])
            assert response["status"] == 200
            assert json.loads(body) == {"bytes": 15, "head": "after move-done"}
            assert not old.closed.is_set(), "closed with the /slow request still open"

            # A cancel for the other open stream ends it, and with it the drain.
            await old.send({"type": "request-cancel", "id": cancelled["id"]})
            assert await old.wait_closed() == 1000
            assert not new.closed.is_set()
        finally:
            crew.release.set()
            await stop(client, ingress)


@pytest.mark.asyncio
async def test_move_done_on_a_connection_that_did_not_agree_it_is_refused() -> None:
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(relay, crew)
        try:
            old, _ = await _start(client, relay)
            await old.send({"type": "move-done"})
            error = await old.recv_type("error")
            assert error["code"] == "unsupported_frame"
            assert not _connection(client).move_done.is_set()
            assert not old.closed.is_set()
        finally:
            await stop(client, ingress)


@pytest.mark.parametrize(
    "frame",
    [
        {"type": "move-done"},
        {"type": "move-done", "lastId": 41},
        {"type": "move-done", "lastId": 1, "later": True},
    ],
    ids=["bare", "last-id", "unknown-field"],
)
def test_move_done_parses_with_or_without_last_id(frame) -> None:
    assert parse_inbound(json.dumps(frame))["type"] == "move-done"


@pytest.mark.parametrize("last_id", ["41", -1, True, 1.5])
def test_move_done_with_a_bad_last_id_is_invalid(last_id) -> None:
    with pytest.raises(FrameError) as caught:
        parse_inbound(json.dumps({"type": "move-done", "lastId": last_id}))
    assert caught.value.code == "invalid_message"


@pytest.mark.asyncio
async def test_a_refused_move_done_keeps_the_fallback_running() -> None:
    async with FakeRelay() as relay, FakeCrew() as crew:
        client, _, ingress = make_client(
            relay, crew, timings=RelayTimings(move_grace=0.05, move_done_wait=0.5)
        )
        try:
            old, _ = await _start(client, relay, ready=_agreed_ready())
            new, old_conn = await _move(client, relay, old, ready=_agreed_ready())
            await old.send({"type": "move-done", "lastId": "41"})
            error = await old.recv_type("error")
            assert error["code"] == "invalid_message"
            assert not old_conn.move_done.is_set()
            assert await old.wait_closed() == 1000
            await async_wait_until(lambda: not client._background)
            assert old_conn.move_done_fell_back
            assert client.move_done_fallbacks == 1
            assert not new.closed.is_set()
        finally:
            await stop(client, ingress)


def test_move_done_is_still_a_json_object_frame() -> None:
    with pytest.raises(FrameError):
        parse_inbound('"move-done"')
