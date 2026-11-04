"""Disconnect when Kiro Crew holds the sign-in (``connections.crew_oauth``).

Reuses the handler harness of ``test_connections_disconnect.py``: every side
effect but the decision under test is neutralized there.
"""

from __future__ import annotations

import pytest
from test_connections_disconnect import _SLUG, _client, _entry, _provider_url, _wire


@pytest.mark.asyncio
async def test_a_failed_crew_held_cleanup_is_a_coded_failure_not_a_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A Crew-held sign-in that could not be removed must not read as disconnected."""
    from kiro_crew.connections import crew_oauth

    purged: list[str] = []
    audits: list[dict] = []
    _wire(
        monkeypatch,
        removed=[],
        surviving=[],
        inventory=[_entry(_SLUG, _provider_url())],
        purged=purged,
        audits=audits,
    )

    async def _vault_broken(_slug: str) -> dict:
        raise OSError("vault unreadable")

    monkeypatch.setattr(crew_oauth, "manages", lambda _slug: True)
    monkeypatch.setattr(crew_oauth, "disconnect", _vault_broken)
    client = await _client()
    try:
        resp = await client.post("/api/connections/disconnect", json={"slug": _SLUG})
        body = await resp.json()
    finally:
        await client.close()

    assert resp.status == 502
    assert body["code"] == "crew_cleanup_failed" and body["entryRemoved"] is True
    assert purged == [_SLUG], "the rest of Disconnect still ran"
    assert [a["outcome"] for a in audits if a.get("operation") == "connections_disconnect"] == [
        "partial"
    ]


@pytest.mark.asyncio
async def test_disconnect_always_revokes_the_crew_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Disconnect = Crew grant revoked, even when another entry keeps the native grant."""
    from kiro_crew.connections import crew_oauth, crew_oauth_proxy

    _wire(
        monkeypatch,
        removed=[],
        surviving=[],
        inventory=[_entry(_SLUG, _provider_url()), _entry("notion-work", _provider_url())],
        purged=[],
        revoked=[],
    )
    called: list[str] = []

    async def _disconnect(slug: str) -> dict:
        called.append("disconnect")
        return {"removed": True, "revoked": True}

    monkeypatch.setattr(crew_oauth, "manages", lambda _slug: True)
    monkeypatch.setattr(crew_oauth, "disconnect", _disconnect)
    monkeypatch.setattr(crew_oauth_proxy, "drop_slug", lambda slug: called.append("drop"))
    client = await _client()
    try:
        resp = await client.post("/api/connections/disconnect", json={"slug": _SLUG})
        body = await resp.json()
    finally:
        await client.close()

    assert resp.status == 200
    # Option B: the card reads "grant removed", never "kept for a sharer".
    assert body["grantSharedWith"] == [] and body["grantRemoved"] is True
    assert body["grantCensusIncomplete"] is False
    assert body["crewGrantRemoved"] is True and body["upstreamRevoked"] is True
    assert "crewGrantKept" not in body
    assert called == ["drop", "disconnect"], "Crew's grant was not revoked and cut"
