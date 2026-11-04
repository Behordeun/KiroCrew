"""`kirocrew doctor` reports a credentials file it may not read instead of crashing.

The credentials read can raise PermissionError (inside an agent sandbox, or on
a file with the wrong owner). The Configuration section keeps going with the
environment's credentials only, and the shared data-home helper reports the
denial: a skip inside a sandbox, an issue outside one.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from kiro_crew.config import loader
from kiro_crew.config.loader_credentials import CREDENTIAL_KEYS
from kiro_crew.doctor_checks import confinement, services


def _cfg(url: str, exc: BaseException | None = None):
    def _denied():
        raise exc if exc is not None else PermissionError(1, "Operation not permitted")

    return SimpleNamespace(
        agent=SimpleNamespace(provider="kiro", model="auto", approval_mode="auto"),
        dashboard=SimpleNamespace(url=url),
        load_credentials=_denied,
    )


@pytest.fixture(autouse=True)
def _clean_env(_floor_monkeypatch):
    _floor_monkeypatch.delenv("KIROCREW_PORT", raising=False)
    for key in CREDENTIAL_KEYS:
        _floor_monkeypatch.delenv(key, raising=False)


def _confined(monkeypatch, value):
    def _probe():
        if isinstance(value, BaseException):
            raise value
        return value

    monkeypatch.setattr(confinement, "_doctor_vantage_confined", _probe)


def test_unreadable_credentials_outside_a_sandbox_are_an_issue(monkeypatch, capsys):
    _confined(monkeypatch, False)
    issues: list[str] = []

    binding = services._doctor_configuration(_cfg("http://localhost:8080"), issues)

    out = capsys.readouterr().out
    assert "credentials: ❌ a file it reads is not readable (Operation not permitted)" in out
    assert issues == ["credentials: a file it reads is not readable"]
    assert binding.creds == {}
    assert binding.has_slack is False


def test_unreadable_credentials_inside_a_sandbox_are_a_skip(monkeypatch, capsys):
    _confined(monkeypatch, True)
    issues: list[str] = []

    services._doctor_configuration(_cfg("http://localhost:8080"), issues)

    assert "credentials: ⏭  skipped" in capsys.readouterr().out
    assert issues == []


def test_a_broken_confinement_probe_counts_the_issue(monkeypatch, capsys):
    _confined(monkeypatch, RuntimeError("probe failed"))
    issues: list[str] = []

    services._doctor_configuration(_cfg("http://localhost:8080"), issues)

    assert issues == ["credentials: a file it reads is not readable"]


def test_unreadable_credentials_keep_the_environment_tokens(monkeypatch, capsys):
    _confined(monkeypatch, True)
    monkeypatch.setenv("SLACK_APP_TOKEN", "app-token-value")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "bot-token-value")

    binding = services._doctor_configuration(_cfg("http://localhost:8080"), [])

    assert binding.creds["SLACK_APP_TOKEN"] == "app-token-value"
    assert binding.creds["SLACK_BOT_TOKEN"] == "bot-token-value"
    assert binding.has_slack is True


def test_unreadable_credentials_resolve_environment_secret_references(monkeypatch, capsys):
    _confined(monkeypatch, True)
    monkeypatch.setenv("SLACK_APP_TOKEN", "secret://missing-name")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "bot-token-value")
    seen: list[dict[str, str]] = []

    def _resolve(values, **_kwargs):
        seen.append(dict(values))
        return {k: v for k, v in values.items() if not v.startswith("secret://")}

    monkeypatch.setattr(loader, "resolve_env_credentials", _resolve)
    binding = services._doctor_configuration(_cfg("http://localhost:8080"), [])

    assert seen and seen[0]["SLACK_APP_TOKEN"] == "secret://missing-name"
    assert "SLACK_APP_TOKEN" not in binding.creds
    assert binding.has_slack is False


def test_unreadable_credentials_without_strerror_still_report(monkeypatch, capsys):
    _confined(monkeypatch, False)

    services._doctor_configuration(_cfg("http://localhost:8080", PermissionError()), [])

    assert "credentials: ❌ a file it reads is not readable" in capsys.readouterr().out
