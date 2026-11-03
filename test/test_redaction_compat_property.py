"""The credential plan with the rule table in pass 1's place (``redaction_rules.compat``).

Covers: arbitrary text never raises; known secrets are removed; a table failure
replaces the whole text with a value-free record and a metric; the internal
switch turns pass 1 back on; table rule ids reach records under their old names.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from kiro_crew.security import redaction
from kiro_crew.security.redaction_rules import compat

any_text = st.text(max_size=10_000)


@pytest.fixture
def table_on() -> Iterator[None]:
    before = compat.use_rule_table()
    compat.publish_use_rule_table(True)
    try:
        yield
    finally:
        compat.publish_use_rule_table(before)


@pytest.fixture
def broken_table(monkeypatch: pytest.MonkeyPatch, table_on: None) -> list[str]:
    """The table raises on every scan; returns the metric names counted."""
    counted: list[str] = []

    def boom(*_a: object, **_k: object) -> list[object]:
        raise ValueError("table broke")

    monkeypatch.setattr(compat, "hits", boom)
    monkeypatch.setattr(compat, "_count_fail_closed", lambda: counted.append("fail_closed"))
    return counted


class TestArbitraryTextNeverRaises:
    @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(text=any_text)
    def test_plan_never_raises(self, text: str) -> None:
        spans, warnings, rules = compat.credential_plan_via_table(text)
        assert isinstance(spans, list)
        assert isinstance(warnings, list)
        assert isinstance(rules, dict)
        assert all(start in rules for start, _end, _tag in spans)

    @settings(max_examples=300, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(text=any_text)
    def test_spans_are_sorted_and_disjoint(self, text: str) -> None:
        spans, _, _ = compat.credential_plan_via_table(text)
        cursor = 0
        for start, end, _tag in spans:
            assert cursor <= start <= end <= len(text)
            cursor = end


class TestKnownSecrets:
    CANARY_URL_CODE = "https://auth.example.test/callback?code=4/0AQlEd8xTestCanary123"
    CANARY_CODE_VALUE = "4/0AQlEd8xTestCanary123"
    CANARY_LABELLED = 'password="SuperSecret123XYZ"'
    CANARY_LABELLED_VALUE = "SuperSecret123XYZ"

    def test_url_code_param_is_redacted(self, table_on: None) -> None:
        result, _ = redaction.redact_credentials(self.CANARY_URL_CODE)
        assert self.CANARY_CODE_VALUE not in result

    def test_labelled_password_is_redacted(self, table_on: None) -> None:
        result, _ = redaction.redact_credentials(self.CANARY_LABELLED)
        assert self.CANARY_LABELLED_VALUE not in result

    def test_aws_session_token_keeps_its_old_rule_and_label(self, table_on: None) -> None:
        value = "FwoGZXIvYXdzEBYaDH" + "A" * 200
        text, _, matches = redaction.redact_credentials_with_records(f"aws_session_token={value}")
        assert value not in text
        assert [(m.rule, m.label, m.value) for m in matches] == [
            ("aws_session_token", "aws_session_token=", value)
        ]

    def test_aws_key_id_is_kept(self, table_on: None) -> None:
        text = "key AKIAIOSFODNN7EXAMPLE here"
        assert redaction.redact_credentials(text) == (text, [])

    def test_bare_secret_pass_still_runs_after_the_table(self, table_on: None) -> None:
        secret = "Kx3Q51tPusVbN8mZr2LwTq7HjYcD4fGaE9sRkU0p"
        text, warnings = redaction.redact_credentials(f"x {secret} y")
        assert secret not in text
        assert warnings == ["Redacted bare secret key (40 chars)"]

    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.too_slow])
    @given(
        before=st.text(alphabet=" \t\n", max_size=50),
        after=st.text(alphabet=" \t\n", max_size=50),
    )
    def test_labelled_password_with_whitespace_padding(self, before: str, after: str) -> None:
        was = compat.use_rule_table()
        compat.publish_use_rule_table(True)
        try:
            result, _ = redaction.redact_credentials(f"{before}{self.CANARY_LABELLED}{after}")
        finally:
            compat.publish_use_rule_table(was)
        assert self.CANARY_LABELLED_VALUE not in result


class TestFailClosed:
    TEXT = "token ghp_" + "a" * 36 + " and prose"

    def test_whole_text_is_replaced(self, broken_table: list[str]) -> None:
        text, warnings = redaction.redact_credentials(self.TEXT)
        assert text == redaction.REDACTION_UNAVAILABLE_TAG
        assert warnings == ["Redaction unavailable: whole text replaced"]
        assert broken_table == ["fail_closed"]

    def test_record_carries_no_value(self, broken_table: list[str]) -> None:
        text, _, matches = redaction.redact_credentials_with_records(self.TEXT)
        assert text == redaction.REDACTION_UNAVAILABLE_TAG
        assert [tuple(m) for m in matches] == [(0, redaction.REDACTION_UNAVAILABLE_RULE, "", "")]

    def test_log_names_only_the_error_type(
        self, broken_table: list[str], caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger=compat.__name__):
            redaction.redact_credentials(self.TEXT)
        assert "ValueError" in caplog.text
        assert "ghp_" not in caplog.text and "table broke" not in caplog.text

    def test_load_failure_fails_closed_and_health_reports_it(
        self, monkeypatch: pytest.MonkeyPatch, table_on: None
    ) -> None:
        def no_table() -> object:
            raise OSError("missing")

        monkeypatch.setattr(compat, "load_table", no_table)
        monkeypatch.setattr(compat, "_LOAD_FAILED", False)
        monkeypatch.setattr(compat, "_count_fail_closed", lambda: None)
        assert compat.check_table_health() is False
        assert redaction.redact_credentials(self.TEXT)[0] == redaction.REDACTION_UNAVAILABLE_TAG


class TestSetting:
    def test_off_runs_pass_one(self) -> None:
        before = compat.use_rule_table()
        try:
            compat.publish_use_rule_table(False)
            assert redaction.redact_credentials("AKIAIOSFODNN7EXAMPLE")[0] == (
                redaction.REDACTED_CREDENTIAL_TAG
            )
            compat.publish_use_rule_table(True)
            assert redaction.redact_credentials("AKIAIOSFODNN7EXAMPLE")[0] == (
                "AKIAIOSFODNN7EXAMPLE"
            )
        finally:
            compat.publish_use_rule_table(before)

    def test_every_old_rule_name_has_a_tier(self) -> None:
        from kiro_crew.credential_patterns import RULE_TIERS

        names = set(compat._OLD_RULE.values()) | {redaction.REDACTION_UNAVAILABLE_RULE}
        assert names <= set(RULE_TIERS)
