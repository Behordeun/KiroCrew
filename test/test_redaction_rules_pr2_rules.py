"""Rule-table rows and detectors with the table switched on.

Each case states its input and the full redaction's expected output, read
through ``redaction.redact_credentials`` with the internal switch on, so it
checks what a caller sees and not only the table's own pass. Credential-shaped
values are assembled at run time.
"""

from __future__ import annotations

import string
from collections.abc import Iterator

import pytest

from kiro_crew.security import redaction
from kiro_crew.security import redaction_rules as rr
from kiro_crew.security.redaction_rules import compat

R = rr.PLACEHOLDER
ALNUM = string.ascii_letters + string.digits


def synth(n: int, alphabet: str = ALNUM, seed: int = 0) -> str:
    step = 7 if len(alphabet) % 7 else 11
    return "".join(alphabet[(seed * 13 + i * step) % len(alphabet)] for i in range(n))


@pytest.fixture(autouse=True)
def table_on() -> Iterator[None]:
    before = compat.use_rule_table()
    compat.publish_use_rule_table(True)
    try:
        yield
    finally:
        compat.publish_use_rule_table(before)


def shown(text: str) -> str:
    return redaction.redact_credentials(text)[0]


def table_ids(text: str) -> list[str]:
    return [r.rule_id for r in rr.redact_with_findings(text).records]


# ── A bare auth scheme word ──


@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer",
        "fix Authorization: Bearer",
        "Authorization: Basic",
        "Authorization: Token",
        '{"authorization": "Bearer"}',
        "Authorization: 'Bearer'",
        "Authorization: Bearer   ",
    ],
)
def test_a_scheme_word_alone_is_kept(text: str) -> None:
    assert shown(text) == text


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Authorization: Bearer\nopaque-example", f"Authorization: Bearer\n{R}"),
        ("Authorization: Bearer \r\n  opaque-example", f"Authorization: Bearer \r\n  {R}"),
        (
            "R  Authorization: Bearer\nopaque-example\0old.txt\0",
            f"R  Authorization: Bearer\n{R}\0old.txt\0",
        ),
    ],
)
def test_the_token_on_the_line_after_a_bare_bearer_is_redacted(text: str, expected: str) -> None:
    assert shown(text) == expected


def test_a_quoted_bare_scheme_does_not_reach_the_next_line() -> None:
    text = '{"authorization": "Bearer"}\nnext-line-word'
    assert shown(text) == text


def test_a_no_break_space_after_the_scheme_is_a_separator() -> None:
    token = "opaque-" + synth(16, ALNUM, 1)
    assert shown(f"Authorization: Bearer\u00a0{token}") == f"Authorization: Bearer\u00a0{R}"


def test_a_spaced_bearer_token_keeps_the_scheme_word() -> None:
    assert shown("Authorization: Bearer opaque-example") == f"Authorization: Bearer {R}"


# ── Names that are not credential labels ──


@pytest.mark.parametrize(
    "text",
    [
        '{"max_token": "plain"}',
        "stop_token: plain",
        "eos_token = plainvalue",
        "pad_token: <pad>",
        "pagination_token: abcd1234",
    ],
)
def test_singular_model_and_cursor_settings_are_kept(text: str) -> None:
    assert shown(text) == text


def test_a_credential_ending_in_token_is_still_redacted() -> None:
    assert shown("admin_token: plainvalue") == f"admin_token: {R}"
    assert shown("backend_token: plainvalue") == f"backend_token: {R}"


@pytest.mark.parametrize(
    "text",
    [
        "{'session': 'origin'}",
        "session='origin'",
        "session=chat-1830",
        "could not create a session: 'kirocrew-worker' does not resolve",
        "Project hooks do not run in this session: Crew does not run commands",
        "Error: could not fork the session: slot cap reached (500)",
        "could not create a session: cannot verify delegation",
    ],
)
def test_a_bare_session_field_outside_a_cookie_header_is_kept(text: str) -> None:
    assert shown(text) == text


@pytest.mark.parametrize(
    "template",
    [
        "Cookie: session={v}",
        "Set-Cookie: session={v}; Path=/",
        'curl -H "Cookie: theme=dark; session={v}" https://app.example.com/me',
        "curl --cookie session={v} https://app.example.com/me",
        "PHPSESSID={v}",
        "sessionid={v}",
    ],
)
def test_a_session_cookie_is_redacted(template: str) -> None:
    value = synth(24, ALNUM, 2)
    assert shown(template.format(v=value)) == template.format(v=R)


def test_a_cookie_header_on_an_earlier_line_does_not_reach_a_later_session() -> None:
    text = "Cookie: theme=dark\nsession: origin-chat"
    assert shown(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "set `DEEPSEEK_API_KEY: secret://my-dsh-key`, then start a new chat",
        "api_key=secret://prod/openai",
        '{"token": "secret://gh-token"}',
    ],
)
def test_a_vault_reference_is_kept(text: str) -> None:
    assert shown(text) == text


@pytest.mark.parametrize(
    "text",
    [
        '{"permission": {"*": "ask", "bash": {"pwd": "deny"}}}',
        '{"bash": {"pwd": "allow"}, "probe_secret": "deny"}',
        "pwd: always_allow",
    ],
)
def test_a_permission_decision_under_a_command_name_is_kept(text: str) -> None:
    assert shown(text) == text


def test_a_real_value_under_pwd_is_still_redacted() -> None:
    assert shown('{"pwd": "hunter2hunter2"}') == f'{{"pwd": "{R}"}}'


@pytest.mark.parametrize(
    "text",
    [
        "OAUTH_TOKEN=<hidden sha256:1a2b3c4d>",
        "env OAUTH_TOKEN=<hidden sha256:1a2b3c4d> next",
        "  OAUTH_TOKEN=<hidden sha256:1a2b3c4d>\n",
    ],
)
def test_an_angle_bracket_placeholder_with_a_blank_is_kept_whole(text: str) -> None:
    assert shown(text) == text


def test_text_glued_after_an_angle_placeholder_is_still_a_value() -> None:
    assert shown("password=<s3cr3t>hunter2 user=bob") == f"password={R}"


# ── Owner ruling #3: a dotted or underscored `...password` field ──


@pytest.mark.parametrize("name", ["DB.PASSWORD", "DB_PASSWORD", "spring.datasource.password"])
def test_a_field_named_password_is_a_password_field(name: str) -> None:
    assert shown(f"{name}=ordinary") == f"{name}={R}"


# ── Misses the legacy pass caught ──


def _link_token(dash: bool) -> str:
    # A payload with `g-z` at every 4th place is not base64url of ASCII JSON,
    # so after a `.` only the `-` makes it a token.
    letters = string.ascii_lowercase * 4
    payload = "eyJ" + ("abcd-" if dash else "abcd") + letters[:100]
    return payload + "." + letters[:43]


@pytest.mark.parametrize("lead", ["Open the link.", "prefix.", "see ."])
def test_a_link_token_right_after_a_dot_is_redacted(lead: str) -> None:
    token = _link_token(dash=True)
    assert shown(f"{lead}{token} to continue") == f"{lead}{R} to continue"
    assert table_ids(f"{lead}{token}") == ["link_token.unverified"]


def test_a_dotted_member_chain_shaped_like_a_link_token_is_kept() -> None:
    text = "obj." + _link_token(dash=False)
    assert shown(text) == text


@pytest.mark.parametrize(
    "text, expected",
    [
        ("https://user:ab'cd@host/", f"https://user:{R}@host/"),
        (
            "https://x:hunter2hunter2\u0080%&'()*~~:~~\u0080@db.example.com/",
            f"https://x:{R}@db.example.com/",
        ),
    ],
)
def test_a_url_password_holding_an_apostrophe_is_redacted(text: str, expected: str) -> None:
    assert shown(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "SecretAccessKey\n: short-secret-value",
        "x(u)(u)\n\nSecretAccessKey\n   : " + synth(40, ALNUM + "/+", 5),
        "aws_session_token\n= " + synth(24, ALNUM, 6),
    ],
)
def test_an_aws_field_whose_separator_opens_the_next_line_is_redacted(text: str) -> None:
    out = shown(text)
    assert out.endswith(R)
    assert text.rsplit(" ", 1)[-1] not in out


def test_an_aws_field_name_in_prose_is_kept() -> None:
    text = "Rotate the SecretAccessKey\nwhen the key ages out."
    assert shown(text) == text


@pytest.mark.parametrize("scheme", ["Basic", "Bearer", "Token", "Digest", "AWS4-HMAC-SHA256"])
@pytest.mark.parametrize(
    "template, name",
    [
        ("password={v}", "password"),
        ('{{"password":"{v}"}}', "password"),
        ("api_key={v}", "api_key"),
        ('{{"name":"password","value":"{v}"}}', "password"),
    ],
)
def test_a_scheme_word_under_an_ordinary_credential_label_is_a_value(scheme, template, name):
    assert shown(template.format(v=scheme)) == template.format(v=R)


@pytest.mark.parametrize("name", ["Authorization", "Proxy-Authorization", "X-Authorization"])
@pytest.mark.parametrize("scheme", ["Bearer", "Basic", "Token", "Digest", "AWS4-HMAC-SHA256"])
def test_a_bare_scheme_is_kept_only_for_authorization_labels(name, scheme):
    text = f"{name}: {scheme}"
    assert shown(text) == text
