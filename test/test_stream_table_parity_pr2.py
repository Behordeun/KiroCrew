"""With the credential rule table on, more value shapes stream as the batch pass writes them.

Same contract as ``test_stream_table_parity``: however the text is cut into
chunks, ``StreamRedactor`` writes what one batch call over the whole text
writes. These fixtures cover a ``name``/``value`` pair with a long value,
parameter-list auth schemes (Digest, SigV4), oversized quoted values holding
escaped quotes, private-key headers and blocks, a placeholder glued to a flag
value, and the hooks that keep the legacy stream when the table's stream side
is off or cannot be loaded. Every credential here is synthetic and assembled at
run time.
"""

from __future__ import annotations

import string

import pytest

from kiro_crew.security import StreamRedactor, redact, text_redaction
from kiro_crew.security.redaction_rules import compat

ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"
TAG = "[REDACTED: credential]"


def synth(n: int, alphabet: str = ALNUM, seed: int = 0) -> str:
    step = 7 if len(alphabet) % 7 else 11
    return "".join(alphabet[(seed * 13 + i * step) % len(alphabet)] for i in range(n))


def _long_value(n: int) -> str:
    return "".join(f"v{i:09d}k-" for i in range(n // 12))


def _key_body(lines: int, seed: int) -> str:
    return "\n".join(synth(64, ALNUM + "+/", seed + i) for i in range(lines))


def _escaped_run(quote: str) -> str:
    # Longer than the stream's largest hold, so the value is dropped, not held.
    return "".join(f"w{i:05d}\\{quote}" for i in range(700))


#: Short enough for every two-chunk cut.
FIXTURES = {
    "name value long": 'cfg {"name":"pass' + 'word","value":"' + _long_value(450) + '"} done',
    "name value long words": 'cfg {"name":"pass' + 'word","value":"' + "word " * 90 + '"} ok',
    "digest": "GET /\nAuthor"
    + 'ization: Digest username="bob", realm="r", nonce="'
    + synth(16, HEX, 1)
    + '", uri="/", response="'
    + synth(32, HEX, 2)
    + '"\nnext',
    "sigv4": "GET /\nAuthor"
    + "ization: AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20250101/us-east-1/s3/aws4_request, "
    + "SignedHeaders=host;x-amz-date, Signature="
    + synth(64, HEX, 3)
    + "\nnext",
    "flag glued placeholder": "run --pass" + "word {{x}}" + synth(12, ALNUM, 4) + " --verbose\nok",
    "encrypted pem": "key:\n-----BEGIN ENCRYPTED "
    "PRIVATE KEY-----\n" + synth(64, ALNUM, 5) + "\n-----END ENCRYPTED PRIVATE KEY-----\nafter",
    "bearer after a prefix": "Header: Author" + "ization: Bearer " + synth(32, ALNUM, 6) + " more",
}

#: Past the stream's hold ceiling: the value is dropped, and the drop must end
#: where the batch pass's value ends.
OVERSIZED = {
    "escaped double quotes": 'cfg {"pass'
    + 'word": "'
    + _escaped_run('"')
    + synth(16, ALNUM, 7)
    + '"} after\nnext',
    "escaped single quotes": "cfg pass"
    + "word='"
    + _escaped_run("'")
    + synth(16, ALNUM, 8)
    + "' after\nnext",
    "rsa block": "key:\n-----BEGIN RSA "
    "PRIVATE KEY-----\n" + _key_body(80, 9) + "\n-----END RSA PRIVATE KEY-----\nafter",
    "rsa block holding another END line": "key:\n-----BEGIN RSA "
    "PRIVATE KEY-----\n"
    + _key_body(80, 10)
    + "\n-----END EC PRIVATE KEY-----\n"
    + "inside the block " * 120
    + "\n-----END RSA PRIVATE KEY-----\nafter",
}


@pytest.fixture(autouse=True)
def _table_on():
    before = compat.use_rule_table()
    compat.publish_use_rule_table(True)
    yield
    compat.publish_use_rule_table(before)


def _stream(chunks: list[str]) -> str:
    redactor = StreamRedactor()
    return "".join(redactor.feed(c) for c in chunks) + redactor.flush()


def _sized(text: str, size: int) -> list[str]:
    return [text[i : i + size] for i in range(0, len(text), size)]


@pytest.mark.parametrize("name", sorted(FIXTURES))
@pytest.mark.parametrize("size", [1, 3, 7, 64, 600])
def test_fixed_chunks_equal_the_batch_pass(name: str, size: int) -> None:
    text = FIXTURES[name]
    assert _stream(_sized(text, size)) == redact(text)


@pytest.mark.parametrize("name", sorted(FIXTURES), ids=lambda n: n)
def test_every_two_chunk_cut_equals_the_batch_pass(name: str) -> None:
    text = FIXTURES[name]
    expected = redact(text)
    for cut in range(1, len(text)):
        assert _stream([text[:cut], text[cut:]]) == expected, cut


@pytest.mark.parametrize("name", sorted(OVERSIZED))
@pytest.mark.parametrize("size", [1, 7, 64, 600, 5000])
def test_an_oversized_value_is_dropped_as_the_batch_pass_replaces_it(name: str, size: int) -> None:
    text = OVERSIZED[name]
    assert _stream(_sized(text, size)) == redact(text)


@pytest.mark.parametrize("quote", ['"', "'"])
def test_a_chunk_ending_on_a_backslash_keeps_the_escape_for_the_next_chunk(quote: str) -> None:
    """Every chunk ends right after a backslash inside the dropped value."""
    name = "escaped double quotes" if quote == '"' else "escaped single quotes"
    text = OVERSIZED[name]
    cuts = [i + 1 for i, ch in enumerate(text) if ch == "\\"]
    chunks = [text[a:b] for a, b in zip([0, *cuts], [*cuts, len(text)])]
    out = _stream(chunks)
    assert out == redact(text)
    assert synth(16, ALNUM, 7 if quote == '"' else 8) not in out


def test_a_private_key_header_split_inside_its_key_type_is_held() -> None:
    redactor = StreamRedactor()
    assert redactor.feed("key:\n-----BEGIN ENCRYPTED ") == "key:\n"
    body = synth(64, ALNUM, 11)
    rest = "PRIVATE KEY-----\n" + body + "\n-----END ENCRYPTED PRIVATE KEY-----\nafter"
    out = redactor.feed(rest) + redactor.flush()
    assert out == f"{TAG}\nafter"


def test_a_glued_placeholder_after_an_opening_brace_is_held() -> None:
    redactor = StreamRedactor()
    assert redactor.feed("run --pass" + "word {") == "run "
    value = synth(12, ALNUM, 12)
    out = redactor.feed("{x}}" + value + " --verbose\nok") + redactor.flush()
    assert out == f"--password {TAG} --verbose\nok"


def test_a_digest_header_is_held_until_its_response_parameter_arrives() -> None:
    redactor = StreamRedactor()
    head = "Author" + 'ization: Digest username="bob", realm="r", uri="/", '
    assert redactor.feed(head) == ""
    response = synth(32, HEX, 13)
    out = redactor.feed('response="' + response + '"\nnext') + redactor.flush()
    assert out == head + f'response="{TAG}"\nnext'


def test_a_mid_line_name_holds_only_its_own_word() -> None:
    """A name after other text on its line is nested in any window, so the text before it goes."""
    redactor = StreamRedactor()
    assert redactor.feed("See the api_" + "key") == "See the "
    assert redactor.feed("\n\nNext.") + redactor.flush() == "api_key\n\nNext."


def test_the_stream_side_is_not_loaded_while_the_table_is_off(monkeypatch) -> None:
    compat.publish_use_rule_table(False)
    asked: list[str] = []
    real = text_redaction._submodule

    def spy(module: str):  # type: ignore[no-untyped-def]
        asked.append(module)
        return real(module)

    monkeypatch.setattr(text_redaction, "_submodule", spy)
    text = "cfg pass" + "word=" + synth(20, ALNUM, 14) + " more\nnext"
    assert _stream(_sized(text, 5)) == redact(text)
    assert "redaction_rules.stream" not in asked


def test_a_stream_side_that_cannot_load_leaves_the_legacy_stream(monkeypatch) -> None:
    real = text_redaction._submodule

    def broken(module: str):  # type: ignore[no-untyped-def]
        if module.startswith("redaction_rules"):
            raise ImportError(module)
        return real(module)

    monkeypatch.setattr(text_redaction, "_submodule", broken)
    text = "cfg pass" + "word=foo bar baz"
    redactor = StreamRedactor()
    # As with the table off: nothing is held for the table's value shapes.
    assert redactor.feed(text[:13] + " ") == text[:13] + " "


@pytest.mark.parametrize(
    "template",
    [
        "Set-Cookie: session={v}; Path=/; HttpOnly",
        "Cookie: theme=dark; session={v}",
        "Cookie: theme=dark; session={v}\nnext",
        "session=origin",
    ],
)
def test_cookie_context_reaches_every_streamed_session_value(template):
    text = template.format(v=synth(24, ALNUM, 15))
    expected = template.format(v=TAG) if "Cookie:" in template else text
    assert redact(text) == expected
    for size in range(1, len(text) + 1):
        assert _stream(_sized(text, size)) == expected, size
    for cut in range(1, len(text)):
        assert _stream([text[:cut], text[cut:]]) == expected, cut


def test_a_cookie_header_waits_for_later_pairs_on_its_line():
    redactor = StreamRedactor()
    assert redactor.feed("Cookie: theme=dark; ") == ""
    value = synth(24, ALNUM, 16)
    out = redactor.feed(f"session={value}\nnext") + redactor.flush()
    assert out == f"Cookie: theme=dark; session={TAG}\nnext"


def test_a_bare_session_line_is_released_at_its_line_end():
    redactor = StreamRedactor()
    assert redactor.feed("session=origin\n") == "session=origin\n"
    assert redactor.flush() == ""


@pytest.mark.parametrize("count", [4000, 8000])
def test_name_value_line_boundary_checks_have_a_linear_scan_budget(monkeypatch, count):
    """Count characters offered to the newline finder, independent of runner speed."""
    from kiro_crew.security.redaction_rules import stream

    pattern = stream._LINE_BREAK
    scanned = 0

    class CountedBreaks:
        def search(self, text, pos=0, endpos=None):
            nonlocal scanned
            endpos = len(text) if endpos is None else endpos
            scanned += endpos - pos
            return pattern.search(text, pos, endpos)

    monkeypatch.setattr(stream, "_LINE_BREAK", CountedBreaks())
    text = '{"name":"password","value":"opaque-example"}' * count
    pairs = stream._name_value_pairs(text, lambda name: name == "password")
    assert len(pairs) == count
    assert scanned <= len(text)


@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n"])
def test_name_value_holds_only_cover_values_on_the_last_line(newline):
    from kiro_crew.security.redaction_rules import stream

    first = '{"name":"password","value":"finished"}'
    last = f'{{"name":"password",{newline}"value":"pending'
    text = first + newline + last
    pairs = stream._name_value_pairs(text, lambda name: name == "password")
    assert len(pairs) == 1
    assert pairs[0].cut == len(first + newline) + 1
    assert pairs[0].kind == stream.QUOTE_DOUBLE


@pytest.mark.parametrize(
    "text",
    ["password=Basic", '{"password":"Bearer"}', '{"name":"password","value":"Digest"}'],
)
def test_streamed_scheme_words_under_password_labels_are_values(text):
    expected = redact(text)
    assert TAG in expected
    for size in range(1, len(text) + 1):
        assert _stream(_sized(text, size)) == expected, size


@pytest.mark.parametrize("size", [1, 7, 64, 512, 5000])
@pytest.mark.parametrize("newline", ["\n", "\r", "\r\n"])
def test_cookie_context_survives_a_bounded_header_commit(size, newline):
    text = "Cookie: theme=" + "a" * 700 + "; session=" + synth(24, ALNUM, 17)
    text += newline + "session=origin"
    assert _stream(_sized(text, size)) == redact(text)


@pytest.mark.parametrize("count", [128, 256])
@pytest.mark.parametrize("quote", ["", '"'])
@pytest.mark.parametrize("reader", ["stream", "batch"])
def test_name_value_readers_share_one_newline_index(monkeypatch, count, quote, reader):
    """Each buffer offers its characters to the detector's newline index at most once."""
    from kiro_crew.security.redaction_rules import detectors, stream

    pattern = detectors._LINE_BREAK_RE
    scanned = 0

    class CountedBreaks:
        def finditer(self, text):
            nonlocal scanned
            scanned += len(text)
            return pattern.finditer(text)

    monkeypatch.setattr(detectors, "_LINE_BREAK_RE", CountedBreaks())
    text = ('{"name":"password","value":' + quote + "opaque-example" + quote + "}") * count
    if reader == "stream":
        pairs = stream.open_values(compat._table(), text)
        assert len(pairs) == count
        assert all(pair.kind == stream.CLOSED for pair in pairs)
    else:
        assert redact(text) == ('{"name":"password","value":' + quote + TAG + quote + "}") * count
    assert scanned <= len(text)


@pytest.mark.parametrize("has_outer", [False, True])
@pytest.mark.parametrize("raises", [False, True])
def test_open_values_restores_the_outer_scan(monkeypatch, has_outer, raises):
    from kiro_crew.security.redaction_rules import detectors, stream

    outer = detectors._Scan("outer text") if has_outer else None
    monkeypatch.setattr(detectors._SCAN, "scan", outer, raising=False)
    text = '{"name":"password","value":opaque-example}'
    table = compat._table()
    real = detectors.url_head_spans

    def inspect_scan(value):
        if value is not text:
            return real(value)
        inner = detectors._SCAN.scan
        assert inner is not outer
        assert inner.text is text
        # A nested batch call must restore the stream's cache, too.
        detectors.detect(table, "password=another-example")
        assert detectors._SCAN.scan is inner
        if raises:
            raise RuntimeError("scan interrupted")
        return real(value)

    monkeypatch.setattr(detectors, "url_head_spans", inspect_scan)
    if raises:
        with pytest.raises(RuntimeError, match="scan interrupted"):
            stream.open_values(table, text)
    else:
        assert len(stream.open_values(table, text)) == 1
    assert detectors._SCAN.scan is outer
