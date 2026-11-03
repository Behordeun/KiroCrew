"""With the credential rule table on, streamed output equals the batch pass's output.

``StreamRedactor`` holds back each value the table reads until its end arrives
(``security.redaction_rules.stream``), so however the text is cut into chunks
the stream writes what one batch call over the whole text writes. Every
credential here is synthetic and assembled at run time.
"""

from __future__ import annotations

import string

import pytest

from kiro_crew.security import StreamRedactor, redact
from kiro_crew.security.redaction_rules import compat

ALNUM = string.ascii_letters + string.digits


def synth(n: int, alphabet: str = ALNUM, seed: int = 0) -> str:
    step = 7 if len(alphabet) % 7 else 11
    return "".join(alphabet[(seed * 13 + i * step) % len(alphabet)] for i in range(n))


def _long_value(n: int) -> str:
    return "".join(f"v{i:09d}k-" for i in range(n // 12))


def _pem() -> str:
    body = "\n".join(synth(64, ALNUM + "+/", 10 + i) for i in range(4))
    return f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----"


FIXTURES = {
    "line value with spaces": "intro\npass" + "word=correct horse battery\nnext line",
    "header line": "GET /\nAuthor" + "ization: Bearer " + synth(40, ALNUM, 1) + " trailing\nok",
    "nested pair": "cfg pass" + "word=" + synth(20, ALNUM, 2) + " and more words\nok",
    "json quoted": 'body {"api_' + 'key": "' + synth(30, ALNUM, 3) + '", "region": "x"} end',
    "yaml": "env:\n  - name: DB_PASS" + "WORD\n    value: " + synth(20, ALNUM, 4) + "\n  - x: y\n",
    "xml": "<cfg><pass" + "word>" + synth(20, ALNUM, 5) + "</pass" + "word></cfg> done",
    "flag": "run --pass" + "word " + synth(20, ALNUM, 6) + " --verbose\nok",
    "over-long line": "x\nsecret_" + "key=" + _long_value(3000) + "\nnext",
    "over-long nested": "x cfg api_" + "key=" + _long_value(3000) + " next",
    "pem block": "key:\n" + _pem() + "\nafter",
    "unterminated pem": "key:\n-----BEGIN RSA PRIVATE KEY-----\n" + synth(64, ALNUM, 7) + "\nmore",
    "vendor token": "token gh"
    + "p_"
    + synth(36, ALNUM, 8)
    + " and gl"
    + "pat-"
    + synth(20, ALNUM, 9),
    "url param": "see https://example.com/cb?sig=" + synth(32, ALNUM, 11) + "&x=1 done",
    "url userinfo": "db postgres://app:" + synth(16, ALNUM, 12) + "@db.internal:5432/app ok",
    "prose": "Nothing secret here, just words: on a line.\nAnd another one.",
    "aws pair": "creds aws_secret_" + "access_key = " + synth(40, ALNUM + "/+", 13) + " ok\nx",
    "escaped json": 'log "{\\"pass' + 'word\\": \\"' + synth(20, ALNUM, 14) + '\\"}" end',
    "two pairs": "a token=" + synth(20, ALNUM, 15) + "; secret=" + synth(20, ALNUM, 16) + " end",
    "export line": "  export API_" + "TOKEN=" + synth(24, ALNUM, 17) + " # note\nnext",
    "token line word": "AWS_SEC" + "RET=" + synth(40, ALNUM + "/+", 18) + " keep this prose\nx",
    "authorization prose": "Author" + "ization: granted to all users.\nnext",
    "authorization value": "Author" + "ization: " + synth(24, ALNUM, 19) + "\nnext",
    "entity token param": "a &amp" + "token=" + synth(16, ALNUM, 20) + " &Amp;" + "token=x" * 3,
    "entity ref token": "&#00000000038;" + "token=" + synth(16, ALNUM, 21) + " end",
    "placeholder past floor": " &token=${" + "a" * 486 + " BEGIN RSA PRIVATE",
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


@pytest.mark.parametrize("name", sorted(FIXTURES))
@pytest.mark.parametrize("size", [1, 3, 7, 64, 600])
def test_fixed_chunks_equal_the_batch_pass(name: str, size: int) -> None:
    text = FIXTURES[name]
    chunks = [text[i : i + size] for i in range(0, len(text), size)]
    assert _stream(chunks) == redact(text)


@pytest.mark.parametrize(
    "name", sorted(n for n in FIXTURES if len(FIXTURES[n]) < 600), ids=lambda n: n
)
def test_every_two_chunk_cut_equals_the_batch_pass(name: str) -> None:
    text = FIXTURES[name]
    expected = redact(text)
    for cut in range(1, len(text)):
        assert _stream([text[:cut], text[cut:]]) == expected, cut


def test_off_runs_the_legacy_stream() -> None:
    """With the setting off nothing is held for the table's value shapes."""
    compat.publish_use_rule_table(False)
    text = "cfg pass" + "word=foo bar baz"
    redactor = StreamRedactor()
    assert redactor.feed(text[:13] + " ") == text[:13] + " "
