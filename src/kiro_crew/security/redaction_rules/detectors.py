"""The detectors behind the credential rule table.

Each function turns one rule into the spans of a text it claims. None of them
decides by a value's shape alone: a pattern rule needs its vendor prefix or
structural markers (and, for ``key_id_pair``, a key ID nearby), and the
``labelled`` and ``url_param`` detectors decide by the field or parameter NAME a
value sits under. Every regex here is bounded, so a scan is linear in the text.

A value is read through to its natural end (end of line, closing quote, end of
the container's run) however long it is: a bounded run that reaches
``MAX_VALUE_LEN`` is continued from where it stopped (:class:`_Scan`), so no
tail of an over-long value is left in plain text.
"""

from __future__ import annotations

import bisect
import logging
import re
import threading
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass

from kiro_crew.security.redaction_rules.model import Detector, Hit
from kiro_crew.security.redaction_rules.rules import (
    MAX_VALUE_LEN,
    Rule,
    RuleTable,
    normalise_name,
)

logger = logging.getLogger(__name__)

#: Values shorter than this under a name-keyed detector are ignored: they are
#: flags, booleans and enum words far more often than secrets.
MIN_NAMED_VALUE_LEN = 4

_N = MAX_VALUE_LEN

_URL_SCHEME_RE = re.compile(r"(?<![A-Za-z0-9+.\-])[A-Za-z][A-Za-z0-9+.\-]{0,31}://")
_URL_BODY_RE = re.compile(rf"[^\s\"'<>`]{{0,{_N}}}")
#: The part of a URL the labelled detector leaves to the URL rules. It ends at
#: ``;``: in a connection string (``Endpoint=sb://host/;Key=...``,
#: ``jdbc:sqlserver://db;password=...``) the pairs after it are not part of the
#: URL. Query parameters are still read over the whole URL.
_URL_HEAD_BODY_RE = re.compile(rf"[^\s\"'<>`;]{{0,{_N}}}")
_QUERY_START_RE = re.compile(r"[?#]")
_PARAM_RE = re.compile(rf"[?&#](?P<name>[^=&#?\s]{{1,128}})=(?P<val>[^&#?\s\"'<>`)\]]{{0,{_N}}})")
_PARAM_VALUE_RE = re.compile(rf"[^&#?\s\"'<>`)\]]{{0,{_N}}}")

_KEY_RE = re.compile(
    r"(?<![A-Za-z0-9_.\-])(?P<dash>--?)?(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})(?![A-Za-z0-9_.\-])"
)
#: ``key = value`` / ``key: value`` / ``"key": value`` / ``key => value``, with
#: an optional (escaped) closing quote on the key. ``::``, ``://`` and ``==``
#: are not separators.
_SEP_RE = re.compile(r"(?:\\?[\"'])?[ \t]{0,8}(?:=>|:(?![:/])|=(?!=))[ \t]{0,8}")
#: ``--flag value``: a CLI flag also takes its value after plain whitespace,
#: unless the next word is another flag.
_FLAG_SEP_RE = re.compile(r"[ \t]{1,8}(?=[^\s\-])")

#: An auth scheme word and its separator. A no-break space separates as a space
#: does, and a scheme word alone at the end of its value region (a bare
#: ``Authorization: Bearer``, a quoted value holding only the scheme) is a scheme
#: with no credential after it on that line.
_SCHEME_RE = re.compile(r"(?i:(bearer|basic|token|digest|aws4-hmac-sha256))(?:[ \t\u00a0]{1,8}|\Z)")
#: The token on the line after a bare ``Bearer``, as the legacy ``Bearer\s+token`` read it.
_NEXT_LINE_TOKEN_RE = re.compile(r"[ \t\u00a0]{0,64}\r?\n\s{0,16}(?=[A-Za-z0-9._~+/\-]{4})")
_BLANKS_TO_END_RE = re.compile(r"[ \t\u00a0]{0,64}\Z")
#: Schemes whose credentials are a parameter list: only the named parameter is
#: secret, and the rest (an AWS key ID and credential scope, a Digest realm) is
#: kept.
_SCHEME_PARAM = {
    scheme: re.compile(
        rf"(?i)(?<![A-Za-z0-9_]){param}[ \t]{{0,8}}=[ \t]{{0,8}}\"?([^\s\",;]{{1,{_N}}})"
    )
    for scheme, param in (("digest", "response"), ("aws4-hmac-sha256", "signature"))
}
#: Schemes whose credential is one token68 (RFC 7235 §2.1), which holds no blank:
#: the value ends where the token does, and the text after it on the line is kept.
_TOKEN68_SCHEMES = frozenset({"bearer", "basic", "token"})
_TOKEN68_RUN_RE = re.compile(rf"[A-Za-z0-9._~+/\-]{{0,{_N}}}")
#: The body of a quoted value, one bounded chunk at a time: a backslash escapes
#: the next character, and a value never crosses a line.
_QUOTED_BODY_RE = {q: re.compile(rf"(?:[^{q}\\\n]|\\.){{0,{_N}}}") for q in "\"'"}
_ESCAPED_QUOTED_BODY_RE = {q: re.compile(rf"[^{q}\\\n]{{0,{_N}}}") for q in "\"'"}
_UNQUOTED_RE = re.compile(rf"[^\s\"'`,;&)\]}}]{{1,{_N}}}")
_UNQUOTED_RUN_RE = re.compile(rf"[^\s\"'`,;&)\]}}]{{0,{_N}}}")
_FLAG_VALUE_RE = re.compile(rf"[^\s\"'`]{{1,{_N}}}")
_FLAG_VALUE_RUN_RE = re.compile(rf"[^\s\"'`]{{0,{_N}}}")
#: The run each value regex reads, for continuing a match that reached the cap.
_RUN_OF = {_UNQUOTED_RE: _UNQUOTED_RUN_RE, _FLAG_VALUE_RE: _FLAG_VALUE_RUN_RE}

#: Value shapes: a line-oriented assignment, a CLI flag, or a pair nested in
#: other text.
LINE = "line"
FLAG = "flag"
NESTED = "nested"
#: What may precede a key that opens a line-oriented assignment: indentation, a
#: shell ``export``/``set``/``declare``, or a YAML list dash.
_LINE_LEAD_RE = re.compile(r"[ \t]{0,64}(?:(?:export|set|setx|declare)[ \t]{1,8}|-[ \t]{1,8})?")
_LEAD_MAX = 80
#: One template placeholder: ``${VAR}``, or ``{{ var }}`` whose body may hold a
#: lone ``}`` (``default({})``) and ends at the first ``}}``.
_TEMPLATE_ONE = r"(?:\$\{[^{}\r\n]{1,200}\}|\{\{(?:[^}\r\n]|\}(?!\})){0,200}\}\})"
#: A template placeholder, or a run of up to eight joined by at most three of
#: `` -/:.,_`` (``${A}${B}``, ``{{ a }}-{{ b }}``), is read whole, so the
#: table's allow entries see it as written instead of cut at a brace.
_TEMPLATE_RE = re.compile(
    rf"{_TEMPLATE_ONE}(?:[ \t\-/:.,_]{{0,3}}{_TEMPLATE_ONE}){{0,7}}(?=[\s\"'`,;&)\]}}]|$)"
)
#: A template run with text glued after it (``{{ x }}hunter2``) is a value, read
#: through the trailing text, so the allow list does not keep it as a template.
_GLUED_TEMPLATE_RE = re.compile(rf"{_TEMPLATE_ONE}{{1,8}}[^\s\"'`,;&)\]}}]{{1,{_N}}}")
#: An angle-bracket placeholder (``<hidden sha256:...>``) is read whole, blanks
#: included, so the table's ``<...>`` allow entry sees it as written.
_ANGLE_RE = re.compile(r"<[^<>\r\n]{1,200}>(?=[\s\"'`,;&)\]}]|$)")
_LINE_BREAK_RE = re.compile(r"[\r\n]")
#: ``<password>value</password>``: the tag name is the key, the text up to the
#: matching close tag is the value.
_XML_OPEN_RE = re.compile(r"<(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})(?:[ \t][^<>\r\n]{0,500})?>")
_XML_TEXT_RE = re.compile(rf"[^<\r\n]{{0,{_N}}}")
_XML_CLOSE_RE = re.compile(r"</(?P<key>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[ \t]{0,8}>")
#: A ``name``/``key`` field naming the label, as JSON, YAML or an XML
#: attribute; its ``value`` field must follow within the same object.
_NAME_FIELD_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])[\"']?(?:name|key)[\"']?[ \t]{0,8}[:=][ \t]{0,8}"
    r"[\"']?(?P<name>[A-Za-z_][A-Za-z0-9_.\-]{0,63})[\"']?"
)
_VALUE_FIELD_RE = re.compile(
    r"[^{}<>\[\]]{0,200}?(?<![A-Za-z0-9_\-])[\"']?value[\"']?[ \t]{0,8}[:=][ \t]{0,8}"
)
#: A value opening one of these is a nested structure or an existing
#: placeholder, not a scalar to judge.
_NOT_A_VALUE_START = frozenset("\r\n[{(")


@dataclass(frozen=True)
class _Named:
    """A ``name -> value`` pair a name-keyed detector judges."""

    name: str
    start: int
    end: int


class _Spans:
    """Sorted, non-overlapping spans with an O(log n) containment test."""

    def __init__(self, spans: Sequence[tuple[int, int]]) -> None:
        self._starts = [s for s, _ in spans]
        self._ends = [e for _, e in spans]

    def contains(self, pos: int) -> bool:
        i = bisect.bisect_right(self._starts, pos) - 1
        return i >= 0 and pos < self._ends[i]


class _Scan:
    """Reads value runs of one text through to their natural end, in linear time.

    Every value regex is bounded at ``MAX_VALUE_LEN`` characters, so a value
    longer than that would stop mid-value and leave its tail in plain text. A
    run that reaches the bound is continued, one bounded chunk at a time, until
    it stops short of it. Line ends come from one pass over the text, and the
    last run read per character class is remembered: a run of one class has the
    same end from any position inside it, so values nested in one long run cost
    one read of it, not one each.

    A quoted body can hold escapes, so its run is not position-independent and
    is not remembered. Its reads share a budget of a few times the text length;
    past it a quoted value runs to the end of its line, which is never shorter
    than the quoted value itself, since a quoted value never crosses a line.
    """

    def __init__(self, text: str) -> None:
        self.text = text
        self._breaks: list[int] | None = None
        self._runs: dict[re.Pattern[str], tuple[int, int]] = {}
        self._quoted_budget = 4 * len(text) + 4 * _N

    def line_end(self, i: int) -> int:
        """The first ``\\r`` or ``\\n`` at or after ``i``, else the text's end."""
        if self._breaks is None:
            self._breaks = [m.start() for m in _LINE_BREAK_RE.finditer(self.text)]
        k = bisect.bisect_left(self._breaks, i)
        return self._breaks[k] if k < len(self._breaks) else len(self.text)

    def run_end(self, run: re.Pattern[str], i: int, limit: int | None = None) -> int:
        """End of the maximal run ``run`` (a ``[class]{0,N}`` regex) reads from ``i``."""
        limit = len(self.text) if limit is None else limit
        last = self._runs.get(run)
        if last is not None and last[0] <= i <= last[1]:
            return min(last[1], limit)
        pos = i
        while True:
            m = run.match(self.text, pos)
            if m is None or m.end() == pos:
                break
            pos = m.end()
            if pos - m.start() < _N:
                break
        self._runs[run] = (i, pos)
        return min(pos, limit)

    def quoted_end(self, q: str, i: int) -> int | None:
        """Where the quoted body opening at ``i`` closes, or None if not on its line."""
        body = _QUOTED_BODY_RE[q]
        pos = i
        while True:
            m = body.match(self.text, pos)
            if m is None:
                break
            self._quoted_budget -= m.end() - pos + 1
            pos = m.end()
            if m.end() - m.start() < _N:
                break
            if self._quoted_budget < 0:
                return None
        return pos if self.text.startswith(q, pos) else None

    def quoted_budget_left(self) -> bool:
        return self._quoted_budget >= 0


_SCAN = threading.local()


def _scan_for(text: str) -> _Scan:
    """The :class:`_Scan` :func:`detect` opened for ``text`` on this thread, else a new one."""
    scan = getattr(_SCAN, "scan", None)
    return scan if scan is not None and scan.text is text else _Scan(text)


def _line_end(text: str, i: int) -> int:
    return _scan_for(text).line_end(i)


def _value_region(text: str, i: int) -> tuple[int, int, bool] | None:
    """Where a value starting at ``i`` may lie: ``(start, end, quoted)``.

    An unterminated quote runs to the end of its line, so a value cut off by a
    truncated log line is still judged.
    """
    if i >= len(text):
        return None
    scan = _scan_for(text)
    if text[i] == "\\" and text[i + 1 : i + 2] in ('"', "'"):
        q = text[i + 1]
        end = scan.run_end(_ESCAPED_QUOTED_BODY_RE[q], i + 2)
        if text.startswith("\\" + q, end):
            return i + 2, end, True
        i += 1
    if text[i] in "\"'":
        close = scan.quoted_end(text[i], i + 1) if scan.quoted_budget_left() else None
        if close is not None:
            return i + 1, close, True
        return i + 1, scan.line_end(i + 1), True
    if text[i] in _NOT_A_VALUE_START and not text.startswith("{{", i):
        return None
    return i, scan.line_end(i), False


def _token68_end(text: str, start: int, hi: int) -> int:
    """Where the token68 credential starting at ``start`` ends, its ``=`` padding included."""
    end = _scan_for(text).run_end(_TOKEN68_RUN_RE, start, hi)
    if end > start:
        while end < hi and text[end] == "=":
            end += 1
    return end


def _min_len(start: int, end: int) -> tuple[int, int] | None:
    return (start, end) if end - start >= MIN_NAMED_VALUE_LEN else None


def labelled_value(text: str, i: int, shape: str = NESTED) -> tuple[int, int] | None:
    """The span of the value after a separator ending at ``i``, auth scheme stripped.

    ``shape`` decides where an unquoted value ends. A ``LINE`` assignment (env,
    INI, YAML, an HTTP header) runs to the end of its line, as those formats
    read it, so a password holding ``,`` ``;`` or a space is replaced whole. A
    ``FLAG`` value runs to the next blank. A ``NESTED`` pair (a cookie, an
    inline object, a pair inside another value) stops at its container's
    delimiters.
    """
    region = _value_region(text, i)
    if region is None:
        return None
    lo, hi, quoted = region
    start = lo
    scheme = _SCHEME_RE.match(text, lo, hi)
    if scheme:
        param = _SCHEME_PARAM.get(scheme.group(1).lower())
        if param is not None:
            m = param.search(text, scheme.end(), hi)
            return m.span(1) if m else None
        start = scheme.end()
        if _BLANKS_TO_END_RE.match(text, start, hi):
            # A scheme word with nothing after it on its line: only a bare
            # unquoted ``Bearer`` takes the token on the next line.
            nxt = None
            if not quoted and scheme.group(1).lower() == "bearer":
                nxt = _NEXT_LINE_TOKEN_RE.match(text, start)
            if nxt is None:
                return None
            start, hi = nxt.end(), _scan_for(text).line_end(nxt.end())
            return _min_len(start, _token68_end(text, start, hi))
        if start < hi and text[start] in _NOT_A_VALUE_START:
            return None
        if scheme.group(1).lower() in _TOKEN68_SCHEMES:
            end = _token68_end(text, start, hi)
            if end > start:
                return _min_len(start, end)
    if quoted or shape == LINE:
        end = len(text[start:hi].rstrip()) + start
    else:
        value_re = _FLAG_VALUE_RE if shape == FLAG else _UNQUOTED_RE
        m = (
            _TEMPLATE_RE.match(text, start, hi)
            or _ANGLE_RE.match(text, start, hi)
            or _GLUED_TEMPLATE_RE.match(text, start, hi)
            or value_re.match(text, start, hi)
        )
        if m is None:
            return None
        end = m.end()
        run = _RUN_OF.get(m.re, _UNQUOTED_RUN_RE if m.re is _GLUED_TEMPLATE_RE else None)
        if run is not None:
            # A run that reached the cap goes on to its natural end.
            end = _scan_for(text).run_end(run, end, hi)
    return (start, end) if end - start >= MIN_NAMED_VALUE_LEN else None


def named_value(text: str, i: int, shape: str, name: str) -> tuple[int, int] | None:
    """Read a labelled value, treating a bare scheme as a value outside auth fields."""
    if not is_authorization_name(name):
        region = _value_region(text, i)
        if region is not None:
            lo, hi, _ = region
            scheme = _SCHEME_RE.match(text, lo, hi)
            if scheme and _BLANKS_TO_END_RE.match(text, scheme.end(), hi):
                return _min_len(lo, lo + len(text[lo:hi].rstrip()))
    return labelled_value(text, i, shape)


#: Field names (as a suffix of the normalised name) whose line-oriented value is
#: a phrase that may hold blanks, so it runs to the end of its line. Every other
#: credential name (a token, a key, a secret, an AWS field, ``authorization``)
#: reads one blank-free token, and the text after it on the line is kept.
PHRASE_NAMES = ("password", "passwd", "pwd", "passphrase")


def reads_phrase(name: str) -> bool:
    """Whether a line-oriented value under ``name`` runs to the end of its line."""
    return name.endswith(PHRASE_NAMES)


def _key_shape(text: str, key_start: int, dash: bool, name: str = "") -> str:
    """How the pair whose key starts at ``key_start`` reads its value."""
    if dash:
        return FLAG
    line_start = text.rfind("\n", max(0, key_start - _LEAD_MAX), key_start) + 1
    if line_start == 0 and key_start > _LEAD_MAX:
        return NESTED
    if not _LINE_LEAD_RE.fullmatch(text, line_start, key_start):
        return NESTED
    return LINE if reads_phrase(name) else FLAG


#: An HTML character reference (``&amp``, ``&Amp;``, ``&quest``, ``&#38;``)
#: right before a field name: the name is a query parameter spelled with an
#: escaped separator.
_ENTITY_LEAD_RE = re.compile(r"&(?:#[0-9A-Fa-fXx]{1,16};?|[A-Za-z]{2,8};?)+\Z")
#: Entity names that glue onto the name after them when their ``;`` is missing.
_GLUED_ENTITIES = ("amp", "quest")
#: The parameter name pass 4 (``token=``) owns in every separator spelling.
_TOKEN_PARAM_NAME = "token"
_ENTITY_LOOKBACK = 64


def pair_name(text: str, key_start: int, key: str) -> str | None:
    """The normalised name of the pair whose key ``key`` starts at ``key_start``.

    An escaped separator glued to the key (``&amptoken``) is not part of the
    name. ``None`` when the pair is a ``token`` parameter behind an escaped
    separator: pass 4 owns that parameter and decides which spellings decode.
    """
    name, entity = entity_led_name(text, key_start, key)
    return None if entity and name == _TOKEN_PARAM_NAME else name


def entity_led_name(text: str, key_start: int, key: str) -> tuple[str, bool]:
    """``(name, behind an escaped separator)`` for :func:`pair_name`."""
    entity = False
    if text[key_start - 1 : key_start] == "&":
        low = key.lower()
        for glued in _GLUED_ENTITIES:
            if low.startswith(glued) and len(low) > len(glued):
                key, entity = key[len(glued) :], True
                break
    if not entity:
        entity = bool(_ENTITY_LEAD_RE.search(text, max(0, key_start - _ENTITY_LOOKBACK), key_start))
    return normalise_name(key), entity


#: The field name whose value, with no auth scheme, is kept when more words
#: follow it on its line: that is prose about authorization, not a header.
_AUTHORIZATION = "authorization"


def is_authorization_name(name: str) -> bool:
    """Whether a normalised name matches the table's authorization label suffix."""
    return name.endswith(_AUTHORIZATION)


def is_authorization_prose(text: str, name: str, vstart: int, span: tuple[int, int]) -> bool:
    """Whether ``span`` is a scheme-less word of prose under ``authorization``."""
    if (
        name != _AUTHORIZATION
        or _SCHEME_RE.match(text, vstart, _line_end(text, vstart))
        or text[vstart : vstart + 1] in "\"'\\"
    ):
        return False
    end = span[1]
    rest = text[end : _line_end(text, end)]
    return bool(rest.strip())


def label_candidates(
    text: str, urls: _Spans, wanted: Callable[[str], bool] = lambda name: True
) -> list[_Named]:
    """Every ``key <sep> value`` pair outside a URL whose key ``wanted`` accepts.

    Covers ``key = value`` shapes, XML elements (``<password>...</password>``)
    and name/value pairs (``{"name": "password", "value": "..."}``,
    ``<add key="password" value="..."/>``). The key is judged before its value
    is read, so text full of unrelated pairs costs one key match per pair. The
    scan resumes right after each separator rather than after the value, so a
    pair inside another pair's value (``-H "X-Api-Key: ..."``,
    ``Set-Cookie: api_key=...``) is found too.
    """
    found: list[_Named] = []
    pos = 0
    while True:
        m = _KEY_RE.search(text, pos)
        if m is None:
            break
        sep = _SEP_RE.match(text, m.end())
        if sep is None and m.group("dash"):
            sep = _FLAG_SEP_RE.match(text, m.end())
        if sep is None:
            pos = m.end()
            continue
        pos = sep.end()
        name = pair_name(text, m.start(), m.group("key"))
        if name is None or not wanted(name) or urls.contains(m.start()):
            continue
        shape = _key_shape(text, m.start(), bool(m.group("dash")), name)
        span = named_value(text, sep.end(), shape, name)
        if span is not None and not is_authorization_prose(text, name, sep.end(), span):
            found.append(_Named(name, *span))
    found.extend(_xml_elements(text, urls, wanted))
    found.extend(_name_value_pairs(text, urls, wanted))
    return found


def _xml_elements(text: str, urls: _Spans, wanted: Callable[[str], bool]) -> Iterator[_Named]:
    scan = _scan_for(text)
    pos = 0
    while (m := _XML_OPEN_RE.search(text, pos)) is not None:
        pos = m.start() + 1
        start = m.end()
        end = scan.run_end(_XML_TEXT_RE, start)
        close = _XML_CLOSE_RE.match(text, end)
        if end == start or close is None or close.group("key") != m.group("key"):
            continue
        pos = close.end()
        name = normalise_name(m.group("key"))
        if not wanted(name) or urls.contains(m.start()):
            continue
        raw = text[start:end]
        start += len(raw) - len(raw.lstrip())
        end -= len(raw) - len(raw.rstrip())
        if end - start >= MIN_NAMED_VALUE_LEN:
            yield _Named(name, start, end)


def _name_value_pairs(text: str, urls: _Spans, wanted: Callable[[str], bool]) -> Iterator[_Named]:
    for m in _NAME_FIELD_RE.finditer(text):
        name = normalise_name(m.group("name"))
        if not wanted(name) or urls.contains(m.start()):
            continue
        value = _VALUE_FIELD_RE.match(text, m.end())
        if value is None:
            continue
        span = named_value(text, value.end(), NESTED, name)
        if span is not None:
            yield _Named(name, *span)


def url_parameters(text: str, url_spans: Sequence[tuple[int, int]]) -> list[_Named]:
    """Every query and fragment parameter of every URL in ``text``.

    ``?`` and ``#`` inside a value also start a parameter, so a URL nested in a
    ``redirect_uri`` does not hide its own parameters.
    """
    found: list[_Named] = []
    for start, end in url_spans:
        q = _QUERY_START_RE.search(text, start, end)
        if q is None:
            continue
        scan = _scan_for(text)
        pos = q.start()
        while (m := _PARAM_RE.search(text, pos, end)) is not None:
            val_start = m.start("val")
            val_end = scan.run_end(_PARAM_VALUE_RE, val_start, end)
            pos = max(val_end, m.end())
            if val_end - val_start >= MIN_NAMED_VALUE_LEN:
                found.append(_Named(normalise_name(m.group("name")), val_start, val_end))
    return found


def _url_spans(text: str, body: re.Pattern[str]) -> list[tuple[int, int]]:
    """Every URL in ``text``, its body read by ``body`` through to its natural end."""
    scan = _scan_for(text)
    spans: list[tuple[int, int]] = []
    pos = 0
    while (m := _URL_SCHEME_RE.search(text, pos)) is not None:
        end = scan.run_end(body, m.end())
        if end == m.end():
            pos = m.start() + 1
            continue
        spans.append((m.start(), end))
        pos = end
    return spans


def _name_matches(name: str, labels: frozenset[str], exclude: frozenset[str], suffix: bool) -> bool:
    if not name or name in exclude:
        return False
    if suffix:
        if any(name.endswith(x) for x in exclude):
            return False
        return any(name.endswith(label) for label in labels)
    return name in labels


def _allowed(table: RuleTable, rule: Rule, value: str) -> bool:
    return table.allow.permits(value) or rule.allow.permits(value)


#: A cookie header before a pair on its line: ``Cookie:``, ``Set-Cookie:``,
#: ``"Cookie": "...``, ``document.cookie = "...``, ``curl --cookie ...``.
_COOKIE_HEADER_RE = re.compile(r"(?i)(?<![A-Za-z0-9_])cookie[\"']?[ \t]{0,8}[:=]|--cookie[ \t=]")


def in_cookie_header(text: str, i: int, headers: Sequence[int]) -> bool:
    """Whether one of ``headers`` (cookie-header ends, sorted) opens ``i``'s line before it."""
    k = bisect.bisect_right(headers, i) - 1
    return k >= 0 and _line_end(text, headers[k]) >= i


def _cookie_headers(text: str) -> list[int]:
    return [m.end() for m in _COOKIE_HEADER_RE.finditer(text)]


def _named_hits(
    table: RuleTable, rule: Rule, text: str, pairs: Sequence[_Named], suffix: bool
) -> Iterator[Hit]:
    headers: list[int] | None = None
    for pair in pairs:
        if not _name_matches(pair.name, rule.labels, table.label_exclude, suffix):
            continue
        if pair.name in rule.cookie_only:
            if headers is None:
                headers = _cookie_headers(text)
            if not in_cookie_header(text, pair.start, headers):
                continue
        if _allowed(table, rule, text[pair.start : pair.end]):
            continue
        yield Hit(rule.id, rule.tier, rule.detector, pair.start, pair.end)


class _Anchors:
    """Pair-anchor spans, in text order, for the ``key_id_pair`` window test."""

    def __init__(self, spans: Sequence[tuple[int, int]]) -> None:
        self._spans = spans
        self._ends = [e for _, e in spans]

    def near(self, start: int, end: int, window: int) -> bool:
        """An anchor not overlapping ``[start, end)`` lies within ``window`` of it."""
        i = bisect.bisect_left(self._ends, start - window)
        while i < len(self._spans) and self._spans[i][0] <= end + window:
            a_start, a_end = self._spans[i]
            if a_end <= start or a_start >= end:
                return True
            i += 1
        return False


def _pattern_hits(table: RuleTable, rule: Rule, text: str) -> Iterator[Hit]:
    if rule.pattern is None:
        return
    anchors = None
    if rule.pair_with is not None:
        spans = [m.span() for m in rule.pair_with.pattern.finditer(text)]
        if not spans:
            return
        anchors = _Anchors(spans)
    has_value = "v" in rule.pattern.groupindex
    pos = 0
    while (m := rule.pattern.search(text, pos)) is not None:
        # A rejected match is retried one character on, so a credential that
        # starts inside it (`eyJfoo.<token>`) is still found; a kept one is not
        # rescanned.
        pos = m.start() + 1
        vs, ve = m.span("v") if has_value else m.span()
        if vs < 0 or ve <= vs:
            continue
        value = text[vs:ve]
        if rule.validate is not None and not rule.validate(value):
            continue
        if rule.validate_at is not None and not rule.validate_at(text, vs, ve):
            continue
        if _allowed(table, rule, value):
            continue
        if (
            rule.pair_with is not None
            and anchors is not None
            and not anchors.near(vs, ve, rule.pair_with.window)
        ):
            continue
        pos = max(pos, m.end())
        start, end = (vs, ve) if rule.replace == "value" else m.span()
        yield Hit(rule.id, rule.tier, rule.detector, start, len(text) if rule.through_end else end)


def detect(table: RuleTable, text: str) -> list[Hit]:
    """Every hit every rule makes on ``text``, overlaps unresolved."""
    outer = getattr(_SCAN, "scan", None)
    _SCAN.scan = _Scan(text)
    try:
        return _detect(table, text)
    finally:
        # The scan holds the text: drop it rather than keep it past the call.
        _SCAN.scan = outer


def label_filter(table: RuleTable) -> Callable[[str], bool]:
    """Whether a normalised field name is one some ``labelled`` row of ``table`` reads."""
    label_rules = [r for r in table.rules if r.detector is Detector.LABELLED]
    seen: dict[str, bool] = {}

    def wanted(name: str) -> bool:
        if name not in seen:
            seen[name] = any(
                _name_matches(name, r.labels, table.label_exclude, suffix=True) for r in label_rules
            )
        return seen[name]

    return wanted


def url_head_spans(text: str) -> list[tuple[int, int]]:
    """The URL parts the labelled detector leaves to the URL rules."""
    return _url_spans(text, _URL_HEAD_BODY_RE)


def _detect(table: RuleTable, text: str) -> list[Hit]:
    url_spans = _url_spans(text, _URL_BODY_RE)
    labelled: list[_Named] | None = None
    params: list[_Named] | None = None
    found: list[Hit] = []
    wanted = label_filter(table)

    for rule in table.rules:
        if rule.detector is Detector.LABELLED:
            if labelled is None:
                labelled = label_candidates(text, _Spans(url_head_spans(text)), wanted)
            found.extend(_named_hits(table, rule, text, labelled, suffix=True))
        elif rule.detector is Detector.URL_PARAM:
            if params is None:
                params = url_parameters(text, url_spans)
            found.extend(_named_hits(table, rule, text, params, suffix=False))
        else:
            found.extend(_pattern_hits(table, rule, text))
    return found
