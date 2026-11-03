"""Where a streamed buffer must be held so the rule table reads each value whole.

``StreamRedactor`` commits a chunk's text once nothing in it can still grow into
a credential, and redacts each committed window on its own. Its hold-back was
built on the legacy pass's shapes: a credential is a run of credential-class
characters. The rule table also reads values by the field name before them, and
those values follow other rules: a line-oriented assignment (``KEY=value with
spaces``, an HTTP header) runs to the end of its line, a quoted value to its
closing quote, a ``<password>`` element to its close tag, a private-key block to
its END line. A window that holds the name but not the whole value, or the value
but not the name, redacts differently from the whole text.

:func:`open_values` reads the buffer as the table does and returns every value
whose end has not arrived yet. The stream holds from each one's cut, so the
value reaches one window whole, with its name and enough of the line before the
name for the table to read the same value shape it reads in the whole text: a
name at the start of a line (after indentation, ``export`` or a YAML dash) is a
line-oriented assignment, anywhere else a pair nested in other text.

Only text on the buffer's last line can still be open: no value the table reads
crosses a line, except a private-key block and the ``value`` field of a
``{"name": ..., "value": ...}`` pair, which are looked for over a bounded tail.
The scan is bounded by the buffer, which the stream itself bounds.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from kiro_crew.security.redaction_rules import detectors as d
from kiro_crew.security.redaction_rules.rules import RuleTable

#: How a dropped value ends, per kind, when the stream fails closed on it.
LINE = "table-line"
NESTED = "table-nested"
FLAG = "table-flag"
QUOTE_DOUBLE = "table-quote-double"
QUOTE_SINGLE = "table-quote-single"
XML = "table-xml"
PEM = "table-pem"
#: Not open: a whole pair at the buffer's end, kept from being cut in two.
CLOSED = "table-closed"

#: Value bytes of each kind, for the stream's sticky discard.
DISCARD_RUN_RES: dict[str, re.Pattern[str]] = {
    LINE: re.compile(r"[^\r\n]*"),
    NESTED: re.compile(r"[^\s\"'`,;&)\]}]*"),
    FLAG: re.compile(r"[^\s\"'`]*"),
    QUOTE_DOUBLE: re.compile(r"[^\"\r\n]*"),
    QUOTE_SINGLE: re.compile(r"[^'\r\n]*"),
    XML: re.compile(r"[^<\r\n]*"),
    # Up to the END line, which is kept: it alone is not key material.
    PEM: re.compile(r"(?:(?!-----END )[\s\S])*"),
}
#: Bytes of a private-key discard kept buffered, so an END line split across
#: chunks is seen whole on the next one.
PEM_CARRY = 96

_SHAPE_KIND = {d.LINE: LINE, d.NESTED: NESTED, d.FLAG: FLAG}
_QUOTE_KIND = {'"': QUOTE_DOUBLE, "'": QUOTE_SINGLE}

#: A private-key header and END line, as the table's PEM rows read them.
_PEM_HEADER_RE = re.compile(r"-----BEGIN (?P<k>[A-Z ]{0,60})PRIVATE KEY-----")
#: A value that has not started yet may still be a scheme word and a blank
#: (``Bearer ``); past this many characters with no value, none is coming.
_PENDING_VALUE_MAX = 64
#: A credential field name at the buffer's end whose separator may follow:
#: an optional closing quote and a few blanks.
_KEY_TAIL_RE = re.compile(r"(?:\\[\"']?|[\"'])?[ \t]{0,8}\Z")
#: How far a ``value`` field may follow its ``name`` field (``_VALUE_FIELD_RE``),
#: and how far back a ``name`` field is looked for.
_VALUE_FIELD_REACH = 200
_NAME_FIELD_REACH = 400
_LINE_BREAK = re.compile(r"[\r\n]")
_BLANK = re.compile(r"\s")


@dataclass(frozen=True)
class OpenValue:
    """A value the table reads whose end has not arrived yet.

    ``cut`` is where the stream holds from; ``value_start`` is where the text
    the batch pass replaces starts (the value, after any auth scheme word; an AWS
    field name too, which the batch pass replaces with its value), so a
    fail-closed drop keeps what the batch pass keeps. ``key_start`` is where the
    field name starts. ``strong`` is False for a field name whose separator has
    not arrived: it is held, but never drops data.
    """

    cut: int
    value_start: int
    kind: str
    strong: bool
    key_start: int = -1
    #: For a :data:`CLOSED` pair, where its value ends: a commit must not fall
    #: between ``cut`` and here, or the name and the value reach different windows.
    end: int = -1


_FILTERS: dict[int, tuple[RuleTable, object]] = {}


def _wanted(table: RuleTable):  # type: ignore[no-untyped-def]
    cached = _FILTERS.get(id(table))
    if cached is None or cached[0] is not table:
        cached = (table, d.label_filter(table))
        _FILTERS.clear()
        _FILTERS[id(table)] = cached
    return cached[1]


def _token_param_placeholder(text: str, start: int) -> bool:
    # Lazy, as in `table_active`.
    from kiro_crew.security.redaction_rules import compat

    return compat.is_token_param_placeholder(text, start)


def _last_line_start(text: str) -> int:
    i = max(text.rfind("\n"), text.rfind("\r"))
    return i + 1


def _shape_cut(text: str, key_start: int, heads: list[tuple[int, int]]) -> int:
    """Where to hold from so a window reads the pair at ``key_start`` in its own shape.

    The table decides a pair's shape from the line before its name, looking at
    most ``_LEAD_MAX`` characters back; keeping that much (or back to the line
    start) keeps the decision. A cut is never left inside a URL.
    """
    line_start = max(text.rfind("\n", 0, key_start), text.rfind("\r", 0, key_start)) + 1
    cut = max(line_start, key_start - d._LEAD_MAX - 1)
    for start, end in heads:
        if start < cut < end:
            cut = start
    return cut


def _region_open(text: str, vstart: int, shape: str) -> tuple[bool, str]:
    """Whether a value starting at ``vstart`` on the last line can still change, and its kind."""
    n = len(text)
    if vstart >= n:
        return True, _SHAPE_KIND[shape]
    lead = vstart
    if text[lead] == "\\" and text[lead + 1 : lead + 2] in ('"', "'"):
        lead += 1
    if text[lead] in "\"'":
        q = text[lead]
        region = d._value_region(text, vstart)
        # The region stops at its closing quote, or in front of `\"` for an
        # escaped value; an unclosed one runs to the end of the text.
        closed = region is not None and region[1] < n and text[region[1]] in (q, "\\")
        return (not closed), _QUOTE_KIND[q]
    if shape == d.LINE:
        return True, LINE
    span = d.labelled_value(text, vstart, shape)
    if span is None:
        rest = text[vstart:]
        pending = len(rest) <= _PENDING_VALUE_MAX and not set(rest) & set("[{(")
        return pending, _SHAPE_KIND[shape]
    return span[1] >= n, _SHAPE_KIND[shape]


def _pair_values(text: str, wanted, heads: list[tuple[int, int]]) -> list[OpenValue]:  # type: ignore[no-untyped-def]
    found: list[OpenValue] = []
    urls = d._Spans(heads)
    pos = _last_line_start(text)
    n = len(text)
    while (m := d._KEY_RE.search(text, pos)) is not None:
        pos = m.end()
        name = d.pair_name(text, m.start(), m.group("key"))
        lead_name, entity = d.entity_led_name(text, m.start(), m.group("key"))
        if entity and m.end() == n and d._TOKEN_PARAM_NAME.startswith(lead_name):
            # The name may still grow into `token` behind its escaped separator.
            name = None
        if name is None:
            # A `token` parameter behind an escaped separator is pass 4's, and
            # the table skips it only while its separator is in the same window.
            if not _BLANK.search(text, m.start()):
                found.append(OpenValue(_shape_cut(text, m.start(), heads), n, NESTED, strong=False))
            continue
        if not wanted(name) or urls.contains(m.start()):
            continue
        sep = d._SEP_RE.match(text, m.end())
        if sep is None and m.group("dash"):
            sep = d._FLAG_SEP_RE.match(text, m.end())
        cut = _shape_cut(text, m.start(), heads)
        if sep is None:
            if _KEY_TAIL_RE.match(text, m.end()):
                found.append(OpenValue(cut, n, NESTED, strong=False))
            continue
        if sep.end() == n and not text[m.end() : n].strip(" \t\"'\\"):
            # Only the blanks or quote before a separator so far.
            found.append(OpenValue(cut, n, NESTED, strong=False))
            continue
        pos = sep.end()
        shape = d._key_shape(text, m.start(), bool(m.group("dash")), name)
        is_open, kind = _region_open(text, sep.end(), shape)
        if is_open and _token_param_placeholder(text, sep.end()):
            # Pass 4's, held by the stream's own `token=` anchor, as the batch defers it.
            continue
        if is_open:
            start = _replaced_start(text, sep.end(), shape)
            found.append(OpenValue(cut, start, kind, strong=True, key_start=m.start()))
        else:
            end = _closed_end(text, sep.end(), shape)
            if end is not None and name == d._AUTHORIZATION:
                held = _authorization_hold(text, sep.end(), shape, cut, end)
                if held is not None:
                    found.append(held)
                    continue
            if end is not None:
                found.append(OpenValue(cut, end, CLOSED, False, m.start(), end))
    return found


def _authorization_hold(text: str, vstart: int, shape: str, cut: int, end: int) -> OpenValue | None:
    """A scheme-less ``authorization`` value is prose when a word follows it on its line.

    Until that word or the line's end arrives, the pair is held (weakly); once
    the word is in, the name, value and the word's first character reach one
    window together, so the window reads it as the whole text does.
    """
    span = d.labelled_value(text, vstart, shape)
    if span is None or not d.is_authorization_prose(text + "x", d._AUTHORIZATION, vstart, span):
        return None
    n = len(text)
    rest = text[span[1] : n]
    if _LINE_BREAK.search(rest):
        return None
    if not rest.strip():
        return OpenValue(cut, n, NESTED, strong=False)
    word = span[1] + len(rest) - len(rest.lstrip())
    return OpenValue(cut, word + 1, CLOSED, False, cut, word + 1)


def _closed_end(text: str, vstart: int, shape: str) -> int | None:
    """Where a closed value read from ``vstart`` ends, its closing quote included.

    A window that ends inside an escaped closing quote (``\\"``) would read the
    backslash as part of the value.
    """
    span = d.labelled_value(text, vstart, shape)
    if span is None:
        return None
    end = span[1]
    if text[end : end + 2] in ('\\"', "\\'"):
        return end + 2
    return end + 1 if text[end : end + 1] in ('"', "'") else end


def _replaced_start(text: str, vstart: int, shape: str) -> int:
    """Where the batch pass's replacement of the value read from ``vstart`` starts."""
    # Lazy: `compat` imports `security.redaction`.
    from kiro_crew.security.redaction_rules import compat

    span = d.labelled_value(text, vstart, shape)
    if span is not None:
        start = span[0]
    else:
        region = d._value_region(text, vstart)
        start = region[0] if region is not None else vstart
    aws = compat._aws_label(text, start)
    return start - len(aws[1]) if aws is not None else start


def _xml_values(text: str, wanted) -> list[OpenValue]:  # type: ignore[no-untyped-def]
    found: list[OpenValue] = []
    pos = _last_line_start(text)
    while (m := d._XML_OPEN_RE.search(text, pos)) is not None:
        pos = m.start() + 1
        if not wanted(d.normalise_name(m.group("key"))):
            continue
        if f"</{m.group('key')}" not in text[m.end() :]:
            found.append(OpenValue(m.start(), m.end(), XML, strong=True))
    return found


def _name_value_pairs(text: str, wanted) -> list[OpenValue]:  # type: ignore[no-untyped-def]
    found: list[OpenValue] = []
    n = len(text)
    for m in d._NAME_FIELD_RE.finditer(text, max(0, n - _NAME_FIELD_REACH)):
        if not wanted(d.normalise_name(m.group("name"))):
            continue
        value = d._VALUE_FIELD_RE.match(text, m.end())
        if value is None:
            # The `value` field may still follow within its reach.
            if n - m.end() <= _VALUE_FIELD_REACH:
                found.append(OpenValue(m.start(), n, NESTED, strong=False))
            continue
        if _LINE_BREAK.search(text, value.end()):
            continue
        is_open, kind = _region_open(text, value.end(), d.NESTED)
        if is_open:
            found.append(OpenValue(m.start(), value.end(), kind, strong=True))
    return found


def _private_key(text: str) -> list[OpenValue]:
    """Each whole private-key block, and the first header no END line follows yet."""
    found: list[OpenValue] = []
    for m in _PEM_HEADER_RE.finditer(text):
        end_line = f"-----END {m.group('k')}PRIVATE KEY-----"
        at = text.find(end_line, m.end())
        if at == -1:
            found.append(OpenValue(m.start(), m.end(), PEM, strong=True))
            break
        end = at + len(end_line)
        found.append(OpenValue(m.start(), end, CLOSED, False, m.start(), end))
    return found


#: An element's open tag still arriving (`<`, `<passw`, `<password attr="x`).
_XML_PARTIAL_RE = re.compile(r"<(?:[A-Za-z_][A-Za-z0-9_.\-]{0,63}(?:[ \t][^<>\r\n]{0,500})?)?\Z")
#: A ``name``/``key`` field whose value (the label of a name/value pair) is
#: still arriving.
_NAME_FIELD_TAIL_RE = re.compile(
    r"(?<![A-Za-z0-9_\-])[\"']?(?:name|key)[\"']?[ \t]{0,8}[:=][ \t]{0,8}"
    r"[\"']?[A-Za-z0-9_.\-]{0,64}[\"']?\Z"
)
#: A character reference still arriving, or complete with no name after it yet
#: (``&``, ``&Am``, ``&Amp;``, ``&#38;``): the table reads a name after one as a
#: query parameter (``detectors.pair_name``), so it reaches the name's window.
_ENTITY_TAIL_RE = re.compile(
    r"&(?:#[0-9A-Fa-fXx]{0,16};?|[A-Za-z]{0,8};?)(?:&(?:#[0-9A-Fa-fXx]{0,16};?|[A-Za-z]{0,8};?))*\Z"
)
_TAIL_REACH = 600


def _partial_heads(text: str) -> list[OpenValue]:
    """Weak holds for an element tag or a ``name`` field cut off at the buffer's end."""
    n = len(text)
    lo = max(0, n - _TAIL_REACH)
    found = []
    for pattern in (_XML_PARTIAL_RE, _NAME_FIELD_TAIL_RE, _ENTITY_TAIL_RE):
        m = pattern.search(text, lo)
        if m is not None:
            found.append(OpenValue(m.start(), n, NESTED, strong=False))
    return found


# ── The stream's side ──
#
# A committed window starts wherever the previous commit stopped, often mid-line.
# A name at the window's start would then read as the start of a line (a
# line-oriented assignment) when in the whole text it sits after other text on
# its line (a nested pair), and the two read different values. So the stream
# keeps the raw text it committed since the last line break (its "line
# context"), and when that context is not line-start lead (indentation,
# `export`, a YAML dash) it reads each window with one character in front that
# nothing redacts and every look-behind reads as a start of text: `|`.

#: The line context kept: one more than the table looks back, so a longer
#: context still reads as "not a line start".
CONTEXT_MAX = d._LEAD_MAX + 2
NOT_A_LINE_START = "|"


def window_prefix(context: str) -> str:
    """``""`` when ``context`` reads as a line's lead, else :data:`NOT_A_LINE_START`."""
    if len(context) <= d._LEAD_MAX and d._LINE_LEAD_RE.fullmatch(context):
        return ""
    return NOT_A_LINE_START


def line_context(context: str, committed: str) -> str:
    """The line context after ``committed`` is emitted following ``context``."""
    joined = context + committed
    return joined[joined.rfind("\n") + 1 :][-CONTEXT_MAX:]


def table_active() -> RuleTable | None:
    """The table, when ``compat.use_rule_table()`` routes the credential pass to it."""
    # Lazy: `compat` imports `security.redaction`, which the stream module sits beside.
    from kiro_crew.security.redaction_rules import compat

    if not compat.use_rule_table():
        return None
    try:
        return compat._table()
    except Exception:
        # The batch pass fails closed on the same error; nothing to hold for.
        return None


def buffer_open_values(table: RuleTable, context: str, buf: str) -> list[OpenValue]:
    """:func:`open_values` of a stream buffer read after its line context, in ``buf`` offsets."""
    pre = window_prefix(context)
    p = len(pre)
    return [
        OpenValue(
            max(0, v.cut - p),
            max(0, v.value_start - p),
            v.kind,
            v.strong,
            v.key_start - p if v.key_start >= 0 else -1,
            v.end - p if v.end >= 0 else -1,
        )
        for v in open_values(table, pre + buf)
    ]


def open_values(table: RuleTable, text: str) -> list[OpenValue]:
    """Every value in ``text`` the table reads whose end has not arrived, by cut."""
    wanted = _wanted(table)
    heads = d.url_head_spans(text)
    found = [
        *_pair_values(text, wanted, heads),
        *_xml_values(text, wanted),
        *_name_value_pairs(text, wanted),
        *_private_key(text),
        *_partial_heads(text),
    ]
    return sorted(found, key=lambda v: (v.cut, not v.strong))


# ── StreamRedactor glue ──


@dataclass(frozen=True)
class BufferRead:
    """What the table reads in a stream buffer: its open values and whole pairs."""

    #: Values whose end has not arrived (``kind != CLOSED``), by cut.
    open: tuple[OpenValue, ...] = ()
    #: Whole pairs near the buffer's end, which a commit must not split.
    pairs: tuple[OpenValue, ...] = ()

    @property
    def strong(self) -> tuple[OpenValue, ...]:
        """Open values with a separator: they may fail closed."""
        return tuple(v for v in self.open if v.strong)

    def keep_pairs(self, i: int) -> int:
        """Move a commit at ``i`` back so no whole pair is split from its name."""
        for v in self.pairs:
            if v.cut < i < v.end:
                i = v.cut
        return i

    def floor_past_pairs(self, i: int) -> int:
        """Move a forced floor cut at ``i`` past any whole pair it would split.

        The pair is complete, so committing all of it keeps the bound and gives
        the window the pair's name and its separator, as the whole text has them.
        """
        for v in self.pairs:
            if v.cut < i < v.end:
                i = v.end
        return i

    def drop_start(self, base_cuts: list[int], table_only: bool) -> int:
        """Where a fail-closed drop starts when a table value is open.

        A table value's cut keeps its line lead, which is not secret: the drop
        starts where the value does (a private-key block at its header), keeping
        the name as the batch pass does, or where a legacy carrier starts. A
        legacy carrier cut at a field name the table also reads keeps that name.
        """
        starts = [v.cut if v.kind == PEM else v.value_start for v in self.strong]
        i = min(base_cuts + (starts if table_only else []))
        if not table_only:
            for v in self.strong:
                if v.key_start == i < v.value_start:
                    return v.value_start
        return i


_NOTHING = BufferRead()


def read_buffer(context: str, buf: str) -> BufferRead:
    """The table's :class:`BufferRead` of ``buf``; empty with the setting off."""
    table = table_active()
    if table is None:
        return _NOTHING
    read = buffer_open_values(table, context, buf)
    return BufferRead(
        tuple(v for v in read if v.kind != CLOSED), tuple(v for v in read if v.kind == CLOSED)
    )


def redact_window(redact: Callable[[str], str], context: str, text: str) -> str:
    """``redact(text)`` for a window emitted after ``context`` on its line.

    With the setting on, a window that starts mid-line is read after
    :data:`NOT_A_LINE_START`, so a name at its start keeps the value shape it
    has in the whole text.
    """
    pre = window_prefix(context) if table_active() is not None else ""
    if pre:
        out = redact(pre + text)
        if out.startswith(pre):
            return out[len(pre) :]
    return redact(text)


def discard_run_res(legacy: dict[str, re.Pattern[str]]) -> dict[str, re.Pattern[str]]:
    """The stream's discard-run regexes with the table's kinds added."""
    return {**legacy, **DISCARD_RUN_RES}


def discard_carry(kinds: tuple[str, ...], carry: int) -> int:
    """How much of a discard to keep buffered: a private-key END line may be split."""
    return max(carry, PEM_CARRY) if PEM in kinds else carry
