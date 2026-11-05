"""kiro-cli ``toolsSettings.shell.allowedCommands`` entries, read and matched safely.

kiro-cli compiles each entry with Rust's ``regex`` crate, anchored at both ends, and
runs a command one matches without a prompt. Crew answers the same grant at its own
gate on KAS, and must neither grant more than kiro-cli would nor let a pattern stall
the gateway. Python's ``re`` does neither safely: it reads some Rust syntax
differently (a POSIX class such as ``[[:alpha:]]``) and backtracks without bound
on nested repetition.

So Crew reads only the syntax whose meaning is the same in both engines, with its
own parser, and matches it with its own automaton, never with ``re``:

- literal characters, and a backslash-escaped punctuation character as a literal
  (in an entry using any syntax below, only ASCII punctuation other than ``<`` /
  ``>``, which Rust reads as word boundaries; a literal-plus-``.*`` entry keeps
  the reading it always had);
- ``.`` (any character);
- a bracket class: ``[abc]``, ranges such as ``[A-Za-z0-9_./-]``, negation
  ``[^;|&]``, escaped punctuation inside it;
- groups ``( )`` and ``(?: )``, alternation ``|``, and the repeats ``*``, ``+``
  and ``?``;
- optional ``^`` / ``\\A`` at the start and ``$`` / ``\\z`` at the end, read as the
  anchoring kiro-cli adds anyway.

Everything else is refused (``None``) and its commands keep prompting: a POSIX or
nested class, a class operator (``&&``, ``--``, ``~~``), a ``]`` first in a class,
a ``-`` that is neither first, last nor a range, an alphanumeric escape (``\\d``,
``\\w``, ``\\b``), a counted repeat ``{n,m}``, a lazy or doubled repeat, a flag or
named group ``(?``, and ``^`` / ``$`` anywhere but the two ends. A whole entry is
matched against the whole command, so a top-level ``a|b`` grants exactly ``a`` or
``b``, never the wider prefix-or-suffix reading the Rust anchoring would give it.

Matching is a Thompson automaton walked one character at a time: linear in the
command's length times the pattern's size, with a hard step budget on top, so no
pattern can stall the gateway. A literal-plus-``.*`` entry (the shape kiro-cli's
own documentation shows: ``git status``, ``npm run .*``) keeps a faster direct match.

``parse(raw, for_deny=True)`` reads a ``deniedCommands`` entry, where reading MORE
only refuses more, and also accepts (never for a grant):

- ``\\b`` and ``\\B``, zero-width word-boundary assertions (a word character is
  ``ch.isalnum() or ch == "_"``, Unicode-aware like Rust's default), checked in the
  automaton's closure against the characters either side of the position;
- one ``(?i)`` right at the start (after an optional ``^`` / ``\\A``): the entry and
  the command are both ``str.casefold()``-ed. A literal that folds to more than one
  character, a non-ASCII range, and an ASCII range that holds cased letters but is
  not ``A-Z``-style uppercase on both ends are refused.

A deny entry with ``\\<`` or ``\\>`` is refused even in the literal-plus-``.*``
shape, so it never reads as literal brackets that match nothing.

:func:`match_within` tells a deny caller "matched", "not matched" and "budget spent"
apart.

A LEAF on purpose: stdlib only, so both the KAS projection and the gate import it.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Characters that make a regex more than a literal outside a class.
_REGEX_METACHARACTERS = frozenset(".^$*+?()[]{}|\\")

#: Bound on one entry, so the record a session carries stays small.
MAX_PATTERN_LENGTH = 1024

#: Characters that make a command more than one plain command: chaining, pipes,
#: redirection and substitution. A command holding any of them, quoted or not, is
#: never granted by an entry, however wide, so a ``git status .*`` grant cannot
#: carry ``git status; <anything>``.
UNGRANTABLE_COMMAND_CHARS = frozenset(";&|<>$`\n\r")

#: Grouping and brace characters. A command holding one OUTSIDE a quoted argument
#: is never granted (a subshell, a group, a brace expansion); inside a single- or
#: double-quoted argument they are plain text to every shell, so
#: ``git commit -m "fix(scope): x"`` can be granted. See :func:`plain_command`.
QUOTED_ONLY_COMMAND_CHARS = frozenset("(){}")

#: Commands longer than this are not matched against an entry at all.
MAX_COMMAND_LENGTH = 4096

#: Deepest group nesting an entry may have.
_MAX_GROUP_DEPTH = 32

#: Automaton states one match may visit before it gives up and grants nothing.
_MAX_MATCH_STEPS = 1_000_000

#: One character test: (negated, single characters, inclusive ranges).
_CharSet = tuple[bool, frozenset[str], tuple[tuple[str, str], ...]]

_ANY: _CharSet = (True, frozenset("\n"), ())


@dataclass(frozen=True)
class Pattern:
    """One accepted entry, ready to match.

    ``segments`` is set for a literal-plus-``.*`` entry: its literal pieces between
    the wildcards (``("git status",)`` is exact, ``("npm run ", "")`` is
    ``npm run .*``). ``program`` is set for every other accepted entry: the
    automaton :func:`matches` walks. ``fold_case`` is set only for a deny entry
    with a leading ``(?i)``: the command is case-folded before matching.
    """

    segments: tuple[str, ...] | None = None
    program: tuple[tuple, ...] | None = None
    start: int = 0
    fold_case: bool = False


def parse(raw: object, *, for_deny: bool = False) -> Pattern | None:
    """*raw* read as an entry Crew can match like kiro-cli, or ``None``.

    *for_deny* also accepts ``\\b``, ``\\B`` and a leading ``(?i)`` (module
    docstring); only a ``deniedCommands`` caller may set it, since reading more
    syntax must never widen a grant.
    """
    if not isinstance(raw, str):
        return None
    # Read verbatim, as kiro-cli reads it: no stripping, and no character a reader
    # could not see (control characters, any whitespace but the plain space).
    body = raw
    if not body or len(body) > MAX_PATTERN_LENGTH or not _plain_text(body):
        return None
    for prefix in ("\\A", "^"):
        if body.startswith(prefix):
            body = body[len(prefix) :]
            break
    fold_case = for_deny and body.startswith("(?i)")
    if fold_case:
        body = body[len("(?i)") :]
    for suffix in ("\\z", "$"):
        if body.endswith(suffix) and not body.endswith("\\" + suffix):
            body = body[: -len(suffix)]
            break
    segments = _literal_segments(body, for_deny=for_deny)
    if segments is not None:
        if not any(segments) and len(segments) == 1:
            return None
        if fold_case:
            segments = tuple(seg.casefold() for seg in segments)
        return Pattern(segments=segments, fold_case=fold_case)
    try:
        tree = _Parser(body, for_deny=for_deny, fold_case=fold_case).parse()
    except _Refused:
        return None
    program, start = _compile(tree)
    return Pattern(program=program, start=start, fold_case=fold_case)


def _literal_segments(body: str, *, for_deny: bool = False) -> tuple[str, ...] | None:
    """*body*'s literal pieces between ``.*`` wildcards, or ``None`` when it holds
    any other regex syntax."""
    segments: list[str] = []
    current: list[str] = []
    i = 0
    while i < len(body):
        ch = body[i]
        if body.startswith(".*", i):
            segments.append("".join(current))
            current = []
            i += 2
        elif ch == "\\":
            nxt = body[i + 1] if i + 1 < len(body) else ""
            if not nxt or nxt.isalnum() or nxt.isspace() or (for_deny and nxt in "<>"):
                # A deny reads ``\\<`` / ``\\>`` as Rust does, a word boundary:
                # refused below, never a literal that matches nothing.
                return None
            current.append(nxt)
            i += 2
        elif ch in _REGEX_METACHARACTERS:
            return None
        else:
            current.append(ch)
            i += 1
    segments.append("".join(current))
    return tuple(segments)


class _Refused(Exception):
    """The entry holds syntax outside what Crew reads like kiro-cli."""


class _Parser:
    """Recursive descent over one entry's body (anchors already removed).

    Produces a tree of tuples: ``("set", charset)``, ``("cat", [..])``,
    ``("alt", [..])``, ``("star" | "plus" | "opt", node)``, and, with *for_deny*
    only, ``("assert", at_boundary)`` for ``\\b`` (``True``) / ``\\B``. Raises
    :class:`_Refused` on anything outside the accepted syntax.
    """

    def __init__(self, text: str, *, for_deny: bool = False, fold_case: bool = False) -> None:
        self.text = text
        self.pos = 0
        self.depth = 0
        self.for_deny = for_deny
        self.fold_case = fold_case

    def _fold(self, ch: str) -> str:
        """*ch* case-folded under ``(?i)``; refused when it folds to several."""
        if not self.fold_case:
            return ch
        folded = ch.casefold()
        if len(folded) != 1:
            raise _Refused
        return folded

    def parse(self) -> tuple:
        node = self._alternation()
        if self.pos != len(self.text):
            raise _Refused  # an unmatched ``)``
        return node

    def _peek(self) -> str:
        return self.text[self.pos] if self.pos < len(self.text) else ""

    def _alternation(self) -> tuple:
        branches = [self._concat()]
        while self._peek() == "|":
            self.pos += 1
            branches.append(self._concat())
        return branches[0] if len(branches) == 1 else ("alt", branches)

    def _concat(self) -> tuple:
        items: list[tuple] = []
        while self.pos < len(self.text) and self._peek() not in "|)":
            items.append(self._repeat())
        return ("cat", items)

    def _repeat(self) -> tuple:
        if self._peek() in ("*", "+", "?"):
            raise _Refused  # nothing to repeat
        atom = self._atom()
        quant = self._peek()
        if quant in ("*", "+", "?"):
            if atom[0] == "assert":
                raise _Refused  # a repeated zero-width assertion
            self.pos += 1
            if self._peek() in ("*", "+", "?", "{"):
                raise _Refused  # lazy (``*?``) or doubled repeat
            return ({"*": "star", "+": "plus", "?": "opt"}[quant], atom)
        return atom

    def _atom(self) -> tuple:
        ch = self._peek()
        if ch == "(":
            self.pos += 1
            if self.text.startswith("?:", self.pos):
                self.pos += 2
            elif self._peek() == "?":
                raise _Refused  # a flag, a named group, a look-around
            self.depth += 1
            if self.depth > _MAX_GROUP_DEPTH:
                raise _Refused
            inner = self._alternation()
            if self._peek() != ")":
                raise _Refused  # unclosed
            self.pos += 1
            self.depth -= 1
            return inner
        if ch == "[":
            self.pos += 1
            return ("set", self._class())
        if ch == ".":
            self.pos += 1
            return ("set", _ANY)
        if ch == "\\":
            nxt = self.text[self.pos + 1 : self.pos + 2]
            if self.for_deny and nxt in ("b", "B"):
                self.pos += 2
                return ("assert", nxt == "b")
            return ("set", (False, frozenset(self._escape()), ()))
        if ch in "^${}]":
            raise _Refused  # an anchor mid-pattern, a counted repeat, a stray ``]``
        self.pos += 1
        return ("set", (False, frozenset(self._fold(ch)), ()))

    def _escape(self) -> str:
        """The literal a ``\\`` + ASCII punctuation at :attr:`pos` names.

        Rust escapes only ASCII punctuation to a literal, and reads ``\\<`` /
        ``\\>`` as word boundaries; every other escape (``\\d``, ``\\b``,
        ``\\x41``, a non-ASCII character, a trailing ``\\``) is refused.
        """
        nxt = self.text[self.pos + 1] if self.pos + 1 < len(self.text) else ""
        if not nxt.isascii() or not nxt.isprintable() or nxt.isalnum() or nxt in " <>":
            raise _Refused
        self.pos += 2
        return nxt

    def _class(self) -> _CharSet:
        negated = False
        if self._peek() == "^":
            negated = True
            self.pos += 1
        first = self.pos
        chars: set[str] = set()
        ranges: list[tuple[str, str]] = []
        while True:
            ch = self._peek()
            if not ch:
                raise _Refused  # unclosed
            if ch == "]":
                if self.pos == first:
                    raise _Refused  # ``[]`` or ``[]a]``: Rust reads the ``]`` literally
                self.pos += 1
                break
            if ch == "[" or self.text.startswith(("&&", "--", "~~"), self.pos):
                raise _Refused  # nested / POSIX class, or a class operator
            if ch == "-":
                # Literal only first or last, where both engines agree.
                if self.pos != first and self.text[self.pos + 1 : self.pos + 2] != "]":
                    raise _Refused
                self.pos += 1
                chars.add("-")
                continue
            lo = self._class_char()
            if self._peek() == "-" and self.text[self.pos + 1 : self.pos + 2] not in ("]", ""):
                self.pos += 1
                if self._peek() in ("[", "]", "-"):
                    raise _Refused
                hi = self._class_char()
                if hi < lo:
                    raise _Refused
                ranges.append(self._fold_range(lo, hi))
            else:
                chars.add(self._fold(lo))
        return (negated, frozenset(chars), tuple(ranges))

    def _fold_range(self, lo: str, hi: str) -> tuple[str, str]:
        """``lo-hi`` under ``(?i)``: an ASCII range folding to itself (``a-z``,
        ``0-9``) or one of uppercase letters only (``A-Z`` to ``a-z``); any other
        would fold to a set that is not one range, so it is refused."""
        if not self.fold_case:
            return (lo, hi)
        if not (lo.isascii() and hi.isascii()):
            raise _Refused
        if "A" <= lo <= hi <= "Z":
            return (lo.casefold(), hi.casefold())
        if any(chr(c).casefold() != chr(c) for c in range(ord(lo), ord(hi) + 1)):
            raise _Refused
        return (lo, hi)

    def _class_char(self) -> str:
        ch = self._peek()
        if ch == "\\":
            return self._escape()
        self.pos += 1
        return ch


def _compile(tree: tuple) -> tuple[tuple[tuple, ...], int]:
    """*tree* as a Thompson program and its start state.

    States: ``("match",)``, ``("set", charset, next)``, ``("split", a, b)``, and
    ``("assert", at_boundary, next)`` (deny entries only).
    """
    states: list[tuple] = [("match",)]

    def add(state: tuple) -> int:
        states.append(state)
        return len(states) - 1

    def emit(node: tuple, out: int) -> int:
        kind = node[0]
        if kind in ("set", "assert"):
            return add((kind, node[1], out))
        if kind == "cat":
            for child in reversed(node[1]):
                out = emit(child, out)
            return out
        if kind == "alt":
            entries = [emit(child, out) for child in node[1]]
            entry = entries[-1]
            for other in reversed(entries[:-1]):
                entry = add(("split", other, entry))
            return entry
        if kind == "opt":
            return add(("split", emit(node[1], out), out))
        # star / plus: a loop through one split state, patched once the body exists.
        loop = add(("split", -1, out))
        body = emit(node[1], loop)
        states[loop] = ("split", body, out)
        return loop if kind == "star" else body

    start = emit(tree, 0)
    return tuple(states), start


def _plain_text(text: str) -> bool:
    """Every character printable, and the plain space the only whitespace."""
    return all(ch == " " or (ch.isprintable() and not ch.isspace()) for ch in text)


def plain_command(command: object) -> bool:
    """Whether *command*, exactly as the host recovered it, may be granted at all.

    Not empty, at most :data:`MAX_COMMAND_LENGTH`, none of
    :data:`UNGRANTABLE_COMMAND_CHARS` anywhere, none of
    :data:`QUOTED_ONLY_COMMAND_CHARS` outside a quoted argument
    (:func:`_grouping_only_quoted`), and no control character or whitespace but
    the plain space: a non-breaking space or a tab names a different path to the
    shell while looking the same, so a grant for ``rm scratch`` never covers
    ``rm scratch`` plus an invisible character. Never stripped or rewritten: the
    command matched is the command that runs.
    """
    return (
        isinstance(command, str)
        and bool(command)
        and len(command) <= MAX_COMMAND_LENGTH
        and not UNGRANTABLE_COMMAND_CHARS.intersection(command)
        and _plain_text(command)
        and _grouping_only_quoted(command)
    )


#: What the person is told when an ``allowedCommands`` entry would match a command
#: but the command's shell composition keeps it from being granted.
COMPOSITION_NOTICE = (
    "This command matches allowedCommands, but commands with |, >, <, &&, ;, $() "
    "or backticks always ask. Run the script alone, or move the pipeline into the script."
)

#: Characters that end the leading simple command of a composed one.
_COMPOSITION_BREAK_CHARS = UNGRANTABLE_COMMAND_CHARS | QUOTED_ONLY_COMMAND_CHARS


def composition_blocks_match(raw_patterns: object, command: object) -> bool:
    """Whether *command* is refused a grant only because of its shell composition.

    True when *command* is not :func:`plain_command` because it chains, pipes,
    redirects, substitutes or groups, and one of *raw_patterns* matches either the
    whole command or its leading simple command (the text before the first such
    character, without trailing spaces). Used only to EXPLAIN a prompt: it never
    grants, and a command it returns True for still asks.
    """
    if not isinstance(command, str) or not command or len(command) > MAX_COMMAND_LENGTH:
        return False
    if plain_command(command) or not _COMPOSITION_BREAK_CHARS.intersection(command):
        return False
    cut = min(command.index(ch) for ch in _COMPOSITION_BREAK_CHARS if ch in command)
    leading = command[:cut].rstrip(" ")
    candidates = [leading] if leading and _plain_text(leading) else []
    if _plain_text(command):
        candidates.append(command)
    return any(matches_any(raw_patterns, text) for text in candidates)


def _grouping_only_quoted(command: str) -> bool:
    """Whether every ``( ) { }`` of *command* sits inside a closed quoted argument.

    A command without one passes, as before. With one, the command must be ASCII
    (PowerShell also reads the typographic quotes U+2018 to U+201E as quotes, so
    one could close a string early) and hold no backslash (a ``\\"`` is a quote to
    one shell and a literal to another), every quote must close, and each such
    character must fall between single quotes or between double quotes. Read the
    same way by POSIX shells, zsh and PowerShell; every character that could still
    act inside double quotes (``$``, a backtick) is already refused by
    :data:`UNGRANTABLE_COMMAND_CHARS`.
    """
    if not QUOTED_ONLY_COMMAND_CHARS.intersection(command):
        return True
    if not command.isascii() or "\\" in command:
        return False
    quote = ""
    for ch in command:
        if quote:
            if ch == quote:
                quote = ""
        elif ch in ("'", '"'):
            quote = ch
        elif ch in QUOTED_ONLY_COMMAND_CHARS:
            return False
    return not quote


def matches(pattern: Pattern, command: str) -> bool:
    """Whether *command* is the whole of what *pattern* describes.

    A literal-plus-``.*`` entry is matched directly; any other walks its automaton,
    which gives up (no match, so nothing is granted) past :data:`_MAX_MATCH_STEPS`.
    """
    return _match(pattern, command, [_MAX_MATCH_STEPS])


def matches_any(raw_patterns: object, command: str) -> bool:
    """Whether one of *raw_patterns*, each read by :func:`parse`, matches *command*
    whole. Entries :func:`parse` refuses match nothing. Every automaton walk draws
    on ONE budget of :data:`_MAX_MATCH_STEPS`, so a long list of costly entries
    costs no more than one; once it is spent, the rest match nothing."""
    budget = [_MAX_MATCH_STEPS]
    for raw in raw_patterns if isinstance(raw_patterns, (list, tuple)) else ():
        parsed = parse(raw)
        if parsed is not None and _match(parsed, command, budget):
            return True
    return False


def _match(pattern: Pattern, command: str, budget: list[int]) -> bool:
    return match_within(pattern, command, budget) is True


def match_within(pattern: Pattern, command: str, budget: list[int]) -> bool | None:
    """Whether *pattern* matches the whole of *command*: ``True`` / ``False``, or
    ``None`` once *budget* (one-element list, decremented in place and shared by
    every call the caller makes with it) is spent. For a deny caller, which must
    refuse rather than read a spent budget as "no match"."""
    if pattern.fold_case:
        command = command.casefold()
    if pattern.segments is not None:
        return _segments_match(pattern.segments, command)
    assert pattern.program is not None
    return _walk(pattern.program, pattern.start, command, budget)


def _segments_match(segments: tuple[str, ...], command: str) -> bool:
    """Linear in the command's length times the segment count: the first segment is
    a prefix, the last a suffix, and each middle one is found left to right after
    the previous, which is exactly what a greedy ``.*`` between literals accepts."""
    if len(segments) == 1:
        return command == segments[0]
    first, *middle, last = segments
    if not command.startswith(first) or len(command) < len(first) + len(last):
        return False
    if not command.endswith(last):
        return False
    pos = len(first)
    end = len(command) - len(last)
    for seg in middle:
        found = command.find(seg, pos, end)
        if found < 0:
            return False
        pos = found + len(seg)
    return True


def _in_set(charset: _CharSet, ch: str) -> bool:
    negated, chars, ranges = charset
    inside = ch in chars or any(lo <= ch <= hi for lo, hi in ranges)
    return inside != negated


def _is_word(text: str, pos: int) -> bool:
    return 0 <= pos < len(text) and (text[pos].isalnum() or text[pos] == "_")


def _walk(program: tuple[tuple, ...], start: int, command: str, budget: list[int]) -> bool | None:
    """Walk *program* over *command*: whether it matches, or ``None`` once *budget*
    (shared, decremented in place) runs out; :func:`matches` reads that as no
    match, so a too-costly match grants nothing. Every state visited costs one
    step, an assertion included."""

    def closure(seeds: list[int], pos: int) -> set[int] | None:
        boundary = _is_word(command, pos - 1) != _is_word(command, pos)
        seen: set[int] = set()
        stack = list(seeds)
        while stack:
            state = stack.pop()
            if state in seen:
                continue
            budget[0] -= 1
            if budget[0] < 0:
                return None
            seen.add(state)
            node = program[state]
            if node[0] == "split":
                stack.append(node[2])
                stack.append(node[1])
            elif node[0] == "assert" and node[1] == boundary:
                stack.append(node[2])
        return seen

    current = closure([start], 0)
    for pos, ch in enumerate(command):
        if current is None:
            return None
        if not current:
            return False
        step: list[int] = []
        for state in current:
            node = program[state]
            if node[0] != "set":
                continue
            # A class test costs one step per range it compares, so a wide class
            # draws on the budget as hard as many states would.
            budget[0] -= 1 + len(node[1][2])
            if budget[0] < 0:
                return None
            if _in_set(node[1], ch):
                step.append(node[2])
        current = closure(step, pos + 1)
    return None if current is None else 0 in current
