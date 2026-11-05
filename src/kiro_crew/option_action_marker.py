"""``[OPTION-ACTIONS: close=<label>]``, the dashboard's zero-turn action chip.

Every other surface has nothing to draw, so each ``[OPTIONS:]`` strip removes this
sibling first. The decisions mirror the dashboard's web grammar.
"""

from __future__ import annotations

import bisect
import re

from kiro_crew.constants import (
    _MARKER_BRACKETS,
    _MARKER_CLOSE_CLASS,
    _MARKER_STRAY_TIC,
    _RAW_OPTIONS_RE_LINE,
    MARKER_CLOSERS,
    MARKER_OPENERS,
    _FenceWalk,
    _in_open_fence,
    _marker_body,
    _marker_labels_have_unmatched_opener,
)

_ANY_MARKER_HEAD = r"(?i:OPTIONS?:|OPTION-ACTIONS:)"
_ACTION_BODY_LINE = _marker_body(rf"(?!{_ANY_MARKER_HEAD})", ordinary=rf"[^{_MARKER_BRACKETS}\n]")
_RAW_OPTION_ACTIONS_RE = re.compile(
    rf"\[(?i:OPTION-ACTIONS:)(?P<labels>{_ACTION_BODY_LINE}){_MARKER_CLOSE_CLASS}"
    rf"{_MARKER_STRAY_TIC}[ \t]*(?:$|(?=\[{_ANY_MARKER_HEAD}))",
    re.MULTILINE,
)
_OPTION_ACTIONS_OPEN_RE = re.compile(r"\[(?i:OPTION-ACTIONS)")
_WIDGET_SPAN_RE = re.compile(
    r"<mcwidget\b[^>]*>.*?(?:</mcwidget\s*>|\Z)", re.IGNORECASE | re.DOTALL
)


def in_verbatim_region(text: str, idx: int) -> bool:
    """Whether *idx* sits in a code fence or ``<mcwidget>``, which render as written."""
    if _in_open_fence(text, idx):
        return True
    return any(m.start() <= idx < m.end() for m in _WIDGET_SPAN_RE.finditer(text, 0, idx + 1))


def unfinished_option_action_start(text: str) -> int:
    """Start of a still-arriving ``[OPTION-ACTIONS`` tail outside verbatim text, else ``-1``."""
    # Only the last head can still be arriving: a body never crosses a later head.
    head = None
    for head in _OPTION_ACTIONS_OPEN_RE.finditer(text, max(0, text.rfind("\n") + 1)):
        pass
    if head is None or not (head.end() == len(text) or text.startswith(":", head.end())):
        return -1
    if _action_head_closes(text, head.end()):
        return -1
    return -1 if in_verbatim_region(text, head.start()) else head.start()


def _action_head_closes(text: str, pos: int) -> bool:
    """Whether a closer at the head's own depth follows *pos*, as the ``[OPTIONS`` probe judges it."""
    stack: list[str] = []
    for i in range(pos, len(text)):
        ch = text[i]
        if ch in MARKER_OPENERS:
            stack.append(ch)
        elif ch in MARKER_CLOSERS:
            if stack:
                if MARKER_OPENERS.index(stack[-1]) == MARKER_CLOSERS.index(ch):
                    stack.pop()
            else:
                return True
    return False


def _ends_with_options_marker(text: str, pos: int, line_end: int) -> bool:
    """Whether an accepted ``[OPTIONS:]`` marker runs from *pos* to *line_end*."""
    m = _RAW_OPTIONS_RE_LINE.match(text, pos, line_end)
    return m is not None and not _marker_labels_have_unmatched_opener(m.group("labels"))


def _accepted_option_action_spans(text: str) -> list[tuple[int, int]]:
    """``(start, end)`` of every ``[OPTION-ACTIONS:]`` marker in *text* a strip may remove."""
    candidates = list(_RAW_OPTION_ACTIONS_RE.finditer(text))
    if not candidates:
        return []
    newlines = [nl.start() for nl in re.finditer("\n", text)]
    widgets = [m.span() for m in _WIDGET_SPAN_RE.finditer(text)]
    widget_starts = [start for start, _ in widgets]
    walk = _FenceWalk()
    fed_to = 0
    lines: list[int] = []
    viable: list[bool] = []
    for m in candidates:
        line = bisect.bisect_left(newlines, m.start())
        line_start = newlines[line - 1] + 1 if line else 0
        walk.feed_text(text[fed_to:line_start])
        fed_to = max(fed_to, line_start)
        w = bisect.bisect_right(widget_starts, m.start()) - 1
        lines.append(line)
        viable.append(
            not walk.inside
            and not (w >= 0 and m.start() < widgets[w][1])
            and not _marker_labels_have_unmatched_opener(m.group("labels"))
        )
    accepted: list[tuple[int, int]] = []
    next_ok = False
    for i in range(len(candidates) - 1, -1, -1):
        m, ok = candidates[i], viable[i]
        line_end = newlines[lines[i]] if lines[i] < len(newlines) else len(text)
        if ok and m.end() < line_end:
            # A sibling head follows: the rest of the line must be accepted markers.
            if i + 1 < len(candidates) and lines[i + 1] == lines[i]:
                gap_end = candidates[i + 1].start()
                ok = next_ok and (
                    gap_end == m.end() or _ends_with_options_marker(text, m.end(), gap_end)
                )
            else:
                ok = _ends_with_options_marker(text, m.end(), line_end)
        if ok:
            accepted.append(m.span())
        next_ok = ok
    accepted.reverse()
    return accepted


def strip_option_action_markers_after(text: str, start: int) -> str:
    """``text[start:]`` minus the accepted action markers that begin at or after *start*."""
    out: list[str] = []
    cursor = start
    for span_start, span_end in _accepted_option_action_spans(text):
        if span_start >= start:
            out.append(text[cursor:span_start])
            cursor = span_end
    out.append(text[cursor:])
    return "".join(out)


def strip_option_action_markers(text: str) -> str:
    """*text* minus its accepted ``[OPTION-ACTIONS:]`` markers; call it before an ``[OPTIONS:]`` parse."""
    spans = _accepted_option_action_spans(text)
    if not spans:
        return text
    out: list[str] = []
    cursor = 0
    for start, end in spans:
        out.append(text[cursor:start])
        cursor = end
    out.append(text[cursor:])
    return "".join(out)


def _peel_trailing_option_actions(text: str, end: int) -> int:
    """Where *text[:end]* stops once the action markers ending it are peeled off."""
    for start, stop in reversed(_accepted_option_action_spans(text[:end])):
        if text[stop:end].strip():
            break
        end = start
    return end
