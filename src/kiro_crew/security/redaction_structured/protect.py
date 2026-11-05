"""Protection masks: the Identifier VALUES a caller may hide from a later shape-based pass.

``protect(text)`` returns the redacted text, the resolved hits and the masks. A mask is
``(start, end, rule_id)`` over the input text. Masks are in text order, never overlap
each other, and never overlap a Secret-tier hit.

- The row's ``mask`` field decides how much of an Identifier hit is masked: ``value``
  the whole hit (a labelled value, a public parameter's value, an ARN, a key ID, a
  placeholder); ``none`` nothing (a whole URL is a container, not a value);
  ``sha_segment`` only the SHA segment of a commit permalink.
- A span that overlaps any Secret-tier hit a detector found is never masked. This is
  checked against the hits before resolve, so a Secret hit that resolve rule 1 dropped
  inside a structural Identifier still keeps its span unmasked.
- Parameter rows never list a credential parameter (``table.NEVER_MASK_PARAMS``), so
  ``client_secret``, ``code`` and the tokens are never masked.
"""

from __future__ import annotations

import bisect

from .charsets import cached
from .engine import render, resolve, scan
from .model import IDENTIFIER, SECRET, Hit
from .table import TABLE, Table

Mask = tuple[int, int, str]


def _modes(table: Table) -> dict[str, str]:
    return {row.id: row.mask for row in table.structures}


def _sha_segment(text: str, h: Hit) -> tuple[int, int] | None:
    """``scheme://host/owner/repo/(commit|blob|tree)/<sha>``: the ``<sha>`` segment."""
    q = text.find("://", h.start, h.end)
    if q == -1:
        return None
    pos = q + 3
    for _ in range(4):
        slash = text.find("/", pos, h.end)
        if slash == -1:
            return None
        pos = slash + 1
    end = text.find("/", pos, h.end)
    end = h.end if end == -1 else end
    return (pos, end) if end > pos else None


def _merged(spans: list[tuple[int, int]]) -> tuple[list[int], list[int]]:
    starts: list[int] = []
    ends: list[int] = []
    for s, e in sorted(spans):
        if ends and s < ends[-1]:
            ends[-1] = max(ends[-1], e)
        else:
            starts.append(s)
            ends.append(e)
    return starts, ends


def masks_for(text: str, hits: list[Hit], resolved: list[Hit], table: Table = TABLE) -> list[Mask]:
    """Masks for ``resolved`` Identifier hits; ``hits`` are the raw hits before resolve."""
    modes = cached(table, _modes)
    starts, ends = _merged([(h.start, h.end) for h in hits if h.tier == SECRET])

    def touches_secret(s: int, e: int) -> bool:
        i = bisect.bisect_right(starts, e - 1) - 1
        return i >= 0 and ends[i] > s

    out: list[Mask] = []
    last = -1
    for h in resolved:
        if h.tier != IDENTIFIER:
            continue
        mode = modes.get(h.rule_id, "value")
        if mode == "none":
            continue
        span: tuple[int, int] | None = (h.start, h.end)
        if mode == "sha_segment":
            span = _sha_segment(text, h)
        if span is None or span[0] < last or touches_secret(*span):
            continue
        out.append((span[0], span[1], h.rule_id))
        last = span[1]
    return out


def protect(text: str, table: Table = TABLE) -> tuple[str, list[Hit], list[Mask]]:
    """``(redacted_text, resolved_hits, masks)`` for whole text."""
    hits = scan(text, final=True, table=table).hits
    if not hits:
        return text, [], []
    resolved = resolve(hits)
    return render(text, resolved, 0, len(text)), resolved, masks_for(text, hits, resolved, table)
