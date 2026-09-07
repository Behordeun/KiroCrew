"""Dashboard HTTP handler for the WakaTime integration.

One read endpoint, single-owner (no per-user identity: this is the local
dashboard owner's own configured WakaTime account):

- ``GET /api/wakatime/export`` — hours grouped by project over a date range,
  as a CSV download, for billable-hours export.

When the integration is disabled or unconfigured the endpoint returns a 200 with
``{"configured": false}`` rather than an error, so the frontend renders an
ordinary "connect WakaTime" empty state instead of an error banner.

The stats endpoint and a JSON export variant are deferred to the dashboard
productivity-view change that consumes them, so this ships only the surface with
a use today: the CSV invoicing export.
"""

from __future__ import annotations

import asyncio
import csv
import io
import logging
import urllib.parse
from collections import defaultdict
from datetime import date
from typing import Any

from aiohttp import web

logger = logging.getLogger(__name__)

# YYYY-MM-DD is the only date shape WakaTime's summaries endpoint accepts.


def _valid_date(value: str) -> bool:
    """True only for a real calendar date in YYYY-MM-DD form.

    A shape-only regex accepts 2026-02-30, a plausible operator typo, which the
    upstream then rejects into an empty result — a false zero-hour export.
    fromisoformat validates both the format and the calendar.
    """
    try:
        # fromisoformat also accepts compact forms like "20260901" (3.11+), so
        # round-trip through isoformat() to hold the promised YYYY-MM-DD shape.
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def _upstream_error() -> web.Response:
    return web.json_response(
        {
            "error": "WakaTime is unreachable or the API key was rejected",
            "code": "upstream_unavailable",
        },
        status=502,
    )


# Characters a spreadsheet treats as the start of a formula. A project name
# is external data (it comes from WakaTime), so a name like "=cmd|..." would
# execute on import if written raw. Prefixing an apostrophe forces the cell to
# be read as text; the leading control chars are equivalents some parsers honor.
_CSV_FORMULA_TRIGGERS = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: str) -> str:
    """Neutralize a leading formula trigger so a CSV cell imports as text."""
    if value and value[0] in _CSV_FORMULA_TRIGGERS:
        return "'" + value
    return value


def _rows_by_project(summaries: list[dict]) -> list[dict[str, Any]]:
    """Fold WakaTime daily summaries into per-project totals.

    Each summary day carries a ``projects`` list of ``{name, total_seconds}``;
    sum the seconds per project name across the range.
    """
    totals: dict[str, float] = defaultdict(float)
    for day in summaries:
        for proj in day.get("projects") or []:
            if not isinstance(proj, dict):
                continue
            name = proj.get("name")
            seconds = proj.get("total_seconds")
            if isinstance(name, str) and isinstance(seconds, (int, float)):
                totals[name] += float(seconds)
    rows = [
        {
            "project": name,
            "seconds": round(secs, 2),
            "hours": round(secs / 3600.0, 4),
        }
        for name, secs in sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
    ]
    return rows


async def api_wakatime_export(request: web.Request) -> web.Response:
    """GET /api/wakatime/export?start=&end= — billable hours as a CSV download.

    Hours grouped by project over ``start``..``end`` (inclusive, YYYY-MM-DD).
    """
    start = request.query.get("start", "")
    end = request.query.get("end", "")

    if not _valid_date(start) or not _valid_date(end):
        return web.json_response(
            {"error": "start and end must be YYYY-MM-DD", "code": "invalid_date"},
            status=400,
        )
    if start > end:
        return web.json_response(
            {"error": "start must not be after end", "code": "invalid_range"},
            status=400,
        )

    # Import the optional WakaTime subsystem lazily, on first request, so it
    # stays off the gateway boot path (handlers/__init__ is imported at startup).
    from kiro_crew.wakatime import WakaTimeUnavailableError, service

    # build_client() does synchronous config-load + vault-decrypt I/O; run it off
    # the event loop so a request never stalls the loop on filesystem reads.
    client = await asyncio.to_thread(service.build_client)
    if client is None:
        return web.json_response({"configured": False})

    try:
        # fetch_summaries RAISES on an upstream failure of THIS endpoint, rather
        # than degrading to []. A blank billing export must not pass off an
        # outage as "zero hours worked", and only the summaries call itself can
        # tell those apart — a probe of a different endpoint cannot.
        summaries = await client.fetch_summaries(start, end)
    except WakaTimeUnavailableError:
        return _upstream_error()
    finally:
        await client.close()

    rows = _rows_by_project(summaries)

    # CSV: generated in-memory, returned with a download disposition.
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["project", "hours", "seconds"])
    for r in rows:
        # Project names are neutralized by _csv_safe against formula injection;
        # the taint rule cannot see that wrapper, so scope a waiver to this sink.
        # nosemgrep: python.django.security.injection.csv-writer-injection.csv-writer-injection
        writer.writerow([_csv_safe(r["project"]), r["hours"], r["seconds"]])
    filename = f"wakatime-hours-{start}-to-{end}.csv"
    quoted = urllib.parse.quote(filename, safe="")
    return web.Response(
        body=buf.getvalue().encode("utf-8"),
        content_type="text/csv",
        charset="utf-8",
        headers={
            "Content-Disposition": f"attachment; filename*=UTF-8''{quoted}",
            "X-Content-Type-Options": "nosniff",
        },
    )
