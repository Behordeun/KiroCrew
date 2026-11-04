"""What a Shared Crew guest may not do: the owner-only surface, pinned in one place.

A guest is a collaborator a membership boundary admitted (``collaborators``).
Inside the Crew a guest has the owner's abilities: ``is_owner_dashboard_request``
answers true for a guest, so every owner-gated in-Crew route (chat, mates,
approvals, artifacts, skills, ...) admits one. The routes below are the
exception. They manage the share itself or the host's ceiling, so a guest is
refused on them exactly as before. Matching is by request path, which keeps the
list reviewable as data and lets one test pin it.

Anything that is not listed is open to a guest. Add a route here when it
manages who may reach the Crew, the network path, ``config.json``, security
policy, a credential, the gateway process, or code and tools the host runs
outside an agent's approvals.
"""

from __future__ import annotations

import os
import posixpath
import re
import stat
from pathlib import Path
from typing import Any

__all__ = [
    "OWNER_ONLY_METHOD_PATHS",
    "OWNER_ONLY_PATH_PATTERNS",
    "OWNER_ONLY_PATH_PREFIXES",
    "OWNER_ONLY_WRITE_PATTERNS",
    "OWNER_ONLY_RAW_PREFIXES",
    "guest_acts_as_owner",
    "attachment_read",
    "guest_attachment_read",
    "guest_created_by",
    "guest_creator_name",
    "guest_write_denial",
    "guest_job_tag",
    "guest_posture_refusal",
    "guest_recently_revoked",
    "is_guest_session",
    "record_guest_revocation",
    "is_owner_only_path",
]

#: Matched on a path-segment boundary: ``/api/mcp`` covers ``/api/mcp/custom`` and
#: not ``/api/mcp-apps/call``.
OWNER_ONLY_PATH_PREFIXES: tuple[str, ...] = (
    # Who may reach the Crew, and over which network path.
    "/api/shared-crew/access",
    "/api/shared-crew/preview",
    "/api/shared-crew/tailscale",
    "/api/shared-crew/ssm",
    "/api/tailnet",
    "/api/tunnel",
    "/api/mobile-connect",
    "/api/instances",
    # config.json and security policy.
    "/api/config",
    "/api/dashboard/config",
    "/api/agent/config",
    "/api/security",
    "/api/governance",
    "/api/redaction",
    "/api/admin",
    "/api/sel",
    "/api/decisions/consent",
    "/api/decisions/provider",
    "/api/decisions/local-models",
    "/api/aws",
    "/api/computer-use",
    "/api/telemetry/collection",
    "/api/debug",
    "/api/logs",
    "/api/diagnostics",
    "/api/system",
    # Credentials, connection secrets and the channels that hold them.
    "/api/secrets",
    "/api/connections",
    "/api/kas-login",
    "/api/kas-bundle",
    "/api/sso-login",
    "/api/sso-ttl",
    "/api/token",
    "/api/auth",
    "/api/webhooks",
    "/api/channels",
    "/api/channel",
    "/api/channel-folders",
    "/api/session-environments",
    "/api/wakatime",
    "/api/onboarding",
    "/api/stt/ffmpeg",
    "/api/slack",
    "/api/telegram",
    "/api/discord",
    "/api/feishu",
    "/api/imessage",
    "/api/teams",
    "/api/messaging",
    "/api/webex",
    "/api/wecom",
    "/api/weixin",
    "/api/whatsapp",
    "/api/voice/config",
    "/api/notifications/push",
    "/api/cloud",
    "/api/usage",
    "/api/sessions/usage",
    "/api/deploy",
    "/api/publish-providers",
    "/api/remote-artifacts",
    "/api/send-message",
    "/api/delete-message",
    "/api/slack-profile",
    "/api/mediated-secret-request",
    "/api/mediated-secret-capability",
    "/api/app-store",
    "/api/mcp-gateway",
    "/api/skills/-/trust",
    "/api/mcp/oauth",
    # Monitors probe a provider with the owner's credentials and report what they find.
    "/api/monitors",
    "/api/autonudge",
    # The gateway process and code the host runs outside an agent's approvals.
    "/api/restart",
    "/api/shutdown",
    "/api/update",
    "/api/terminal",
    "/api/ws/terminal",
    "/api/mcp",
    "/api/capability",
    "/api/mcp-apps",
    "/api/hooks",
    "/api/kiro-hooks",
    "/api/apps",
    "/api/browser",
    "/apps",
    "/api/themes/install",
    "/api/themes/install-zip",
    "/api/portability",
    "/api/worktree",
    "/api/project-scaffold",
    # The host filesystem outside the Crew's own stores. ``/api/file-raw`` is
    # reached by a guest only for chat attachments (``guest_reads_attachment``).
    "/api/directory-upload",
    "/api/browse-dirs",
    "/api/browse-files",
    "/api/path-complete",
    "/api/reveal",
    "/api/project/git",
    "/api/project/tree",
    "/api/project/session-files",
    "/api/project/session-file-diff",
    "/api/knowledge/pick-folder",
    "/api/knowledge/remote-search",
    "/api/knowledge/import",
    "/api/knowledge/ingest",
    "/api/knowledge/sources",
    "/api/memory/stores",
    "/api/memory/backup",
    "/api/memory/backups",
    "/api/memory/restore",
    "/api/memory/import",
    "/api/memory/migrate",
    "/api/memory/enable-embeddings",
    "/api/memory/disable-embeddings",
    "/api/memory/embedding-model",
)

#: Matched as a plain string prefix (the file routes share a ``file-`` stem).
OWNER_ONLY_RAW_PREFIXES: tuple[str, ...] = ("/api/file-",)

#: Matched against the whole path.
OWNER_ONLY_PATH_PATTERNS: tuple[str, ...] = (
    # A schedule's script source and secret grants.
    r"/api/crons/[^/]+/(?:script|secrets)",
    # Publishing or syncing an artifact spends the owner's account and posts it publicly.
    r"/api/artifacts/[^/]+/(?:publish|sharing|pull-latest|upstream-status|overwrite-remote)(?:/.*)?",
    # A session's remote environment: browsing and writing its files.
    r"/api/chat/slots/[^/]+/environment/(?:browse|file)(?:/.*)?",
)

#: Matched against the whole path for every method but a read. A guest reads these
#: (the agent picker, the workspace list, a session's environment) and does not
#: change them: an agent spec writes machine-wide tool approvals and MCP
#: declarations into ``config.json``, a workspace adopts a host directory, and an
#: environment repoints where the session runs.
OWNER_ONLY_WRITE_PATTERNS: tuple[str, ...] = (
    r"/api/agents(?:/.*)?",
    r"/api/workspaces(?:/.*)?",
    r"/api/projects(?:/.*)?",
    r"/api/themes(?:/.*)?",
    r"/api/chat/slots/[^/]+/environment",
    # A workflow's agents run with every tool call approved, so starting, saving or
    # promoting one is the owner's. A guest still reads definitions and runs.
    r"/api/workflows/(?:run|run_intent)",
    r"/api/workflows/definitions(?:/.*)?",
    r"/api/workflows/runs/[^/]+/(?:rerun|promote)",
    # Installation-wide settings a guest reads and does not change: history retention
    # (a heartbeat sweep then deletes everyone's older history), notification channels,
    # a mate's Goals check-in schedules (they create unattended jobs no revoke can find),
    # and linking a session to the owner's Slack. A plan step or the plan itself, which an
    # owner's auto-approved run would execute under its standing grant.
    r"/api/memory/settings",
    r"/api/notifications/channels/settings",
    r"/api/members/[^/]+/goals/schedules",
    r"/api/chat/slots/[^/]+/(?:slack|mirror)-(?:link|pause|unlink)",
    r"/api/taskrunner/[^/]+/(?:tasks/[^/]+|plan)",
)

#: ``(method, path)`` pairs refused whatever the rest of the path's methods allow:
#: deleting every stored session cannot be undone.
OWNER_ONLY_METHOD_PATHS: tuple[tuple[str, str], ...] = (
    ("DELETE", "/api/sessions"),
    # The native file picker and the interactive screenshot start host desktop processes.
    ("POST", "/api/upload"),
    ("POST", "/api/screenshot"),
)

_PATTERNS = tuple(re.compile(p) for p in OWNER_ONLY_PATH_PATTERNS)
_DOT_SEGMENT = re.compile(r"(?:^|/)\.\.?(?:/|$)")
_WRITE_PATTERNS = tuple(re.compile(p) for p in OWNER_ONLY_WRITE_PATTERNS)
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def is_owner_only_path(path: str, method: str = "") -> bool:
    """Whether *path* (with *method*, when given) is a route a guest is refused on."""
    if _DOT_SEGMENT.search(path):
        # The router matches the path as sent, so a dot segment can stand in a
        # path variable where normalization would erase it.
        return True
    path = posixpath.normpath("/" + path.lstrip("/")) if path else "/"
    if (method.upper(), path) in OWNER_ONLY_METHOD_PATHS:
        return True
    if any(path.startswith(p) for p in OWNER_ONLY_RAW_PREFIXES):
        return True
    for prefix in OWNER_ONLY_PATH_PREFIXES:
        if path == prefix or path.startswith(prefix + "/"):
            return True
    if any(p.fullmatch(path) for p in _PATTERNS):
        return True
    return (
        bool(method)
        and method.upper() not in _READ_METHODS
        and any(p.fullmatch(path) for p in _WRITE_PATTERNS)
    )


#: Owner-only paths a guest's session still writes to: signing out and refreshing.
_GUEST_WRITE_EXEMPT_PATHS = frozenset({"/api/auth/logout", "/api/auth/refresh", "/api/logout"})


def guest_write_denial(request: Any) -> Any:
    """A 403 when a guest writes to an owner-only route, else ``None``.

    Run before the handler, so a listed route is closed even when its handler
    never asks the owner gate. Reads are left to their handlers: the dashboard
    polls several listed routes and meets their own refusals.
    """
    method = str(getattr(request, "method", "") or "").upper()
    if method in _READ_METHODS or not is_guest_session(request):
        return None
    if "guest_admitted_at" not in request:
        # When this write was admitted, before its body is read: a revoke that lands
        # later fences it however slowly the body arrives (``guest_recently_revoked``).
        import time

        request["guest_admitted_at"] = time.monotonic()
    path = str(getattr(request, "path", "") or "")
    if path.rstrip("/") in _GUEST_WRITE_EXEMPT_PATHS or not is_owner_only_path(path, method):
        return None
    from aiohttp import web

    return web.json_response(
        {"error": "owner authorization required", "code": "owner_only"}, status=403
    )


#: Postures and actions that auto-approve later tool calls without the owner.
_UNATTENDED_POSTURES = frozenset(
    {
        "yolo",
        "trust",
        "trust_reads",
        "trust_command",
        "trust_base",
        # The approve action that turns trust-reads on (``permission_prompt``), posted
        # without the ``trust_reads`` conversion; and a spawned run's ``auto`` mode.
        "approved_trust_reads",
        "auto",
    }
)


def guest_posture_refusal(request: Any, posture: object) -> Any:
    """A 403 when a guest asks for an approval posture that outlasts their click.

    A guest approves or rejects each tool call. Turning on trust, trust-reads or
    YOLO would auto-approve later calls (YOLO for every session) and keep doing so
    after the guest is revoked, so those stay the host owner's.
    """
    if not isinstance(posture, str) or posture not in _UNATTENDED_POSTURES:
        return None
    if not is_guest_session(request):
        return None
    from aiohttp import web

    return web.json_response(
        {"error": "this approval mode is owner-only", "code": "owner_only"}, status=403
    )


_GUEST_TAG_PREFIX = "guest:"

#: A request with no recorded admission time (it did not pass the write checkpoint) is
#: fenced for this long after a revoke instead (seconds).
REVOCATION_FENCE_SECS = 300.0
#: Revoked people held at once; the oldest marks go first.
_REVOKED_MAX = 1024
_REVOKED_AT: dict[str, float] = {}


def record_guest_revocation(principal_ids: Any) -> None:
    """Note that these people were just revoked, before their schedules are swept.

    A create or enable the guest sent before the revoke can commit after the sweep
    read the store; it finds this mark when it commits and undoes itself
    (``guest_recently_revoked``). Recorded first, so a commit the sweep missed is
    always one that sees the mark. The mark is not time-limited: a request is judged
    by when it was admitted, so one that dribbles its body in for minutes is still
    fenced, and a person invited again later is admitted after the mark and is not.
    """
    import time

    now = time.monotonic()
    for pid in principal_ids:
        if pid:
            _REVOKED_AT.pop(pid, None)
            _REVOKED_AT[pid] = now
    while len(_REVOKED_AT) > _REVOKED_MAX:
        del _REVOKED_AT[next(iter(_REVOKED_AT))]


def guest_recently_revoked(request: Any) -> bool:
    """Whether *request*'s guest was revoked after this request was admitted."""
    import time

    from kiro_crew.shared_crew.identity import viewer_principal

    at = _REVOKED_AT.get(viewer_principal(request).id)
    if at is None:
        return False
    admitted = request.get("guest_admitted_at")
    if admitted is not None:
        return bool(admitted <= at)
    return time.monotonic() - at <= REVOCATION_FENCE_SECS


def guest_job_tag(principal_id: str) -> str:
    """The ``created_by`` a schedule a guest created carries, so a revoke can find it."""
    return f"{_GUEST_TAG_PREFIX}{principal_id}"


def guest_creator_name(created_by: str) -> str | None:
    """The display name of the guest a schedule's ``created_by`` stamp names.

    ``None`` when the stamp is not a guest's. ``""`` for a guest nobody has a
    name for, which the dashboard words as "Guest". The stamp itself is never
    shown: it holds the principal id.
    """
    if not isinstance(created_by, str) or not created_by.startswith(_GUEST_TAG_PREFIX):
        return None
    from kiro_crew.shared_crew.people import registry

    principal_id = created_by[len(_GUEST_TAG_PREFIX) :]
    for seen in registry().snapshot():
        if seen.principal.id == principal_id:
            shown = seen.principal.display
            return (shown.name or shown.login or "").strip()
    return ""


def guest_created_by(request: Any) -> str:
    """The ``created_by`` stamp for a schedule *request* creates: a guest's, else ``""``."""
    if not is_guest_session(request):
        return ""
    from kiro_crew.shared_crew.identity import viewer_principal

    return guest_job_tag(viewer_principal(request).id)


def is_guest_session(request: Any) -> bool:
    """Whether *request* is a guest's own dashboard session, on any route.

    A guest is a person a membership boundary admitted: an empty (present) app
    claim, the dashboard-user claim, no internal secret, and a verified
    collaborator actor. Never with the Shared Crew preview off.
    """
    if request.get("internal_auth") is True or request.get("app", None) != "":
        return False
    if request.get("is_dashboard_user") is not True or not request.get("user"):
        return False
    if _is_host_owner(request):
        # The owner on the direct tailnet listener carries the listener's provenance,
        # which a collaborator also carries; the subject tells them apart.
        return False
    from kiro_crew.shared_crew.collaborators import is_collaborator_actor
    from kiro_crew.shared_crew.identity import actor_of

    return is_collaborator_actor(actor_of(request))


def _is_host_owner(request: Any) -> bool:
    """Whether *request* is the host owner; ``False`` when that cannot be told."""
    try:
        from kiro_crew.dashboard.handlers.source_providers import (
            is_host_owner_dashboard_request,
        )

        return is_host_owner_dashboard_request(request)
    except Exception:
        return False


def guest_acts_as_owner(request: Any) -> bool:
    """Whether *request* is a guest on a route a guest may use as the owner would.

    A call that is not a route (no path: a background task, a socket frame) is not
    judged by the list, so it fails closed.
    """
    path = str(getattr(request, "path", "") or "")
    if not path:
        return False
    return is_guest_session(request) and not is_owner_only_path(
        path, str(getattr(request, "method", "") or "")
    )


def attachment_read(raw: str, max_bytes: int) -> tuple[str, bytes] | None:
    """The bytes of a chat attachment named by *raw*, or ``None``.

    A chat attachment is a file directly inside the upload directory or a session's
    ``<stem>.attachments`` directory under the data home's ``sessions/``. The path
    is resolved once, refused when it leaves a store (``..``, a symlink, a symlinked
    directory), and the file is then opened with no-follow and judged on the open
    descriptor: a regular file, one hard link, and the very file the resolution
    saw. Nothing re-resolves the name after the check, so a link swapped in between
    meets the no-follow open or the identity test. A leading ``//`` or ``\\`` is
    refused before any resolution, since resolving a network path on Windows makes
    the host contact that server. Blocking (``realpath``, ``lstat``, ``open``).
    """
    if not raw or "\x00" in raw or raw.startswith(("//", "\\")):
        return None
    from kiro_crew.chat_attachments import ATTACHMENTS_DIR_SUFFIX
    from kiro_crew.config.paths import config_dir
    from kiro_crew.dashboard.handlers.files import _upload_dir

    try:
        resolved = Path(os.path.realpath(os.path.expanduser(raw)))
        parent = resolved.parent
        uploads = Path(os.path.realpath(_upload_dir()))
        sessions = Path(os.path.realpath(config_dir() / "sessions"))
        in_store = parent == uploads or (
            parent.name.endswith(ATTACHMENTS_DIR_SUFFIX) and parent.parent == sessions
        )
        if not in_store:
            return None
        before = os.lstat(resolved)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            return None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        fd = os.open(resolved, flags)
    except (OSError, ValueError):
        return None
    try:
        opened = os.fstat(fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            return None
        with os.fdopen(fd, "rb", closefd=False) as handle:
            data = handle.read(max_bytes + 1)
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        return None
    return str(resolved), data


async def guest_attachment_read(
    request: Any, raw: str, max_bytes: int, *, run: Any = None
) -> tuple[str, bytes] | None:
    """What a guest may read through ``/api/file-raw``: a chat attachment only, else ``None``.

    The read resolves a path the guest chose, which can block on a stalled mount.
    *run* is the executor to do that on (the caller's isolated path-probe pool, so a
    stall cannot starve the gateway's shared one); it defaults to ``asyncio.to_thread``.
    """
    import asyncio
    import functools

    if not is_guest_session(request):
        return None
    return await (run or asyncio.to_thread)(functools.partial(attachment_read, raw, max_bytes))
