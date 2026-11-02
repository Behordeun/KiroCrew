"""The admin's opt-in that lets Crew's own servers carry session identity under the registry.

Read by :func:`kiro_crew.acp.session_mcp.kiro_control_plane_servers`, which imports
:func:`_registry_local_control_plane_permitted` under that module's own name, so
callers and tests reach it as ``session_mcp._registry_local_control_plane_permitted``.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("kiro_crew.acp.session_mcp")


def _registry_local_control_plane_permitted() -> bool:
    """Whether the admin's security policy opts Crew's own servers past the registry.

    The policy's top-level ``mcp_registry_local_control_plane``
    (``GovernanceCeiling.mcp_registry_local_control_plane``). ``security_policy.json``
    is a keystone the sandbox mounts read-only and the agent file gate refuses to
    write, so the opt-in is the admin's alone. Absent, ``false``, no policy at all,
    or a ceiling that cannot be read all answer ``False``: the default on a
    registry-governed host stays the one that mounts nothing outside the catalog.
    A memory read of the installed ceiling.
    """
    try:
        from kiro_crew.platform.context import current_context

        return (
            getattr(current_context().governance, "mcp_registry_local_control_plane", False) is True
        )
    except Exception:
        logger.warning(
            "session MCP: could not read the security policy's "
            "mcp_registry_local_control_plane; treating it as off, so Kiro Crew's own "
            "servers get no per-session identity element under registry mode.",
            exc_info=True,
        )
        return False
