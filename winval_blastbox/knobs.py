"""One reader for the numeric knobs the deploy's env files carry.

Every tier (the ingress container, the host pool-manager, the orchestrator) reads the same
/etc/winval/winval.env-style variables; a bare int() at import time turned an operator's
typo (`512M`, an emptied line) into a crash before any log line — eight systemd restarts and
a unit latched `failed`. A bad value is a warning by name plus the default, never a crash.
"""
from __future__ import annotations

import logging
import os

logger = logging.getLogger("winval.knobs")


def env_int(name: str, default: int, floor: int | None = None) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        logger.warning("%s=%r is not a whole number: using %d", name, raw, default)
        return default
    if floor is not None and n < floor:
        logger.warning("%s=%r is below %d: using %d", name, raw, floor, floor)
        return floor
    return n


def env_float(name: str, default: float, floor: float | None = None) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        v = float(raw)
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError(raw)
    except ValueError:
        logger.warning("%s=%r is not a number: using %s", name, raw, default)
        return default
    if floor is not None and v < floor:
        logger.warning("%s=%r is below %s: using %s", name, raw, floor, floor)
        return floor
    return v


def upload_mb() -> int:
    """AUTHENTICODE_MAX_UPLOAD_MB: the bound the ingress enforces on an upload AND the bound the host
    pool-manager enforces on the spooled input it copies — set it the same in both tiers' environments."""
    return env_int("AUTHENTICODE_MAX_UPLOAD_MB", 1024, floor=1)


def agent_port() -> int:
    """AUTHENTICODE_AGENT_PORT: the port the golden LISTENS on (baked into its URL ACL, firewall rule and
    task), read by the pool, the builder and the engine alike."""
    return env_int("AUTHENTICODE_AGENT_PORT", 8765, floor=1)
