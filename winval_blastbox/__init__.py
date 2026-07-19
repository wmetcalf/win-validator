"""blastbox ``authenticode`` engine — Windows signature/cert-graveyard verdicts via myatg.

The engine (:class:`~winval_blastbox.engine.AuthenticodeEngine`) wraps the myatg Windows validator
running inside a disposable libvirt VM worker pool (:mod:`winval_blastbox.pool`), driven host-side by
:class:`~winval_blastbox.host_runner.HostRunner`.

Imports are LAZY (PEP 562): ``import winval_blastbox`` pulls in NOTHING heavy, so the unprivileged
``ingress`` tier can ``import winval_blastbox.ingress`` without the libvirt/engine dependencies (it
only needs the JobStore + FastAPI). The engine/HostRunner load on first attribute access — used by
the privileged ``pool_manager`` on the host.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["AuthenticodeEngine", "HostRunner", "get_pool", "shutdown_pool"]

if TYPE_CHECKING:  # for type-checkers only; never executed at runtime
    from .engine import AuthenticodeEngine, get_pool, shutdown_pool
    from .host_runner import HostRunner


def __getattr__(name: str):
    if name in ("AuthenticodeEngine", "get_pool", "shutdown_pool"):
        from . import engine
        return getattr(engine, name)
    if name == "HostRunner":
        from .host_runner import HostRunner
        return HostRunner
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
