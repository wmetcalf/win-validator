"""win-validator POOL-MANAGER — the privileged dispatcher half of the split.

The libvirt analogue of ``blastbox dispatch``: instead of ``docker run``ning a worker container per
job, it keeps a warm VM pool (the ``WarmPool`` primitive — spawn/snapshot/recycle + rooter egress +
the tunnel kill-switch) and validates each job through a long-lived worker's myatg HTTP agent.

It owns ALL the host privilege (libvirt, iptables) and is NEVER exposed to untrusted network input:
it only reads queued jobs from the shared JobStore + their spooled inputs from ``job_root``, runs
them through the VM (the sandbox), and writes the verdict back as the Job's ``result_summary``. The
unprivileged ``ingress`` is the only client-facing tier; this is its counterpart across the boundary.

    BLASTBOX_DATABASE_URL    shared JobStore (must match the ingress)
    WINVAL_JOB_ROOT          shared dir holding <id>/input/<file> (must match the ingress)
    AUTHENTICODE_POOL_SIZE   warm VM workers == claim concurrency

Run on the libvirt host:  python -m winval_blastbox.pool_manager
"""
from __future__ import annotations

import json
import logging
import os
import signal
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from blastbox.host.jobs.base import JobStatus
from blastbox.host.jobs.factory import build_job_store_from_env

from .host_runner import HostRunner

logger = logging.getLogger("winval.pool_manager")

JOB_ROOT = Path(os.environ.get("WINVAL_JOB_ROOT", "/var/lib/winval/jobs"))
POLL_S = float(os.environ.get("WINVAL_CLAIM_POLL_S", "0.5"))


def _extract_verdict(env: dict) -> dict:
    """Pull the myatg verdict (components, not opinion) out of the sealed envelope, plus the
    warnings + envelope status. Same shape the old single-process orchestrator surfaced."""
    fields = (env.get("payload") or {}).get("fields") or {}
    raw = fields.get("authenticode_json")
    verdict = None
    if isinstance(raw, str):
        try:
            verdict = json.loads(raw)
        except ValueError:
            verdict = None
    return {
        "verdict": verdict,
        "warnings": [w.get("code") for w in env.get("warnings") or []],
        "envelope_status": env.get("status"),
    }


class PoolManager:
    def __init__(self) -> None:
        self._store = build_job_store_from_env()
        self._runner = HostRunner()
        self._stop = threading.Event()
        self._concurrency = int(os.environ.get("AUTHENTICODE_POOL_SIZE", "2"))

    def _process(self, job) -> None:
        """Validate one claimed job and write its verdict back (CAS-fenced on the claim)."""
        # job.filename / job.result_dir come from the shared, ingress-writable job store, and this
        # manager runs as root. Sanitize before touching the filesystem: a traversal here (e.g.
        # filename="../../../etc/shadow") would let a compromised ingress delete/clobber arbitrary
        # host files via the finally-unlink. Strip filename to a basename; require result_dir under
        # JOB_ROOT.
        filename = Path(job.filename or "").name
        if not filename:
            raise ValueError(f"job {job.job_id}: empty/invalid filename")
        result_dir = Path(job.result_dir).resolve()
        if not result_dir.is_relative_to(JOB_ROOT.resolve()):
            raise ValueError(f"job {job.job_id}: result_dir escapes JOB_ROOT: {job.result_dir!r}")
        in_path = result_dir / "input" / filename
        out_dir = result_dir / "output"
        try:
            if not in_path.exists():
                raise FileNotFoundError(f"spooled input missing: {in_path}")
            env = self._runner.validate_to_dir(in_path, out_dir)
            summary = _extract_verdict(env)
            status = (JobStatus.FAILED if summary.get("envelope_status") == "engine_error"
                      else JobStatus.DONE)
            self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=status, finished_at=time.time(), result_summary=summary,
                worker_runtime="vm")
        except Exception as exc:  # noqa: BLE001 — one bad job must not sink the manager
            logger.warning("job %s failed: %s", job.job_id, exc, exc_info=True)
            self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=JobStatus.FAILED, finished_at=time.time(), error=type(exc).__name__)
        finally:
            try:  # the sample is consumed; drop the spooled input (keep the sealed output)
                in_path.unlink()
            except OSError:
                pass

    def _worker_loop(self) -> None:
        while not self._stop.is_set():
            try:
                job = self._store.claim_next()
            except Exception:  # noqa: BLE001 — a transient store error must not kill the loop
                logger.warning("claim_next failed", exc_info=True)
                job = None
            if job is None:
                self._stop.wait(POLL_S)
                continue
            self._process(job)

    def run(self) -> None:
        logger.info("warming VM pool (%d workers)…", self._concurrency)
        self._runner.warmup()
        logger.info("pool warm; claiming jobs from %s", type(self._store).__name__)
        with ThreadPoolExecutor(max_workers=self._concurrency, thread_name_prefix="claim") as ex:
            for _ in range(self._concurrency):
                ex.submit(self._worker_loop)
            self._stop.wait()  # block until SIGTERM/SIGINT
        self._runner.shutdown()
        logger.info("pool-manager stopped")

    def stop(self, *_: object) -> None:
        self._stop.set()


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    pm = PoolManager()
    signal.signal(signal.SIGTERM, pm.stop)
    signal.signal(signal.SIGINT, pm.stop)
    pm.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
