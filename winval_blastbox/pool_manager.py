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
RETENTION_DAYS = float(os.environ.get("WINVAL_JOB_RETENTION_DAYS", "7"))   # a finished (or rowless) job directory is removed after this
SWEEP_S = 3600.0


def _confine(p: Path, what: str) -> Path:
    """A path this ROOT process will read, write through or unlink must lie under JOB_ROOT with NO symlink
    in any component below it: the ingress owns job_root (uid 10001) and a compromised ingress could
    otherwise replace <job>/input or <job>/output with a symlink and steer this process anywhere. The
    resolved path is returned; the walk below refuses intermediate links (blastbox's retention sweeper
    keeps the same rule: symlinks are never followed out of job_root)."""
    ap = Path(os.path.abspath(p))          # LEXICAL: resolve() would erase the very links being refused,
    for base in (Path(os.path.abspath(JOB_ROOT)), JOB_ROOT.resolve()):   # so a link into ANOTHER job's dir passed
        if ap.is_relative_to(base):
            break
    else:
        raise ValueError(f"{what} escapes JOB_ROOT: {p}")
    cur = base
    for part in ap.relative_to(base).parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValueError(f"{what}: symlink in path refused: {cur}")
    if not ap.resolve().is_relative_to(JOB_ROOT.resolve()):
        raise ValueError(f"{what} escapes JOB_ROOT: {p}")
    return ap


def _rm_job_dir(d: Path) -> None:
    """Remove one job directory tree, never following symlinks (they are unlinked as links)."""
    d = _confine(d, "job dir")
    for root_, dirs, files in os.walk(d, topdown=False, followlinks=False):
        for f in files + [x for x in dirs if (Path(root_) / x).is_symlink()]:
            try:
                (Path(root_) / f).unlink()
            except OSError:
                pass
        for x in dirs:
            try:
                (Path(root_) / x).rmdir()
            except OSError:
                pass
    try:
        d.rmdir()
    except OSError:
        pass
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
        in_path = None
        recorded = False   # whether a terminal status reached the store: only then is the spooled input consumed
        try:
            # INSIDE the guard: a hostile row is exactly what the sanitiser exists for, and raising
            # outside it ended the claim thread for the life of the process (the unit stayed "active")
            filename = Path(job.filename or "").name
            if not filename:
                raise ValueError(f"job {job.job_id}: empty/invalid filename")
            result_dir = _confine(Path(job.result_dir or ""), f"job {job.job_id}: result_dir")
            in_path = _confine(result_dir / "input" / filename, f"job {job.job_id}: input")
            out_dir = _confine(result_dir / "output", f"job {job.job_id}: output") if (result_dir / "output").exists() else result_dir / "output"
            if not in_path.is_file():
                raise FileNotFoundError(f"spooled input missing: {in_path}")
            env = self._runner.validate_to_dir(in_path, out_dir)
            summary = _extract_verdict(env)
            status = (JobStatus.FAILED if summary.get("envelope_status") == "engine_error"
                      else JobStatus.DONE)
            self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=status, finished_at=time.time(), result_summary=summary,
                worker_runtime="vm")
            recorded = True
        except Exception as exc:  # noqa: BLE001 — one bad job must not sink the manager
            logger.warning("job %s failed: %s", job.job_id, exc, exc_info=True)
            try:   # the recovery write uses the same store that may have just failed (a Postgres restart): it must not escape either
                self._store.update_if_status(
                    job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                    status=JobStatus.FAILED, finished_at=time.time(), error=type(exc).__name__)
                recorded = True
            except Exception:  # noqa: BLE001
                # there is NO store-side reaper for RUNNING jobs (blastbox's retention never touches them): the row
                # stays RUNNING until the next pool-manager start recovers it (_recover_orphans), and the spooled
                # input is KEPT so that recovery — or an operator — can still act on the sample
                logger.warning("job %s: could not record the failure; the row stays RUNNING until the next pool-manager start recovers it", job.job_id, exc_info=True)
        finally:
            if in_path is not None and recorded:
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
            try:
                self._process(job)
            except Exception:  # noqa: BLE001 — NOTHING a job does may end this loop: run() never reads the executor's futures, so a dead loop is a silent claim thread lost for the life of the process
                logger.error("job %s: unexpected error escaped _process; the claim loop continues", getattr(job, "job_id", "?"), exc_info=True)

    def _recover_orphans(self) -> None:
        """A RUNNING job at pool-manager START belongs to nobody: this process is the store's only claimant of
        its tier, so anything still RUNNING was abandoned by the previous instance (a restart mid-validation,
        a lost terminal write). blastbox's retention never touches RUNNING rows and there is no reaper, so
        they would sit RUNNING forever — the UI polling them without end. Mark them FAILED, by name."""
        try:
            stale = list(self._store.list(status=JobStatus.RUNNING))
        except Exception:  # noqa: BLE001 — recovery is best effort; the claim loops will surface a broken store
            logger.warning("orphan recovery: could not list RUNNING jobs", exc_info=True)
            return
        for job in stale:
            try:
                if self._store.update_if_status(job.job_id, JobStatus.RUNNING, status=JobStatus.FAILED,
                                                finished_at=time.time(), error="orphaned by a pool-manager restart"):
                    logger.warning("job %s was RUNNING at start (abandoned by the previous pool-manager): marked FAILED", job.job_id)
                    # the spooled input a lost terminal write KEPT (see _process) is consumed here, once the row is terminal
                    name = Path(job.filename or "").name
                    if name:
                        try:
                            _confine(Path(job.result_dir or "") / "input" / name, "orphan input").unlink()
                        except (OSError, ValueError):
                            pass
            except Exception:  # noqa: BLE001
                logger.warning("orphan recovery: job %s could not be updated", job.job_id, exc_info=True)

    def _sweep_job_root(self) -> None:
        """Retention for WINVAL_JOB_ROOT (nothing else has any): a job directory older than RETENTION_DAYS
        whose row is terminal — or has no row at all (an upload the ingress rejected after mkdir) — is
        removed; RUNNING/QUEUED rows are kept whatever their age; symlinked entries are never followed."""
        cutoff = time.time() - RETENTION_DAYS * 86400
        try:
            entries = list(JOB_ROOT.iterdir())
        except OSError:
            return
        for d in entries:
            try:
                if d.is_symlink() or not d.is_dir() or d.stat().st_mtime > cutoff:
                    continue
                job = self._store.get(d.name)
                if job is not None and job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
                    continue
                _rm_job_dir(d)
                logger.info("retention: removed job dir %s (%s)", d.name, "no row" if job is None else job.status.value)
            except Exception:  # noqa: BLE001 — one odd entry must not stop the sweep
                logger.warning("retention: could not sweep %s", d, exc_info=True)

    def _sweep_loop(self) -> None:
        while not self._stop.is_set():
            self._sweep_job_root()
            self._stop.wait(SWEEP_S)

    def run(self) -> None:
        self._recover_orphans()
        threading.Thread(target=self._sweep_loop, name="retention", daemon=True).start()
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
