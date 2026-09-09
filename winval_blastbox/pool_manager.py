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
import math
import os
import shutil
import signal
import stat
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from blastbox.host.jobs.base import JobStatus
from blastbox.host.jobs.factory import build_job_store_from_env

from .host_runner import HostRunner
from .vm_pool import pool_size

logger = logging.getLogger("winval.pool_manager")

JOB_ROOT = Path(os.environ.get("WINVAL_JOB_ROOT", "/var/lib/winval/jobs"))
# The pool-manager's OWN scratch root (mode 0700, this uid): the engine reads its input copy from and
# writes its sealed output into a tree the ingress cannot touch; results are then PUBLISHED into
# <job>/output by directory descriptor with O_EXCL (see _publish). Never place it under WINVAL_JOB_ROOT.
WORK_ROOT = Path(os.environ.get("WINVAL_WORK_ROOT", "/var/lib/winval/work"))
SWEEP_S = 3600.0
# The same bound the ingress enforces on an upload (AUTHENTICODE_MAX_UPLOAD_MB): a compromised ingress can
# spool ANY size, and the copy into WORK_ROOT must not be how the manager's disk is exhausted
MAX_INPUT_BYTES = int(os.environ.get("AUTHENTICODE_MAX_UPLOAD_MB", "1024") or "1024") * 1024 * 1024


def _retention_days() -> float:
    """WINVAL_JOB_RETENTION_DAYS: days a finished (or rowless) job directory is kept; 0 (or less) DISABLES
    the sweep — blastbox's own convention for its retention knob — and an unparsable value is a warning
    plus the default, never a crash at import that latches the unit failed. Below one day is raised to one:
    the scratch trees under WORK_ROOT have no liveness guard but their age, and a validation can run long."""
    raw = os.environ.get("WINVAL_JOB_RETENTION_DAYS", "7").strip()
    try:
        days = float(raw or "7")
        if not math.isfinite(days):   # 'nan' passes float() and every comparison below: it would sweep EVERYTHING
            raise ValueError(raw)
    except ValueError:
        logger.warning("WINVAL_JOB_RETENTION_DAYS=%r is not a number of days: using 7", raw)
        return 7.0
    if 0 < days < 1:
        logger.warning("WINVAL_JOB_RETENTION_DAYS=%r is below one day: using 1 (a running validation's scratch tree is protected only by its age)", raw)
        return 1.0
    return days


_pool_size = pool_size   # ONE reader for both the warm size (vm_pool.authenticode_spec) and the claim concurrency


def _rel_parts(p: Path, what: str, root: Path = JOB_ROOT) -> tuple:
    """The components of p below root, LEXICALLY (abspath collapses '..'); nothing here touches the
    filesystem. Every open that follows is done component by component from a descriptor on root
    (_open_under), so there is no path for the ingress to swap between a check and its use."""
    ap = Path(os.path.abspath(p))
    for base in (Path(os.path.abspath(root)), root.resolve()):
        if ap.is_relative_to(base):
            parts = ap.relative_to(base).parts
            if not parts:
                raise ValueError(f"{what} is {root} itself")
            return parts
    raise ValueError(f"{what} escapes {root}: {p}")


_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


def _open_under(root: Path, parts, what: str) -> int:
    """A descriptor on root/parts reached by openat per component with O_NOFOLLOW|O_DIRECTORY. The ingress
    owns job_root and everything below it: a link in ANY component fails here (a path-based open would
    re-resolve the intermediate <job> component, which the ingress can rename away and replace with a
    link to any host directory between a check and the open), and a component swapped after this walk
    cannot matter — the descriptor pins the directory that was walked. root's own parent is root-owned."""
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts:
            nfd = os.open(part, _DIR, dir_fd=fd)
            os.close(fd)
            fd = nfd
        return fd
    except OSError as exc:
        os.close(fd)
        raise ValueError(f"{what}: {root / Path(*parts)}: {exc.strerror}") from exc


def _copy_tree_into(src_dir: Path, dst_fd: int) -> None:
    """Every entry of the manager's own scratch output (nested artifacts too, as blastbox's envelope allows)
    created O_EXCL|O_NOFOLLOW relative to a descriptor on a directory this process made and owns."""
    for e in sorted(os.scandir(src_dir), key=lambda e: e.name):
        if e.is_symlink():
            continue
        if e.is_dir(follow_symlinks=False):
            os.mkdir(e.name, 0o755, dir_fd=dst_fd)
            sub = os.open(e.name, _DIR, dir_fd=dst_fd)
            try:
                _copy_tree_into(Path(e.path), sub)
            finally:
                os.close(sub)
        elif e.is_file(follow_symlinks=False):
            ofd = os.open(e.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=dst_fd)
            with open(ofd, "wb") as out, open(e.path, "rb") as src:
                shutil.copyfileobj(src, out)


def _publish(src_dir: Path, job_fd: int, what: str) -> None:
    """Copy the sealed output from the manager's own scratch tree into <job>/output, everything relative to
    the pinned <job> descriptor: the directory is CREATED here (anything already there is refused),
    verified by descriptor to be ours, and every file is created O_EXCL|O_NOFOLLOW under it."""
    os.mkdir("output", 0o755, dir_fd=job_fd)   # EEXIST: the ingress planted an output entry (or a link) -> refuse to write into it
    fd = os.open("output", _DIR, dir_fd=job_fd)
    try:
        if os.fstat(fd).st_uid != os.geteuid():
            raise PermissionError(f"{what}: output is not owned by this process")
        _copy_tree_into(src_dir, fd)
    finally:
        os.close(fd)


def _rm_tree_fd(fd: int) -> None:
    """Empty the directory behind fd, every unlink and rmdir by NAME relative to a descriptor: a path
    reassembled during the walk was re-resolved by the kernel at unlink time, and a subdirectory the
    ingress swapped for a link mid-walk made root unlink through it."""
    for e in os.scandir(fd):
        if e.is_dir(follow_symlinks=False):
            sub = os.open(e.name, _DIR, dir_fd=fd)
            try:
                _rm_tree_fd(sub)
            finally:
                os.close(sub)
            try:
                os.rmdir(e.name, dir_fd=fd)
            except NotADirectoryError:   # swapped for a link since the listing: remove the LINK, never what it names
                os.unlink(e.name, dir_fd=fd)
        else:
            os.unlink(e.name, dir_fd=fd)


def _rm_job_dir(d: Path, root: Path = JOB_ROOT) -> None:
    """Remove one job directory tree under root by descriptors, never following a link anywhere."""
    parts = _rel_parts(d, "job dir", root)
    parent = _open_under(root, parts[:-1], "job dir")
    try:
        fd = os.open(parts[-1], _DIR, dir_fd=parent)
        try:
            _rm_tree_fd(fd)
        finally:
            os.close(fd)
        os.rmdir(parts[-1], dir_fd=parent)
    finally:
        os.close(parent)


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
        self._concurrency = _pool_size()

    def _process(self, job) -> None:
        """Validate one claimed job and write its verdict back (CAS-fenced on the claim)."""
        # job.filename / job.result_dir come from the shared, ingress-writable job store, and this
        # manager runs as root. The ingress owns <job>/ outright, so NO path under it is trusted twice:
        # <job> is reached by openat per component (_open_under) and pinned as a descriptor, the spooled
        # input is opened O_NOFOLLOW relative to it, copied into this process's own scratch tree
        # (WORK_ROOT), validated there, and the sealed output is published back relative to the same
        # descriptor (_publish). A traversal in filename, a link in any component, a planted
        # output/metadata.json link — all fail the job by name; nothing reaches a host file.
        job_fd = None
        in_dirfd = None
        in_fd = None
        work = None
        recorded = False   # whether a terminal status reached the store: only then is the spooled input consumed
        try:
            # INSIDE the guard: a hostile row is exactly what the sanitiser exists for, and raising
            # outside it ended the claim thread for the life of the process (the unit stayed "active")
            filename = Path(job.filename or "").name
            if not filename or filename in (".", ".."):
                raise ValueError(f"job {job.job_id}: empty/invalid filename")
            what = f"job {job.job_id}: result_dir"
            job_fd = _open_under(JOB_ROOT, _rel_parts(Path(job.result_dir or ""), what), what)
            try:
                in_dirfd = os.open("input", _DIR, dir_fd=job_fd)
                # O_NONBLOCK: a FIFO the ingress mkfifo'd here (no capability needed) would otherwise park this
                # claim thread in open(2) until a writer appeared — forever — and the type check below never ran
                in_fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=in_dirfd)
            except FileNotFoundError:
                raise FileNotFoundError(f"spooled input missing: {Path(job.result_dir) / 'input' / filename}") from None
            st = os.fstat(in_fd)
            if st.st_size > MAX_INPUT_BYTES:
                raise ValueError(f"job {job.job_id}: spooled input is {st.st_size} bytes, over the {MAX_INPUT_BYTES}-byte upload bound")
            if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                # a hard link to a root-owned file would pass O_NOFOLLOW and S_ISREG (fs.protected_hardlinks
                # forbids the ingress making one, but that is a per-host sysctl this code cannot assert)
                raise ValueError(f"job {job.job_id}: spooled input is not a plain regular file")
            work = Path(tempfile.mkdtemp(prefix="job.", dir=WORK_ROOT))
            (work / "input").mkdir(0o700)
            (work / "output").mkdir(0o700)
            with open(in_fd, "rb", closefd=False) as src, open(work / "input" / filename, "wb") as dst:
                copied = 0
                while True:   # bounded by BYTES, not by the size fstat saw: the ingress can still be appending
                    chunk = src.read(1 << 20)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > MAX_INPUT_BYTES:
                        raise ValueError(f"job {job.job_id}: spooled input grew past the {MAX_INPUT_BYTES}-byte upload bound while being copied")
                    dst.write(chunk)
            env = self._runner.validate_to_dir(work / "input" / filename, work / "output")
            summary = _extract_verdict(env)
            status = (JobStatus.FAILED if summary.get("envelope_status") == "engine_error"
                      else JobStatus.DONE)
            recorded = bool(self._store.update_if_status(
                job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                status=status, finished_at=time.time(), result_summary=summary,
                worker_runtime="vm"))
            if not recorded:
                # the CAS lost: the row is no longer RUNNING under this claim (a restart's orphan recovery
                # marked it FAILED, or another claimant took it). Nothing is published and the spooled
                # input is KEPT, so an operator can still act on the sample
                logger.warning("job %s: verdict NOT recorded — the row was no longer RUNNING under claim %s; output not published, input kept", job.job_id, job.claim_id)
            else:
                try:   # the verdict is in the row; the on-disk copy is a keepsake, and a refused publish is a warning by name
                    _publish(work / "output", job_fd, f"job {job.job_id}: output")
                except (OSError, ValueError) as exc:
                    logger.warning("job %s: sealed output NOT published to %s (%s); the verdict is recorded in the store",
                                   job.job_id, Path(job.result_dir) / "output", exc)
        except Exception as exc:  # noqa: BLE001 — one bad job must not sink the manager
            logger.warning("job %s failed: %s", job.job_id, exc, exc_info=True)
            try:   # the recovery write uses the same store that may have just failed (a Postgres restart): it must not escape either
                recorded = bool(self._store.update_if_status(
                    job.job_id, JobStatus.RUNNING, expect_claim_id=job.claim_id,
                    status=JobStatus.FAILED, finished_at=time.time(), error=type(exc).__name__))
                if not recorded:
                    logger.warning("job %s: failure NOT recorded — the row was no longer RUNNING under claim %s; input kept", job.job_id, job.claim_id)
            except Exception:  # noqa: BLE001
                # there is NO store-side reaper for RUNNING jobs (blastbox's retention never touches them): the row
                # stays RUNNING until the next pool-manager start recovers it (_recover_orphans), and the spooled
                # input is KEPT so that recovery — or an operator — can still act on the sample
                logger.warning("job %s: could not record the failure; the row stays RUNNING until the next pool-manager start recovers it", job.job_id, exc_info=True)
        finally:
            if in_fd is not None:
                os.close(in_fd)
            if in_dirfd is not None:
                if in_fd is not None and recorded:
                    try:  # the sample is consumed; drop the spooled input BY NAME in the pinned directory (keep the sealed output)
                        os.unlink(filename, dir_fd=in_dirfd)
                    except OSError:
                        pass
                os.close(in_dirfd)
            if job_fd is not None:
                os.close(job_fd)
            if work is not None:
                try:
                    _rm_job_dir(work, WORK_ROOT)
                except (OSError, ValueError):
                    logger.warning("job %s: scratch tree %s not removed (retention will)", job.job_id, work, exc_info=True)

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
                    if name and name not in (".", ".."):
                        try:
                            job_fd = _open_under(JOB_ROOT, _rel_parts(Path(job.result_dir or ""), "orphan result_dir"), "orphan result_dir")
                            try:
                                in_fd = os.open("input", _DIR, dir_fd=job_fd)
                                try:
                                    os.unlink(name, dir_fd=in_fd)
                                finally:
                                    os.close(in_fd)
                            finally:
                                os.close(job_fd)
                        except (OSError, ValueError):
                            pass
            except Exception:  # noqa: BLE001
                logger.warning("orphan recovery: job %s could not be updated", job.job_id, exc_info=True)

    def _sweep_job_root(self) -> None:
        """Retention for WINVAL_JOB_ROOT (nothing else has any): a job directory older than the retention
        whose row is terminal — or has no row at all (an upload the ingress rejected after mkdir) — is
        removed; RUNNING/QUEUED rows are kept whatever their age; symlinked entries are never followed.
        Scratch trees a crash left under WORK_ROOT age out the same way. Retention 0 disables the sweep."""
        days = _retention_days()
        if days <= 0:
            return
        cutoff = time.time() - days * 86400
        for root in (JOB_ROOT, WORK_ROOT):
            try:
                entries = list(root.iterdir())
            except OSError:
                continue
            for d in entries:
                self._sweep_one(d, root, cutoff)

    def _sweep_one(self, d: Path, root: Path, cutoff: float) -> None:
        try:
            if d.is_symlink() or not d.is_dir() or d.stat().st_mtime > cutoff:
                return
            job = self._store.get(d.name) if root == JOB_ROOT else None
            if job is not None and job.status in (JobStatus.QUEUED, JobStatus.RUNNING):
                return
            _rm_job_dir(d, root)
            logger.info("retention: removed %s (%s)", d, "no row" if job is None else job.status.value)
        except Exception:  # noqa: BLE001 — one odd entry must not stop the sweep
            logger.warning("retention: could not sweep %s", d, exc_info=True)

    def _sweep_loop(self) -> None:
        while not self._stop.is_set():
            self._sweep_job_root()
            self._stop.wait(SWEEP_S)

    def run(self) -> None:
        wr, jr = Path(os.path.abspath(WORK_ROOT)), Path(os.path.abspath(JOB_ROOT))
        wrr, jrr = wr.resolve(), jr.resolve()   # lexically AND through links: a job root symlinked into the scratch root is one directory tree
        if wr == jr or wr.is_relative_to(jr) or jr.is_relative_to(wr) or wrr == jrr or wrr.is_relative_to(jrr) or jrr.is_relative_to(wrr):
            # the JOB_ROOT sweep would otherwise remove the scratch root as a rowless job dir, and an ingress
            # result_dir could name a directory inside the manager's own scratch tree
            raise SystemExit(f"WINVAL_WORK_ROOT {WORK_ROOT} and WINVAL_JOB_ROOT {JOB_ROOT} must be disjoint")
        WORK_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
        if WORK_ROOT.is_symlink() or WORK_ROOT.stat().st_uid != os.geteuid():
            raise SystemExit(f"WINVAL_WORK_ROOT {WORK_ROOT} must be a directory owned by this process (uid {os.geteuid()})")
        os.chmod(WORK_ROOT, 0o700)
        self._recover_orphans()
        threading.Thread(target=self._sweep_loop, name="retention", daemon=True).start()
        logger.info("warming VM pool (%d workers)…", self._concurrency)
        try:
            try:
                self._runner.warmup(stop_event=self._stop)   # a SIGTERM during the warm-up ends it (and reaps) instead of waiting out the warm timeout
            except RuntimeError as exc:
                if self._stop.is_set():   # the operator's stop, not a failure: exit 0, or the unit latches `failed` and the rotator's restart_pool() resurrects a deliberately stopped manager
                    logger.info("stop requested during the warm-up: %s", exc)
                    return
                raise
            logger.info("pool warm; claiming jobs from %s", type(self._store).__name__)
            with ThreadPoolExecutor(max_workers=self._concurrency, thread_name_prefix="claim") as ex:
                for _ in range(self._concurrency):
                    ex.submit(self._worker_loop)
                self._stop.wait()  # block until SIGTERM/SIGINT
        finally:
            self._runner.shutdown()   # on EVERY exit, a failed warm-up included: whatever workers exist are destroyed
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
