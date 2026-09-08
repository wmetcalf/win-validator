"""Rolling golden refresh + validation-gated rotation, with backup retention.

NOT a temporal-trust ladder: workers sync REAL time + do LIVE CRL on restore, so they always validate
against NOW. This keeps the golden FRESH (re-bake its trust state — disallowed kill-list, CRL/OCSP
cache, trusted roots/CTL via `myatg.exe --refresh`) and keeps the last N known-good goldens as
ROLLBACK backups. The point is fail-safe rebakes: a candidate is promoted to the live `golden-base`
ONLY if it passes a benign+revoked validation gate; otherwise the current golden is kept and the
failure is surfaced — so a bad bake (the WU-wedge / corruption scenarios) never silently ships.

  build_candidate()  master -> overlay clone -> refresh trust state -> flatten -> candidate.qcow2
  validate_golden()  boot a worker off a qcow2 -> assert benign==Valid AND revoked==Revoked
  rotate()           backup current base (keep last N) -> promote candidate -> base

CLI:
  python golden_rotate.py refresh-and-rotate          # the full gated cycle (cron this)
  python golden_rotate.py validate <golden.qcow2>     # just run the gate
  python golden_rotate.py rotate <candidate.qcow2>    # just promote+backup (already validated)
"""
from __future__ import annotations

import base64
import json
import shutil
import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger("winval.golden_rotate")

def _load_env_file(path: str) -> None:
    """Read the units' EnvironmentFile the way systemd does (KEY=VALUE, # comments, optional
    quotes) and apply it to any variable NOT already in the environment — so a hand-run
    `sudo … golden_rotate.py` (sudo's env_reset strips every exported GOLDEN_*/AUTHENTICODE_*
    override) sees the SAME paths the timer's rotation used, instead of the defaults."""
    try:
        lines = Path(path).read_text().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        k = k.strip()
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        if k and k not in os.environ:
            os.environ[k] = v


_load_env_file(os.environ.get("WINVAL_ENV_FILE", "/etc/winval/winval.env"))

MASTER_DOMAIN = os.environ.get("GOLDEN_MASTER_DOMAIN", "winserver2025-core")
MASTER_QCOW2 = os.environ.get("GOLDEN_MASTER", "/var/lib/libvirt/images/winserver2025-core.qcow2")
# ONE name for the RAM base, the pool's (winval_blastbox/vm_pool.py + the pool-manager unit read
# AUTHENTICODE_GOLDEN_BASE): a rotation that promoted to a different path than the pool boots from
# would log "PROMOTED" every night and never reach a job. GOLDEN_BASE is kept as a legacy alias.
GOLDEN_BASE = (os.environ.get("AUTHENTICODE_GOLDEN_BASE") or os.environ.get("GOLDEN_BASE")
               or "/dev/shm/golden-base.qcow2")
GOLDEN_BASE_DISK = os.environ.get("GOLDEN_BASE_DISK", "/var/lib/libvirt/images/golden-base.qcow2")
BACKUP_DIR = Path(os.environ.get("GOLDEN_BACKUP_DIR", "/var/lib/libvirt/images/golden-backups"))
KEEP_N = int(os.environ.get("GOLDEN_KEEP_N", "5"))
CANDIDATE_KEEP_DAYS = int(os.environ.get("GOLDEN_CANDIDATE_KEEP_DAYS", "7"))
SSH_KEY = os.environ.get("AUTHENTICODE_SSH_KEY", "/etc/winval/win_golden")
GRAVEYARD = os.environ.get("GOLDEN_GRAVEYARD", "C:\\certgraveyard\\cert_graveyard_database.csv")
BENIGN = os.environ.get("GOLDEN_BENIGN_SAMPLE", "/var/lib/winval/samples/whoami.exe")
REVOKED = os.environ.get("GOLDEN_REVOKED_SAMPLE", "")  # optional; checks status==Revoked when set
WARM_DIR = os.environ.get("GOLDEN_WARM_DIR", "")        # optional in-guest dir of certs to re-warm

_SSH = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=15", "-i", SSH_KEY]


def _run(a: list[str], t: float = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=t)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(a, 124, "", "timeout")


def _virsh(*a: str, t: float = 120) -> subprocess.CompletedProcess:
    return _run(["sudo", "virsh", *a], t)


def _ssh_ps(ip: str, ps: str, t: float = 300, check: bool = False) -> str:
    """Run PowerShell in the guest; with ``check`` a non-zero exit (or a timeout) RAISES with the
    guest's stderr — a step whose failure must not be mistaken for success."""
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    r = _run(["ssh", "-n", *_SSH, f"Administrator@{ip}",
              "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + enc], t)
    if check and r.returncode != 0:
        raise RuntimeError(f"in-guest step failed (rc={r.returncode}): {r.stderr.strip()[-500:] or r.stdout.strip()[-500:]}")
    return r.stdout.strip()


class NothingPublished(RuntimeError):
    """A rotation that changed NOTHING (lock held, not root, no space, a copy failed before any
    rename): the candidate is still good and `golden_rotate.py rotate <candidate>` can retry it."""


def refresh_ps(gv: str = "", warm: str = "") -> str:
    """The in-guest trust refresh as PowerShell that FAILS HARD (a non-zero myatg exit, JSON that
    does not parse) and then prints myatg's JSON itself, for refresh_result() to judge — never a
    formatted line whose literals an empty result would still render."""
    return ("$ErrorActionPreference = 'Stop'; "
            f"$raw = & C:\\agent\\myatg.exe --refresh {gv}; "
            "if ($LASTEXITCODE -ne 0) { Write-Error (\"myatg --refresh exited $LASTEXITCODE\"); exit 3 }; "
            "$txt = ($raw -join [Environment]::NewLine); "
            "$j = $txt | ConvertFrom-Json; "
            f"{warm} "
            "$txt")


def refresh_result(out: str) -> dict:
    """Judge myatg --refresh by the fields that report SUCCESS (myatg.cs RefreshTrust): roots_synced
    (certutil -syncWithWU completed) and disallowed_kill_list_installed (the fetched kill list was
    added to the Disallowed store) are booleans; disallowed_store_count is a census of the store
    and only proves it is non-empty. Anything else is a failed refresh — the base's stale trust
    state would validate the benign sample just as well, so the gate cannot catch it later."""
    try:
        j = json.loads(out or "")
    except ValueError as e:
        raise RuntimeError(f"in-guest refresh printed no JSON ({e}); candidate discarded, golden unchanged") from e
    if not isinstance(j, dict):
        raise RuntimeError(f"in-guest refresh printed {type(j).__name__}, not an object; candidate discarded, golden unchanged")
    problems = []
    if j.get("roots_synced") is not True:
        problems.append("roots_synced is not true (certutil -syncWithWU did not complete)")
    if j.get("disallowed_kill_list_installed") is not True:
        problems.append("disallowed_kill_list_installed is not true (no kill list was fetched/installed)")
    if not isinstance(j.get("disallowed_store_count"), int) or j["disallowed_store_count"] < 1:
        problems.append(f"disallowed_store_count={j.get('disallowed_store_count')!r}")
    if problems:
        raise RuntimeError("in-guest refresh FAILED: " + "; ".join(problems) + "; candidate discarded, golden unchanged")
    return j


def _free_beside(path: str) -> int:
    return shutil.disk_usage(Path(path).parent).free


def _existing_ancestor(path: str) -> Path:
    p = Path(path)
    while not p.exists() and p.parent != p:
        p = p.parent
    return p


def rotation_preflight(estimate_bytes: int | None = None) -> None:
    """Everything the cycle will need, checked BEFORE the hour-long build and gate: root (the
    lock lives in root-owned /run and every publish step is sudo), a usable lock, the gate's
    samples, and space for the run's PEAK — the candidate the build writes into the backup dir,
    a temporary copy beside EACH base (staged until the rename) and the backup of the current
    golden, all alive at once. Requirements are summed PER FILESYSTEM (the disk base and the
    backup dir normally share one), so the shipped defaults need 3x the image there, not 2x.
    The estimate is the larger of the current golden and the master, or the caller's (the
    build entry point passes its own base); with nothing to estimate from, refuse rather than
    pass a full disk. Raises NothingPublished."""
    if os.geteuid() != 0:
        raise NothingPublished("rotation must run as root (sudo): the rotation lock lives in /run and every publish step is privileged")
    try:
        fd = os.open(ROTATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise NothingPublished(f"cannot open the rotation lock {ROTATE_LOCK} ({e.strerror})") from e
    os.close(fd)
    if not BENIGN or not Path(BENIGN).is_file():   # the gate ALWAYS validates the benign sample
        raise NothingPublished(f"GOLDEN_BENIGN_SAMPLE={BENIGN!r} is not a file: the gate could not run, so the build would be wasted")
    if REVOKED and not Path(REVOKED).is_file():
        raise NothingPublished(f"GOLDEN_REVOKED_SAMPLE={REVOKED} does not exist: the gate could not run, so the build would be wasted")
    if estimate_bytes is None:
        estimate_bytes = max((Path(p).stat().st_size for p in (GOLDEN_BASE_DISK, MASTER_QCOW2) if Path(p).exists()), default=0)
    if estimate_bytes <= 0:
        raise NothingPublished(f"cannot size the run: neither {GOLDEN_BASE_DISK} nor {MASTER_QCOW2} exists (set GOLDEN_MASTER, or pass the base's size)")
    need = estimate_bytes
    # peak per filesystem: candidate + backup in BACKUP_DIR, one temporary beside each base
    demands = [(str(BACKUP_DIR), 2 * need, "candidate + backup in the backup dir"),
               (str(Path(GOLDEN_BASE_DISK).parent), need, "temporary beside the disk base"),
               (str(Path(GOLDEN_BASE).parent), need, "temporary beside the RAM base")]
    per_fs: dict = {}
    for path, amount, what in demands:
        anc = _existing_ancestor(path)
        dev = os.stat(anc).st_dev
        entry = per_fs.setdefault(dev, {"anc": anc, "need": 0, "what": []})
        entry["need"] += amount
        entry["what"].append(what)
    for dev, entry in per_fs.items():
        free = shutil.disk_usage(entry["anc"]).free
        if free < entry["need"]:
            raise NothingPublished(f"not enough space on the filesystem of {entry['anc']}: {free} free, {entry['need']} needed at the run's peak "
                                   f"({' + '.join(entry['what'])}; image estimate {need} bytes)")


def _mac(domain: str) -> str | None:
    for line in _virsh("domiflist", domain).stdout.splitlines():
        p = line.split()
        if len(p) >= 5 and ":" in p[-1]:
            return p[-1]
    return None


def _ensure_backup_dir() -> None:
    """Create the (root-owned) backup dir via sudo + make it world-readable so glob/prune work."""
    _run(["sudo", "mkdir", "-p", str(BACKUP_DIR)])
    _run(["sudo", "chmod", "755", str(BACKUP_DIR)])


def _ip_for_mac(mac: str) -> str | None:
    for line in _run(["ip", "neigh", "show", "dev", "virbr0"]).stdout.splitlines():
        p = line.split()
        if "lladdr" in p and p[0].startswith("192.168.122."):
            i = p.index("lladdr")
            if i + 1 < len(p) and p[i + 1].lower() == mac.lower():
                return p[0]
    return None


def build_candidate() -> str:
    """Clone the master, boot it, refresh the trust state in-guest, flatten -> a candidate qcow2.

    The refresh runs on an OVERLAY off the master so the master stays pristine; the flattened
    candidate carries master + the fresh disallowed-list / CRL cache / roots."""
    ts = _run(["date", "+%Y%m%d-%H%M%S"]).stdout.strip()
    dom = f"golden-cand-{ts}"
    overlay = f"/dev/shm/{dom}.qcow2"
    candidate = f"{BACKUP_DIR}/golden-base.candidate-{ts}.qcow2"
    _ensure_backup_dir()
    _virsh("destroy", dom)
    _virsh("undefine", dom, "--snapshots-metadata")
    _run(["sudo", "rm", "-f", overlay])
    logger.info("cloning master -> overlay %s", overlay)
    xml_path = f"/tmp/{dom}.xml"
    built = False
    try:   # from here every exit — a failed overlay, XML, define or start included — destroys the domain + overlay
        assert _run(["sudo", "qemu-img", "create", "-f", "qcow2", "-b", MASTER_QCOW2, "-F", "qcow2",
                     overlay], 120).returncode == 0, "overlay create failed"
        _run(["sudo", "chmod", "644", overlay])
        # define+boot the overlay domain (reuse the runtime's XML generator for a real worker shape)
        from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime
        rt = LibvirtVmRuntime(LibvirtVmConfig(golden_base=MASTER_QCOW2))
        Path(xml_path).write_text(rt._domain_xml(dom, overlay))
        assert _virsh("define", xml_path).returncode == 0, "define failed"
        assert _virsh("start", dom).returncode == 0, "start failed"
        mac = _mac(dom)
        ip, dl = None, time.time() + 240
        while time.time() < dl:
            ip = _ip_for_mac(mac) if mac else None
            if ip and "READY" in _ssh_ps(ip, "'READY'", 15):
                break
            time.sleep(5)
        assert ip, "candidate guest never reachable"
        logger.info("refreshing trust state in %s (myatg --refresh)…", ip)
        gv = f'--gv "{GRAVEYARD}"' if GRAVEYARD else ""
        warm = f'C:\\agent\\myatg.exe --warm-cache "{WARM_DIR}" {gv} | Out-Null;' if WARM_DIR else ""
        out = _ssh_ps(ip, refresh_ps(gv, warm), 600, check=True)
        j = refresh_result(out)   # the whole point of the rebake is FRESH trust state
        logger.info("refresh result: roots_synced=%s kill_list_installed=%s disallowed_store_count=%s",
                    j.get("roots_synced"), j.get("disallowed_kill_list_installed"), j.get("disallowed_store_count"))
        _ssh_ps(ip, "Stop-Computer -Force", 20)
        dl = time.time() + 180
        while time.time() < dl and "shut off" not in _virsh("domstate", dom).stdout:
            time.sleep(3)
        logger.info("flattening overlay -> candidate %s", candidate)
        assert _run(["sudo", "qemu-img", "convert", "-O", "qcow2", overlay, candidate], 900).returncode == 0
        _run(["sudo", "chmod", "644", candidate])
        built = True
    finally:
        _virsh("destroy", dom)
        _virsh("undefine", dom, "--snapshots-metadata")
        _run(["sudo", "rm", "-f", overlay, xml_path])
        if not built:
            # a convert that failed or timed out leaves a full-size partial candidate in the
            # backup dir; _prune_backups deliberately never touches candidates, so nothing else
            # would ever reclaim it and each failed nightly rebake would keep one image of space
            _run(["sudo", "rm", "-f", candidate])
    return candidate


def validate_golden(qcow2: str) -> bool:
    """Boot a throwaway worker off ``qcow2`` and assert the validation gate: a benign signed sample
    is Valid AND (if configured) a known-revoked sample is Revoked. False if the worker won't boot,
    the agent won't answer, or any verdict is wrong — i.e. a broken/regressed golden is rejected."""
    from winval_blastbox.vm_pool import agent_validate
    from blastbox.host.runtime.vm_compose import VmImageSpec, VmWorkerSpec
    spec = VmWorkerSpec(name="goldgate", image=VmImageSpec(golden=qcow2), agent_port=8765)
    rt = spec.runtime()
    try:
        slot = rt.spawn_ready(timeout_s=240)
    except Exception as exc:
        logger.error("GATE FAIL: candidate %s did not boot a healthy worker: %s", qcow2, exc)
        return False
    try:
        checks = [(BENIGN, "Valid")]
        if REVOKED:
            checks.append((REVOKED, "Revoked"))
        for sample, want in checks:
            try:
                got = agent_validate(slot.endpoint, sample).get("status")
            except Exception as exc:
                logger.error("GATE FAIL: agent_validate(%s) raised: %s", sample, exc)
                return False
            logger.info("gate: %s -> %s (want %s)", Path(sample).name, got, want)
            if got != want:
                logger.error("GATE FAIL: %s gave %r, expected %r", sample, got, want)
                return False
        logger.info("GATE PASS: candidate %s validated", qcow2)
        return True
    finally:
        rt.reap(slot)


# under /run (root-owned 0755), NOT /run/lock (1777, sticky): a lock file any local user can
# create is a lock any local user can hold forever, blocking every rotation with a message
# that blames a concurrent run — and with fs.protected_regular root cannot even open it
ROTATE_LOCK = os.environ.get("GOLDEN_ROTATE_LOCK", "/run/winval-golden-rotate.lock")


def rotate(candidate: str) -> None:
    """Back up the current live golden (keep the last N), then promote ``candidate`` into place.

    ONE rotation at a time: the timer's rotate and a manual ``golden_build.py build-and-promote``
    (or two manual runs) must not overlap — two promotions would race on the same bases and
    _sweep_own_temps would unlink the other's copy in flight. A held lock fails FAST, it never
    queues: the second caller reports and exits, the first finishes."""
    import fcntl
    c = Path(candidate)
    if c.is_symlink() or not c.is_file():   # BEFORE the lock and before an hour-long backup copy
        raise RuntimeError(f"candidate {candidate} is not a regular file; golden NOT promoted (nothing published, no backup taken)")
    try:
        lock_fd = os.open(ROTATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as e:
        raise NothingPublished(f"cannot open the rotation lock {ROTATE_LOCK} ({e.strerror}); golden NOT promoted (nothing published)") from e
    try:
        st = os.fstat(lock_fd)
        if st.st_uid != os.geteuid():
            raise NothingPublished(f"rotation lock {ROTATE_LOCK} is owned by uid {st.st_uid}, not by this process; refusing to rotate")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as e:
            raise NothingPublished(f"another rotation is in progress (lock {ROTATE_LOCK} held); golden NOT promoted (nothing published)") from e
        _rotate_locked(candidate)
    finally:
        os.close(lock_fd)   # releases the lock with the descriptor


def _rotate_locked(candidate: str) -> None:
    _ensure_backup_dir()
    try:
        _promote(candidate)
    finally:
        _prune_backups()   # on EVERY outcome


def _backup_current() -> str | None:
    """A CHECKED copy of the live golden into the backup dir (None when there is no golden yet).
    Taken only once a promotion is about to publish — a rotation that publishes nothing must not
    add a full-size copy of the unchanged golden that then evicts a genuinely older rollback
    backup. This backup is what a rollback restores from, what _prune_backups keeps as a
    known-good golden, and what the pool-manager's ExecStartPre copies into RAM after a reboot —
    a truncated one (a timeout, ENOSPC) would pass all three, so rc AND size are checked."""
    if not Path(GOLDEN_BASE_DISK).exists():
        return None
    ts = _run(["date", "+%Y%m%d-%H%M%S"]).stdout.strip()
    bak = BACKUP_DIR / f"golden-base.{ts}.qcow2"
    logger.info("backing up current golden -> %s", bak)
    want = Path(GOLDEN_BASE_DISK).stat().st_size
    r = _run(["sudo", "cp", "--reflink=auto", GOLDEN_BASE_DISK, str(bak)], 3600)
    got = bak.stat().st_size if bak.exists() else -1
    if r.returncode != 0 or got != want:
        _run(["sudo", "rm", "-f", str(bak)])
        raise NothingPublished(f"backup of the current golden -> {bak} failed (rc={r.returncode}, {got} of {want} bytes); "
                               f"golden NOT promoted (nothing published, no backup kept)")
    return str(bak)


TMP_TAG = ".rot."   # rotator temporaries: <base>.rot.XXXXXX — a namespace the pool-manager unit's
                    # stale-temp sweep (<base>.??????) never matches, so a start during a rotation
                    # cannot unlink a copy in flight


def _sweep_own_temps() -> None:
    """Remove stale rotator temporaries a killed rotation left beside either base (the rotate
    unit is a single oneshot, so no rotation is in flight when this runs)."""
    for base in (GOLDEN_BASE_DISK, GOLDEN_BASE):
        for t in Path(base).parent.glob(Path(base).name + TMP_TAG + "??????"):
            if t.is_file() and not t.is_symlink():
                logger.info("removing stale temporary %s", t)
                _run(["sudo", "rm", "-f", str(t)])


def _mktemp(beside: str) -> str:
    r = _run(["sudo", "mktemp", f"{beside}{TMP_TAG}XXXXXX"])
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(f"could not create a temporary beside {beside} (rc={r.returncode})")
    return r.stdout.strip()


def _checked_copy(src: str, dst_tmp: str, want: int, what: str) -> None:
    """cp + rc/size check + the 0644 the rest of the codebase assumes (mktemp creates 0600 and
    cp onto an existing file keeps the existing mode); raises with nothing published."""
    r = _run(["sudo", "cp", "--reflink=auto", src, dst_tmp], 3600)
    got = Path(dst_tmp).stat().st_size if Path(dst_tmp).exists() else -1
    if r.returncode != 0 or got != want:
        raise RuntimeError(f"{what} -> {dst_tmp} failed (rc={r.returncode}, {got} of {want} bytes)")
    c = _run(["sudo", "chmod", "644", dst_tmp])
    if c.returncode != 0 or (Path(dst_tmp).stat().st_mode & 0o777) != 0o644:
        raise RuntimeError(f"{what} -> {dst_tmp}: could not set mode 0644 (rc={c.returncode})")


def _promote(candidate: str) -> None:
    logger.info("promoting candidate -> %s (+ %s)", GOLDEN_BASE_DISK, GOLDEN_BASE)
    # ALL OR NOTHING. Both copies land in mktemp temporaries and are CHECKED (rc, size, mode —
    # _run() swallows a timeout into rc=124, ENOSPC is rc=1) before either is published; then
    # two renames (mv -T), disk first. A copy that fails removes both temporaries and raises
    # with nothing published. The one remaining gap — the RAM rename failing after the disk
    # rename — is rolled back from the backup taken above, and reported as what it is.
    #
    # /dev/shm IS WORLD-WRITABLE (sticky): a fixed temp name there is a symlink another local
    # user can plant for root's cp to write through. Every temporary is created by mktemp as
    # root (O_EXCL — never a symlink; the sticky bit stops anyone else replacing it), and each
    # rename is mv -T, so a directory or symlink someone left at a base path is a FAILURE,
    # never a destination. The same refusal the pool-manager's ExecStartPre applies.
    want = Path(candidate).stat().st_size
    for base in (GOLDEN_BASE_DISK, GOLDEN_BASE):
        if Path(base).is_symlink() or Path(base).is_dir():
            raise RuntimeError(f"refusing to promote: {base} is a symlink or a directory, not a regular file; golden NOT promoted")
    _sweep_own_temps()
    for base in (GOLDEN_BASE_DISK, GOLDEN_BASE):
        if _free_beside(base) < want:
            raise NothingPublished(f"not enough space beside {base}: {_free_beside(base)} free, {want} needed for the temporary copy; golden NOT promoted (nothing published)")
    tmps: list[str] = []
    def _cleanup_tmps() -> None:
        for t in tmps:
            _run(["sudo", "rm", "-f", t])
    try:
        for base in (GOLDEN_BASE_DISK, GOLDEN_BASE):
            tmps.append(_mktemp(base))
            _checked_copy(candidate, tmps[-1], want, "promotion copy")
    except BaseException as e:
        _cleanup_tmps()
        raise NothingPublished(f"{e}; golden NOT promoted (nothing published)") from e
    try:
        bak = _backup_current()   # only now: both copies are in place and the publish is next
    except BaseException:
        _cleanup_tmps()
        raise
    r = _run(["sudo", "mv", "-fT", tmps[0], GOLDEN_BASE_DISK])
    if r.returncode != 0:
        _cleanup_tmps()
        raise NothingPublished(f"promotion rename -> {GOLDEN_BASE_DISK} failed (rc={r.returncode}); golden NOT promoted (nothing published)")
    r = _run(["sudo", "mv", "-fT", tmps[1], GOLDEN_BASE])
    if r.returncode == 0:
        return
    _cleanup_tmps()
    # SPLIT STATE: disk = new, RAM = old. Everything below must end in a message that says so —
    # a rollback step that itself fails (mktemp ENOSPC, a store gone read-only) must never
    # replace this diagnostic with "nothing published".
    how = "no backup exists to roll back from (nothing was backed up: no golden was on disk before)"
    if bak and Path(bak).exists():
        try:
            rbt = _mktemp(GOLDEN_BASE_DISK)
            try:
                _checked_copy(bak, rbt, Path(bak).stat().st_size, "rollback copy")
                rr = _run(["sudo", "mv", "-fT", rbt, GOLDEN_BASE_DISK])
                if rr.returncode != 0:
                    raise RuntimeError(f"rollback rename failed (rc={rr.returncode})")
            except BaseException:
                _run(["sudo", "rm", "-f", rbt])
                raise
            # rolled back = nothing changed: the candidate is still good (NothingPublished keeps it),
            # and the backup is now a byte-for-byte duplicate of the live golden — drop it, or it
            # would evict a genuinely older rollback generation in the prune
            _run(["sudo", "rm", "-f", bak])
            raise NothingPublished(f"promotion rename -> {GOLDEN_BASE} failed (rc={r.returncode}); the disk golden was ROLLED BACK "
                                   f"from {bak}; golden NOT promoted (nothing published)")
        except RuntimeError as e:
            if "ROLLED BACK" in str(e):
                raise
            how = (f"the automatic rollback from {bak} FAILED ({e}; the backup itself is intact) — "
                   f"restore the disk twin by hand: sudo cp {bak} {GOLDEN_BASE_DISK}")
        except Exception as e:  # anything unexpected in the rollback path: still report the split state
            how = (f"the automatic rollback from {bak} FAILED ({type(e).__name__}: {e}; the backup itself is intact) — "
                   f"restore the disk twin by hand: sudo cp {bak} {GOLDEN_BASE_DISK}")
    raise RuntimeError(f"promotion rename -> {GOLDEN_BASE} failed (rc={r.returncode}) AFTER the disk twin was published: "
                       f"DISK {GOLDEN_BASE_DISK} = new golden, RAM {GOLDEN_BASE} = old golden; {how}. "
                       f"Restart winval-pool-manager after clearing /dev/shm to enact the new golden instead.")


_BACKUP_NAME = re.compile(r"^golden-base\.\d{8}-\d{6}\.qcow2$")


def _prune_backups() -> None:
    # ONLY real backups (golden-base.<YYYYmmdd-HHMMSS>.qcow2) are counted and pruned: a
    # golden_rotate candidate (.candidate-<ts>), a golden_build image (.built-<ts>) or anything
    # else sharing the directory is neither kept as a rollback golden nor allowed to evict one
    # a candidate kept for a retry (NothingPublished) is reclaimed after CANDIDATE_KEEP_DAYS
    cutoff = time.time() - CANDIDATE_KEEP_DAYS * 86400
    for c in BACKUP_DIR.glob("golden-base.*.qcow2"):
        if (".candidate-" in c.name or ".built-" in c.name) and c.stat().st_mtime < cutoff:
            logger.info("pruning stale candidate %s", c.name)
            _run(["sudo", "rm", "-f", str(c)])
    baks = sorted(b for b in BACKUP_DIR.glob("golden-base.*.qcow2") if _BACKUP_NAME.match(b.name))
    excess = baks[:-KEEP_N] if KEEP_N > 0 else []
    for b in excess:
        logger.info("pruning old backup %s", b.name)
        _run(["sudo", "rm", "-f", str(b)])


def restart_pool() -> None:
    """Re-warm the pool off the freshly promoted golden: warm workers keep the OLD golden's inode
    open (the promotion is a rename) and are only ever snapshot-reverted, never respawned, so
    without this nothing puts the new trust state into service. Every promoting entry point
    calls it. GOLDEN_RESTART_SERVICE unset: say so loudly instead of claiming 'live'."""
    svc = os.environ.get("GOLDEN_RESTART_SERVICE")
    if svc:
        logger.info("restarting %s to warm off the refreshed golden", svc)
        r = _run(["sudo", "systemctl", "restart", svc], 600)
        if r.returncode != 0:
            logger.error("restart of %s FAILED (rc=%s): the pool is still running the OLD golden until it is restarted", svc, r.returncode)
    else:
        logger.warning("GOLDEN_RESTART_SERVICE is unset: the promoted golden is NOT in service until winval-pool-manager is restarted")


def refresh_and_rotate() -> int:
    """The full gated cycle: build a refreshed candidate, validate it, and ONLY promote if it passes.
    A failing gate keeps the current golden and returns non-zero (surfaced to the cron/alert)."""
    rotation_preflight()   # root, lock, space — BEFORE the hour-long build and gate
    candidate = build_candidate()
    if not validate_golden(candidate):
        logger.error("REBAKE REJECTED: keeping current golden %s; candidate %s discarded",
                     GOLDEN_BASE_DISK, candidate)
        _run(["sudo", "rm", "-f", candidate])
        return 1
    try:
        rotate(candidate)
    except NothingPublished as e:
        # nothing changed and the candidate is still gated-good: keep it for a retry instead of
        # throwing away the build and the gate boot (it is reclaimed after CANDIDATE_KEEP_DAYS)
        logger.error("%s — candidate KEPT at %s; retry with: sudo %s %s rotate %s", e, candidate, sys.executable, Path(__file__).resolve(), candidate)
        return 1
    except BaseException:
        _run(["sudo", "rm", "-f", candidate])
        raise
    _run(["sudo", "rm", "-f", candidate])
    restart_pool()
    logger.info("REBAKE PROMOTED: golden refreshed; %d backup(s) retained", KEEP_N)
    return 0


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cmd = argv[0] if argv else "refresh-and-rotate"
    if cmd == "refresh-and-rotate":
        return refresh_and_rotate()
    if cmd == "validate" and len(argv) > 1:
        return 0 if validate_golden(argv[1]) else 1
    if cmd == "rotate" and len(argv) > 1:
        rotate(argv[1])
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
