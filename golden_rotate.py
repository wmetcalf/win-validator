"""Rolling golden refresh + validation-gated rotation, with backup retention.

NOT a temporal-trust ladder: workers sync REAL time + do LIVE CRL on restore, so they always validate
against NOW. This keeps the golden FRESH (re-bake its trust state — disallowed kill-list, CRL/OCSP
cache, trusted roots/CTL via `myatg.exe --refresh`) and keeps the last N known-good goldens as
ROLLBACK backups. The point is fail-safe rebakes: a candidate is promoted to the live `golden-base`
ONLY if it passes a benign+revoked validation gate; otherwise the current golden is kept and the
failure is surfaced — so a bad bake (the WU-wedge / corruption scenarios) never silently ships.

  build_candidate()  a PRIVATE COPY of the promoted golden (GOLDEN_REBAKE_FROM=golden, the default)
                     -> overlay clone -> refresh trust state -> flatten -> candidate.qcow2
                     Every GOLDEN_MAX_CHAIN cycles (or GOLDEN_REBAKE_FROM=master) the cycle is
                     instead golden_build's FULL bake from the packer master (it carries no agent).
  validate_golden()  boot a worker off a qcow2 -> assert benign==Valid AND revoked==Revoked
  rotate()           backup current base (keep last N) -> promote candidate -> base -> record the
                     chain depth (beside the golden + the mirror off the images store) -> restart
                     the pool-manager so the promoted golden is in service

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
import fcntl
import os
import re
import subprocess
import tempfile
import sys
import time
from pathlib import Path

if __name__ == "__main__":   # golden_build does `import golden_rotate`: hand it THIS module, not a second copy whose
    sys.modules["golden_rotate"] = sys.modules[__name__]   # NothingPublished would be a different class from main()'s handler

logger = logging.getLogger("winval.golden_rotate")

class rotation_lock:
    """The rotation lock, held for the body: `with rotation_lock("taking the rebake-source copy"): ...`. Bounded like the
    preflight's wait (a pool-manager start holds it for minutes, a rotation for hours): never an unbounded block inside a
    oneshot with no start timeout. Raises NothingPublished when it is still held after PREFLIGHT_LOCK_WAIT_S."""

    def __init__(self, what: str) -> None:
        self._what = what
        self._fd = -1

    def __enter__(self) -> "rotation_lock":
        self._fd = os.open(ROTATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            _tighten_lock(self._fd)
            deadline = time.time() + PREFLIGHT_LOCK_WAIT_S
            while True:
                try:
                    fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    return self
                except OSError as e:
                    if time.time() >= deadline:
                        raise NothingPublished(f"lock {ROTATE_LOCK} still held after {PREFLIGHT_LOCK_WAIT_S}s while {self._what}") from e
                    time.sleep(5)
        except BaseException:
            os.close(self._fd)
            self._fd = -1
            raise

    def __exit__(self, *exc: object) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            self._fd = -1


def _tighten_lock(fd: int) -> None:
    """The rotation lock must be 0600: flock(2) needs only a READABLE descriptor, so a 0644 lock
    (what `flock <path>` in the pool-manager unit creates under umask 022) lets any local user hold
    the exclusive lock and stall every rotation and pool start. Our own opens create it 0600; this
    repairs one another creator left wider (the owner check stays with the callers)."""
    st = os.fstat(fd)
    if st.st_uid == os.geteuid() and st.st_mode & 0o077:
        os.fchmod(fd, 0o600)


# --- envfile parser (systemd src/basic/env-file.c parse_env_file_internal, verified against systemd-run over 77 files) ---
import re as _re
def parse_env_file(data: bytes):
    """winval.env as systemd's EnvironmentFile reads it: a state machine, not lines. Quoted values run across newlines until
    their closing quote (an open one swallows the rest of the file); a closing quote returns to the value (\"a\" \"b\" is ab);
    backslash escapes \\ \" $ ` inside double quotes and any character unquoted, backslash-newline continues; # and ; start
    a comment only where a key would; the LAST assignment wins; a key that is not a valid name is dropped. Returns
    (assignments, unterminated) — unterminated says the file ended inside a quote. Raises ValueError when systemd would
    refuse the whole file (an assignment that is not valid UTF-8 or carries a NUL)."""
    if b"\x00" in data:   # a NUL anywhere, a comment included: systemd refuses the whole file (the UTF-8 rule below is per assignment)
        raise ValueError("the file carries a NUL byte: systemd rejects the whole file")
    text = data.decode("utf-8", "surrogateescape")
    WS = " \t"; NL = "\n\r"; COMMENTS = "#;"; ESC = "\"\\`$"
    PRE_KEY, KEY, PRE_VALUE, VALUE, VALUE_ESCAPE, SQ, DQ, DQ_ESCAPE, COMMENT = range(9)
    st = PRE_KEY; key = []; val = []; key_ws = None; val_ws = None; out = {}
    def push():
        k = "".join(key[:key_ws] if key_ws is not None else key); v = "".join(val)
        if any("\udc80" <= c <= "\udcff" for c in k + v):
            raise ValueError(f"the assignment of {k!r} is not valid UTF-8: systemd rejects the whole file")
        if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k): out[k] = v
    for c in text:
        if st == PRE_KEY:
            if c in COMMENTS: st = COMMENT
            elif c not in WS and c not in NL: st = KEY; key = [c]; key_ws = None
        elif st == KEY:
            if c in NL: st = PRE_KEY; key = []
            elif c == "=": st = PRE_VALUE; val = []; val_ws = None
            else:
                if c not in WS: key_ws = None
                elif key_ws is None: key_ws = len(key)
                key.append(c)
        elif st == PRE_VALUE:
            if c in NL: st = PRE_KEY; push(); key = []; val = []
            elif c == "'": st = SQ
            elif c == '"': st = DQ
            elif c == "\\": st = VALUE_ESCAPE; val_ws = None
            elif c not in WS: st = VALUE; val_ws = None; val.append(c)
        elif st == VALUE:
            if c in NL:
                st = PRE_KEY
                if val_ws is not None: del val[val_ws:]
                push(); key = []; val = []
            elif c == "\\": st = VALUE_ESCAPE; val_ws = None
            else:
                if c not in WS: val_ws = None
                elif val_ws is None: val_ws = len(val)
                val.append(c)
        elif st == VALUE_ESCAPE:
            st = VALUE
            if c not in NL: val.append(c)
        elif st == SQ:
            if c == "'": st = PRE_VALUE
            else: val.append(c)
        elif st == DQ:
            if c == '"': st = PRE_VALUE
            elif c == "\\": st = DQ_ESCAPE
            else: val.append(c)
        elif st == DQ_ESCAPE:
            st = DQ
            if c in ESC: val.append(c)
            elif c != "\n": val.append("\\"); val.append(c)   # only a LINE FEED continues here (env-file.c tests '\n', not the newline set): a CR keeps its backslash
        elif st == COMMENT:
            if c in NL: st = PRE_KEY
    unterminated = st in (SQ, DQ, DQ_ESCAPE)
    if st in (PRE_VALUE, VALUE, VALUE_ESCAPE, SQ, DQ, DQ_ESCAPE):
        if st == VALUE and val_ws is not None: del val[val_ws:]
        push()
    return out, unterminated
# --- end envfile parser ---


def _load_env_file(path: str) -> None:
    """Read the units' EnvironmentFile the way systemd does (parse_env_file above) and apply it to any variable NOT
    already in the environment — so a hand-run `sudo … golden_rotate.py` (sudo's env_reset strips every exported
    GOLDEN_*/AUTHENTICODE_* override) sees the SAME paths the timer's rotation used, instead of the defaults. A file
    systemd would reject applies nothing here either, with a warning: the units started with none of its knobs."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return
    try:
        seen, _ = parse_env_file(data)
    except ValueError as exc:
        logging.getLogger("golden_rotate").warning("%s: %s; none of it is applied here either", path, exc)
        return
    for k, v in seen.items():
        if k not in os.environ:
            os.environ[k] = v


_load_env_file(os.environ.get("WINVAL_ENV_FILE", "/etc/winval/winval.env"))

MASTER_QCOW2 = os.environ.get("GOLDEN_MASTER", "/var/lib/libvirt/images/winserver2025-core.qcow2")
# what a rebake is CLONED FROM: the promoted golden (it carries the agent and last cycle's trust
# state; the refresh runs on top of it) — the frozen master only before any golden was ever
# promoted, exactly as the pool-manager unit materialises the RAM base. GOLDEN_REBAKE_FROM=master
# forces the master (a pristine rebuild every cycle) for images whose master already carries the agent.
REBAKE_FROM = os.environ.get("GOLDEN_REBAKE_FROM", "golden")


def _env_int(name: str, default: int, floor: int = 0) -> int:
    """A GOLDEN_* knob read tolerantly (the same rule as winval_blastbox.knobs.env_int; this script runs
    standalone): an empty value is the default, a non-numeric one is a warning plus the default — never a
    bare traceback that ends the rotate oneshot before its first log line — and below `floor` is `floor`."""
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        n = int(raw)
    except ValueError:
        logger.warning("%s=%r is not a whole number: using %d", name, raw, default)
        return default
    if n < floor:
        logger.warning("%s=%r is below %d: using %d", name, raw, floor, floor)
        return floor
    return n


MAX_CHAIN = _env_int("GOLDEN_MAX_CHAIN", 4, floor=1)   # golden-based rebakes before one from the master


def _chain_file() -> Path:
    return Path(GOLDEN_BASE_DISK + ".chain")


def _mirror_file() -> Path:
    return Path(CHAIN_MIRROR)


def _read_depth(p: Path):
    """None when there is no such record; MAX_CHAIN when it exists but cannot be read (empty, garbage):
    unknown provenance forces the master rebake next cycle (0 would silently reset the counter)."""
    if not p.exists():
        return None
    try:
        return int(p.read_text().strip())
    except (OSError, ValueError):
        return MAX_CHAIN


def chain_length() -> int:
    """The promoted golden's rebake depth: the NEWEST of the record beside the golden, the mirror off
    the images store and the newest `.chain.unrecorded` marker (see below), else 0 (a golden that
    predates the chain keeps rebaking from itself until MAX_CHAIN, as before)."""
    # When the copies disagree the NEWEST wins: the last promotion wrote it. _record_chain REMOVES a copy it
    # could not write (a stale copy must never outlive a master reset — "highest wins" latched a full bake
    # every cycle once a mirror store refused writes), so a disagreement is only ever a copy whose remove
    # failed too (a read-only store), and there the surviving fresh copy is the newer one. A marker is
    # touched at promotion time. The preflight then brings the older copies up to the newest, so a record
    # restored without its mtime is repaired the moment it is older than the mirror — and a copy that is
    # both stale and newest (a plain `cp` restore of the record alone) reads as the depth until the next
    # promotion rewrites both: the operator's restore is trusted, as before this branch.
    copies = []
    for p in (_chain_file(), _mirror_file(), _newest_orphan_sidecar()):
        if p is not None and (d := _read_depth(p)) is not None:
            copies.append((_mtime(p) or 0, d))
    if copies:
        return max(copies, key=lambda t: t[0])[1]
    return 0   # the count starts here — the preflight proves the record CAN be written, so a stuck counter is refused up front, not pinned


def rebake_source() -> str:
    """The promoted golden, unless the operator forced the master or the chain is due for a
    reset: RefreshTrust only ever ADDS to the Disallowed store, so a golden rebaked from itself
    keeps every kill-list entry Microsoft later withdrew — every GOLDEN_MAX_CHAIN cycles the
    rebake starts from the pristine master again (as a FULL bake, see refresh_and_rotate: the
    master is the packer image and carries no agent). Never a path that does not exist: a host
    provisioned by golden_build has no master, and the chain reset must not latch rotation off."""
    golden = Path(GOLDEN_BASE_DISK).exists()
    master = Path(MASTER_QCOW2).exists()
    want_master = REBAKE_FROM == "master" or chain_length() >= MAX_CHAIN
    if want_master and master:
        return MASTER_QCOW2
    if want_master and golden:
        logger.warning("a rebake from the master is due (chain %d >= %d) but %s does not exist: rebaking from the golden again",
                       chain_length(), MAX_CHAIN, MASTER_QCOW2)
        return GOLDEN_BASE_DISK
    if golden:
        return GOLDEN_BASE_DISK
    if master:
        return MASTER_QCOW2
    raise NothingPublished(f"nothing to rebake from: neither {GOLDEN_BASE_DISK} nor {MASTER_QCOW2} exists")


STRANDED_SOURCE_HOURS = _env_int("GOLDEN_STRANDED_SOURCE_HOURS", 24, floor=1)


def _is_builder(pid: str) -> bool:
    """A live process whose command line names one of the two builders (a recycled pid number is not one)."""
    try:
        argv = Path("/proc", pid, "cmdline").read_bytes().split(b"\0")
    except OSError:
        return False
    return any(a.endswith((b"golden_rotate.py", b"golden_build.py")) for a in argv)


def _rebake_src_live(c: Path) -> bool:
    """A rebake-source copy whose builder (the pid in its name, snapshot_source) is still a running builder: the
    BACKING file of that build, whatever its age — for the stranded sweep and the candidate prune alike."""
    if ".rebake-src-" not in c.name:
        return False
    pid = c.name[:-len(".qcow2")].rsplit("-", 1)[-1]
    return pid.isdigit() and _is_builder(pid)


def _sweep_stranded_sources() -> None:
    """A rebake-source copy has no value once its run ended; one left by a killed run (OOM, a
    reboot, systemctl stop) is reclaimed here — called from rotation_preflight() BEFORE its space
    check, and again before each snapshot — after STRANDED_SOURCE_HOURS (a live rebake is younger)."""
    cutoff = time.time() - STRANDED_SOURCE_HOURS * 3600
    for c in BACKUP_DIR.glob("golden-base.rebake-src-*.qcow2"):
        if (_mtime(c) or float("inf")) < cutoff:   # a builder deletes its copy without the lock
            if _rebake_src_live(c):   # the NUMBER alone is recyclable after a day: it must still be a running golden_rotate/golden_build
                logger.warning("rebake-source copy %s is older than %dh but its builder is still running: left alone", c.name, STRANDED_SOURCE_HOURS)
                continue
            logger.warning("removing stranded rebake-source copy %s (a killed run left it)", c.name)
            _run(["sudo", "rm", "-f", str(c)])


def candidate_depth_file(candidate: str) -> Path:
    return Path(candidate + ".chain")


def _newest_orphan_sidecar() -> Path | None:
    """The newest `.chain.unrecorded` marker: the depth of a promotion whose golden record could not be
    written (only such sidecars are ever renamed to the marker; an abandoned build's leftover is not)."""
    marks = list(BACKUP_DIR.glob("*.chain.unrecorded"))
    return max(marks, key=lambda p: _mtime(p) or 0) if marks else None


def unrecorded_marker(candidate: str) -> Path:
    """The sidecar of a candidate that WAS promoted but whose depth never reached the golden's record,
    renamed so the fact survives on disk (a later oneshot cannot know it otherwise) and so that no
    leftover of an abandoned build can ever be mistaken for it. Always INSIDE BACKUP_DIR, where the
    reader and the prune look, whatever path the candidate was promoted from."""
    return BACKUP_DIR / (Path(candidate).name + ".chain.unrecorded")


def _keep_as_unrecorded(candidate: str) -> bool:
    """True when the marker now exists. The rename can fail for the very reason it is attempted (the
    images store refusing writes), which is why the mirror off that store is the primary fallback."""
    sidecar = candidate_depth_file(candidate)
    if not sidecar.exists():
        return unrecorded_marker(candidate).exists()
    r = _run(["sudo", "mv", "-f", str(sidecar), str(unrecorded_marker(candidate))])
    ok = getattr(r, "returncode", 1) == 0 and unrecorded_marker(candidate).exists()
    if ok:
        _run(["sudo", "touch", str(unrecorded_marker(candidate))])   # mv keeps the BUILD time: the marker must date from the promotion, the newest copy chain_length() picks
    if not ok:
        logger.error("the depth sidecar %s could not be kept as %s (the store refuses even a rename)", sidecar, unrecorded_marker(candidate))
    return ok


def _rm_candidate(candidate: str) -> None:
    # a candidate already gone (removed out from under a run — _promote COPIES it, never renames it, and a
    # split state records the depth itself) while the golden has no record: its sidecar would be the golden's
    # ONLY depth — keep it under the marker name chain_length() reads, never as a plain sidecar an aged
    # leftover could imitate
    if not os.path.lexists(candidate) and not _chain_file().exists():
        _keep_as_unrecorded(candidate)
    _run(["sudo", "rm", "-f", candidate, str(candidate_depth_file(candidate))])


def snapshot_source(ts: str, src: str | None = None) -> tuple[str, str, int]:
    """A PRIVATE copy of the rebake source in the backup dir, taken under the rotation lock.
    qcow2 records its backing file BY PATH: an overlay off the live GOLDEN_BASE_DISK would be
    re-parented to whatever a concurrent promotion renames into that path (the retry command
    or build-and-promote can run while the timer's rebake is in flight), and the flattened
    candidate would silently mix two goldens. A copy nothing renames keeps the invariant the
    frozen master used to provide. Returns (source_used, private_copy, chain_depth) — the depth
    read UNDER the same lock as the copy: a promotion between an unlocked chain_length() and the
    copy would pair the new golden's bytes with the old golden's depth."""
    import fcntl
    if src is None:
        src = rebake_source()
    _ensure_backup_dir()
    _sweep_stranded_sources()
    copy = str(BACKUP_DIR / f"golden-base.rebake-src-{ts}-{os.getpid()}.qcow2")   # both builders call this: the second alone is not unique
    fd = os.open(ROTATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    _tighten_lock(fd)
    try:
        # bounded like the preflight's wait (a pool-manager start holds the lock for minutes; a
        # rotation for hours): never an unbounded block inside a oneshot with no start timeout
        deadline = time.time() + PREFLIGHT_LOCK_WAIT_S
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if time.time() >= deadline:
                    raise NothingPublished(f"lock {ROTATE_LOCK} still held after {PREFLIGHT_LOCK_WAIT_S}s while taking the rebake-source copy") from e
                time.sleep(5)
        depth = chain_length()   # with the lock held: the record and the golden cannot change under us
        want = Path(src).stat().st_size
        r = _run(["sudo", "cp", "--reflink=auto", src, copy], 3600)
        got = Path(copy).stat().st_size if Path(copy).exists() else -1
        if r.returncode != 0 or got != want:
            _run(["sudo", "rm", "-f", copy])
            raise RuntimeError(f"snapshot of the rebake source {src} -> {copy} failed (rc={r.returncode}, {got} of {want} bytes)")
    finally:
        os.close(fd)
    return src, copy, depth
# ONE name for the RAM base, the pool's (winval_blastbox/vm_pool.py + the pool-manager unit read
# AUTHENTICODE_GOLDEN_BASE): a rotation that promoted to a different path than the pool boots from
# would log "PROMOTED" every night and never reach a job. GOLDEN_BASE is kept as a legacy alias.
GOLDEN_BASE = (os.environ.get("AUTHENTICODE_GOLDEN_BASE") or os.environ.get("GOLDEN_BASE")
               or "/dev/shm/golden-base.qcow2")
GOLDEN_BASE_DISK = os.environ.get("GOLDEN_BASE_DISK", "/var/lib/libvirt/images/golden-base.qcow2")
BACKUP_DIR = Path(os.environ.get("GOLDEN_BACKUP_DIR", "/var/lib/libvirt/images/golden-backups"))
# A second copy of the chain record OFF the images store: the record beside the golden is the one a
# store that refuses writes (read-only, full) cannot take — and that is the very moment the depth
# must survive. The root filesystem's state dir takes it; chain_length() reads whichever is newer.
CHAIN_MIRROR = os.environ.get("GOLDEN_CHAIN_MIRROR", "/var/lib/winval/golden-base.chain")
KEEP_N = _env_int("GOLDEN_KEEP_N", 5, floor=0)
CANDIDATE_KEEP_DAYS = _env_int("GOLDEN_CANDIDATE_KEEP_DAYS", 7, floor=1)
CONVERT_TIMEOUT_S = _env_int("GOLDEN_CONVERT_TIMEOUT_S", 3600, floor=60)   # the flatten writes a whole image: the same budget as every whole-image copy
SSH_KEY = os.environ.get("AUTHENTICODE_SSH_KEY", "/etc/winval/win_golden")
GRAVEYARD = os.environ.get("GOLDEN_GRAVEYARD", "C:\\certgraveyard\\cert_graveyard_database.csv")
BENIGN = os.environ.get("GOLDEN_BENIGN_SAMPLE", "/var/lib/winval/samples/whoami.exe")
REVOKED = os.environ.get("GOLDEN_REVOKED_SAMPLE", "")  # optional; checks status==Revoked when set
WARM_DIR = os.environ.get("GOLDEN_WARM_DIR", "")   # a GUEST directory (C:\...) of signed binaries for myatg --warm-cache; NOT AUTHENTICODE_WARM_DIR, which is a HOST corpus the pool posts to the agent        # optional in-guest dir of certs to re-warm

_SSH = ["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
        "-o", "ConnectTimeout=15", "-i", SSH_KEY]


def _run(a: list[str], t: float = 120) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(a, capture_output=True, text=True, timeout=t)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(a, 124, "", "timeout")
    except OSError as exc:   # fork/exec failed (ENOMEM, EMFILE — the degraded host that causes a split state): a FAILED result, never a
        # traceback that replaces the diagnostic in flight (every caller already judges the returncode)
        logger.error("could not run %s: %s", a[0], exc)
        return subprocess.CompletedProcess(a, 255, "", f"could not run {a[0]}: {exc}")


def _virsh(*a: str, t: float = 120) -> subprocess.CompletedProcess:
    # under the C locale: the builders match virsh's English output ("shut off"), and a hand-run under a
    # translated locale would see it in that language (sudo's env_reset keeps LC_*, so it is set explicitly)
    return _run(["sudo", "env", "LC_ALL=C", "LANG=C", "virsh", *a], t)


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


class SplitState(RuntimeError):
    """The disk twin was published but the RAM rename failed AND the automatic rollback failed:
    ``backup`` is the copy of the previous golden the message tells the operator to restore from,
    which the prune that runs on every outcome must therefore keep (GOLDEN_KEEP_N=0 would have
    removed it in the same breath as naming it)."""

    def __init__(self, msg: str, backup: str | None = None) -> None:
        super().__init__(msg)
        self.backup = backup


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


def rotation_preflight(estimate_bytes: int | None = None, candidate_built: bool = False, keep: str | None = None,
                       source_copy: bool = True, gate_samples: bool = True) -> None:
    """Everything the cycle will need, checked BEFORE the hour-long build and gate: root (the
    lock lives in root-owned /run and every publish step is sudo), a usable lock, the gate's
    samples, and space for the run's PEAK — the candidate the build writes into the backup dir,
    a temporary copy beside EACH base (staged until the rename) and the backup of the current
    golden, all alive at once. Requirements are summed PER FILESYSTEM (the disk base and the
    backup dir normally share one), so the shipped defaults need 3x the image there, not 2x.
    The estimate is the larger of the current golden and the master, or the caller's (the
    build entry point passes its own base); with nothing to estimate from, refuse rather than
    pass a full disk. Raises NothingPublished."""
    try:
        validate_graveyard(GRAVEYARD)   # static knobs: refused before the lock, the prune and the hour-long build
        validate_warm_dir(WARM_DIR)
    except ValueError as exc:
        raise NothingPublished(str(exc)) from exc
    if os.geteuid() != 0:
        raise NothingPublished("rotation must run as root (sudo): the rotation lock lives in /run and every publish step is privileged")
    import fcntl
    try:
        fd = os.open(ROTATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        _tighten_lock(fd)
    except OSError as e:
        raise NothingPublished(f"cannot open the rotation lock {ROTATE_LOCK} ({e.strerror})") from e
    try:
        # the lock is also held by the pool-manager's ExecStartPre while it materialises the RAM
        # base (minutes); a rotation holds it for hours. Wait a bounded while so a routine start
        # does not cost the night's rebake, then refuse.
        deadline = time.time() + PREFLIGHT_LOCK_WAIT_S
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError as e:
                if time.time() >= deadline:
                    raise NothingPublished(f"lock {ROTATE_LOCK} still held after {PREFLIGHT_LOCK_WAIT_S}s (a rotation in progress, or a pool-manager start materialising the RAM base)") from e
                time.sleep(5)
        _sweep_own_temps()   # UNDER the lock (nothing is in flight): a promotion killed mid-copy strands a
                             # golden-sized temporary beside a base, and the space check below would fail forever
        _prune_backups(keep)   # likewise the expired candidates and surplus backups: pruned only after a
                             # promotion, they could fill the store so that no promotion ever passes this check
        if Path(GOLDEN_BASE_DISK).exists():
            # UNDER THE LOCK: the seed of a missing record must not race a concurrent promotion's _record_chain
        # the chain record must be WRITABLE, or the MAX_CHAIN reset could never fire (a counter that
            # cannot be recorded stays where it is): prove it EVERY run with a probe file beside the record
            # (never by rewriting an existing record), and seed a missing record with the depth it reads as
            probe = str(_chain_file()) + ".probe"
            if not _write_small(probe, "probe"):
                raise NothingPublished(f"cannot write beside the chain record {_chain_file()}: the master-rebake schedule could not be kept")
            _run(["sudo", "rm", "-f", probe])
            # seed a missing record — and REWRITE a differing one: after an images-store outage the record beside
            # the golden may be gone or stale while the mirror holds the real one; chain_length() picks the newest,
            # and both copies are brought to it so a lost mirror (a rebuilt root filesystem) cannot hand a stale
            # depth back
            want = chain_length()
            if _read_depth(_chain_file()) != want and not _write_small(str(_chain_file()), str(want)):
                raise NothingPublished(f"cannot write the chain record {_chain_file()}: the master-rebake schedule could not be kept")
            if _read_depth(_mirror_file()) != want:
                _run(["sudo", "mkdir", "-p", str(_mirror_file().parent)])
                _write_small(str(_mirror_file()), str(want))   # best effort: the mirror probe below reports a store that cannot take it
            # the mirror (the copy that survives the images store refusing writes) is proved the same way, but
            # its loss is a WARNING every run, not a refusal: the record beside the golden is the primary
            _run(["sudo", "mkdir", "-p", str(_mirror_file().parent)])
            mprobe = str(_mirror_file()) + ".probe"
            if _write_small(mprobe, "probe"):
                _run(["sudo", "rm", "-f", mprobe])
            else:
                logger.warning("the chain-record mirror %s cannot be written (GOLDEN_CHAIN_MIRROR; root filesystem full or an unmounted path?): a promotion during an images-store outage would then lose its depth", _mirror_file())
    finally:
        os.close(fd)   # released again: the build does not hold the lock, rotate() takes it
    for base in (GOLDEN_BASE_DISK, GOLDEN_BASE):   # what _promote refuses, refused here, before the build
        if Path(base).is_symlink() or Path(base).is_dir():
            raise NothingPublished(f"{base} is a symlink or a directory, not a regular file: the promotion would refuse it")
    if BACKUP_DIR.exists():
        _sweep_stranded_sources()   # BEFORE the space check below, which a stranded copy would fail forever
    if gate_samples and (not BENIGN or not Path(BENIGN).is_file()):   # the gate ALWAYS validates the benign sample — but a promotion-only retry/rollback never runs the gate
        raise NothingPublished(f"GOLDEN_BENIGN_SAMPLE={BENIGN!r} is not a file: the gate could not run, so the build would be wasted")
    if gate_samples and REVOKED and not Path(REVOKED).is_file():
        raise NothingPublished(f"GOLDEN_REVOKED_SAMPLE={REVOKED} does not exist: the gate could not run, so the build would be wasted")
    try:   # EVERY promoting entry point restarts the pool-manager afterwards, the retry/rollback CLI (no gate) included: the
        # PRODUCTION spec it will start with (the pinned IP pool the gate drops among it) is judged before anything is published
        from winval_blastbox.vm_pool import authenticode_spec, pool_size, validate_egress_posture
        validate_egress_posture(authenticode_spec())
        from winval_blastbox.pool_manager import _refuse_open_egress
        # the pool's own start-time knob guards (WarmVmPool.__init__ refuses each by name): a promotion restarts the pool, and a
        # unit that is 'active' the instant systemctl returns (Type=simple) fails seconds later on these with nothing in the
        # rotation's exit code to say so — judged HERE, before anything is published
        from winval_blastbox.vm_pool import smoke_expect
        smoke_sample = os.environ.get("AUTHENTICODE_SMOKE_SAMPLE")
        if smoke_sample and not os.path.isfile(smoke_sample):
            raise RuntimeError(f"AUTHENTICODE_SMOKE_SAMPLE={smoke_sample!r} is not a file: the pool-manager would refuse to start")
        if smoke_sample:
            smoke_expect()
        pool_warm_dir = os.environ.get("AUTHENTICODE_WARM_DIR")
        if pool_warm_dir and not os.path.isdir(pool_warm_dir):
            raise RuntimeError(f"AUTHENTICODE_WARM_DIR={pool_warm_dir!r} is not a directory: the pool-manager would refuse to start")
        _refuse_open_egress(pool_size(), sysctl="loadable")   # the manager's OWN start refusals (design changes #7/#8: an unset exit, open
        # sibling traffic under several workers); the restart after the promotion would otherwise refuse and the pool would be down until the
        # knobs were fixed. The sysctl half is judged as the restart will find it: the unit's ExecStartPre applies it, so only a host that
        # cannot load br_netfilter at all is refused here
    except (ValueError, RuntimeError) as exc:
        raise NothingPublished(f"the worker spec the pool-manager would start with is invalid ({exc}): fix the AUTHENTICODE_* knobs before promoting anything") from exc
    except SystemExit as exc:
        raise NothingPublished(f"the pool-manager would refuse to start after the promotion ({exc}): fix the AUTHENTICODE_* knobs before promoting anything") from exc
    if gate_samples:   # the gate boots under the PRODUCTION spec: a knob blastbox's fail-closed parsers refuse (AUTHENTICODE_BLOCK_INTERNAL=treu) must fail HERE, not as a traceback after the hour-long build
        try:
            _gate_spec("/dev/null")
        except (ValueError, RuntimeError) as exc:
            raise NothingPublished(f"the worker spec the gate would boot with is invalid ({exc}): fix the AUTHENTICODE_* knobs; the build would be wasted") from exc
    if estimate_bytes is None:
        estimate_bytes = max((Path(p).stat().st_size for p in (GOLDEN_BASE_DISK, MASTER_QCOW2) if Path(p).exists()), default=0)
    if estimate_bytes <= 0:
        raise NothingPublished(f"cannot size the run: neither {GOLDEN_BASE_DISK} nor {MASTER_QCOW2} exists (set GOLDEN_MASTER, or pass the base's size)")
    need = estimate_bytes
    # peak per filesystem: candidate + backup in BACKUP_DIR, one temporary beside each base
    # in the backup dir the peak is 2x: source copy + candidate during the bake (the copy is gone
    # before promotion), then candidate + backup during promotion
    # a retry of a candidate that already EXISTS in the backup dir needs only the backup there
    # what the backup dir really holds at the peak: the candidate (unless it already exists), plus ONE of
    # the rebake-source copy (only when the source is the golden — a bake from the master takes none)
    # and the backup of the current golden (only when there is one; the copy is gone before the backup)
    backup_terms = ([] if candidate_built else ["candidate"]) + (["rebake-source copy / backup"] if (source_copy or Path(GOLDEN_BASE_DISK).exists()) else [])
    demands = [(str(BACKUP_DIR), len(backup_terms) * need, " + ".join(backup_terms) + " in the backup dir" if backup_terms else "nothing in the backup dir"),
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


def build_candidate(src: str | None = None) -> str:
    """Clone the rebake source (a private copy of the promoted golden, or of the master), boot
    it, refresh the trust state in-guest, flatten -> a candidate qcow2.

    The refresh runs on an OVERLAY off that private copy, so neither the live golden nor the
    master is ever written or depended on by path; the flattened candidate carries the source
    + the fresh disallowed-list / CRL cache / roots."""
    ts = _run(["date", "+%Y%m%d-%H%M%S"]).stdout.strip()
    dom = f"golden-cand-{ts}"
    overlay = f"/dev/shm/{dom}.qcow2"
    candidate = f"{BACKUP_DIR}/golden-base.candidate-{ts}.qcow2"
    _ensure_backup_dir()
    _virsh("destroy", dom)
    _virsh("undefine", dom, "--snapshots-metadata")
    _run(["sudo", "rm", "-f", overlay])
    xfd, xml_path = tempfile.mkstemp(prefix=f"{dom}-", suffix=".xml")   # O_EXCL, unpredictable: never a /tmp path another user can pre-create
    os.close(xfd)   # BEFORE the golden-sized private copy: a failure here must strand nothing
    try:
        src, src_copy, at = snapshot_source(ts, src)   # the source the caller decided on (never re-decided here: a promotion in between could flip it to the agent-less master); may raise (lock wait, missing source)
    except BaseException:
        os.unlink(xml_path)
        raise
    depth = 0 if src == MASTER_QCOW2 else at + 1   # the source's depth as read under the copy's lock; the sidecar is written once the candidate exists (below)
    logger.info("rebake source: %s (private copy %s) -> overlay %s", src, src_copy, overlay)
    built = False
    try:   # from here every exit — a failed overlay, XML, define or start included — destroys the domain + overlay
        r = _run(["sudo", "qemu-img", "create", "-f", "qcow2", "-b", src_copy, "-F", "qcow2", overlay], 120)
        if r.returncode != 0:   # the nightly path's twin of golden_build's check: name the source and qemu-img's own words, as one logged line
            raise NothingPublished(f"cannot create the rebake overlay on {src_copy} (rc {r.returncode}): {(r.stderr or '').strip()[-400:]}; golden NOT promoted (nothing published)")
        _run(["sudo", "chmod", "644", overlay])
        # define+boot the overlay domain (reuse the runtime's XML generator for a real worker shape)
        from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime
        rt = LibvirtVmRuntime(LibvirtVmConfig(golden_base=src_copy))
        Path(xml_path).write_text(rt._domain_xml(dom, overlay))
        for step, args in (("define", (xml_path,)), ("start", (dom,))):   # virsh's own words, as one logged line — never a bare assert
            r = _virsh(step, *args)
            if r.returncode != 0:
                raise NothingPublished(f"virsh {step} failed for the rebake domain {dom} (rc {r.returncode}): {(r.stderr or '').strip()[-400:]}; golden NOT promoted (nothing published)")
        mac = _mac(dom)
        ip, ready, dl = None, False, time.time() + 240
        while time.time() < dl:
            ip = _ip_for_mac(mac) if mac else None
            if ip and "READY" in _ssh_ps(ip, "'READY'", 15):
                ready = True
                break
            time.sleep(5)
        if not ready:   # an ADDRESS is not an ANSWER: a guest with a lease that never answers is the usual shape of a wrong key (golden_build's twin says the same)
            raise NothingPublished(f"guest {ip or 'never got an address'} did not answer over ssh within 240s: is {SSH_KEY} the key the image authorises "
                                   "(the packer build's keys/build_key — the image accepts no other)?; golden NOT promoted (nothing published)")
        logger.info("refreshing trust state in %s (myatg --refresh)…", ip)
        gv = f'--gv "{GRAVEYARD}"' if GRAVEYARD else ""
        warm = f'C:\\agent\\myatg.exe --warm-cache "{WARM_DIR}" {gv} | Out-Null;' if WARM_DIR else ""
        out = _ssh_ps(ip, refresh_ps(gv, warm), 600, check=True)
        j = refresh_result(out)   # the whole point of the rebake is FRESH trust state
        logger.info("refresh result: roots_synced=%s kill_list_installed=%s disallowed_store_count=%s",
                    j.get("roots_synced"), j.get("disallowed_kill_list_installed"), j.get("disallowed_store_count"))
        _ssh_ps(ip, "Stop-Computer -Force", 20)
        dl = time.time() + 180
        state = ""
        while time.time() < dl and "shut off" not in (state := _virsh("domstate", dom).stdout):
            time.sleep(3)
        if "shut off" not in state:   # a running guest flattened is a crash-inconsistent candidate that the gate can still pass
            raise NothingPublished(f"guest {dom} did not shut off within 180s (domstate: {state.strip() or 'unknown'}); refusing to flatten a running domain into a candidate")
        logger.info("flattening overlay -> candidate %s", candidate)
        rc = _run(["sudo", "qemu-img", "convert", "-O", "qcow2", overlay, candidate], CONVERT_TIMEOUT_S).returncode
        if rc != 0:
            raise NothingPublished(f"flatten (qemu-img convert) {'timed out after %ds' % CONVERT_TIMEOUT_S if rc == 124 else 'failed (rc=%s)' % rc}; golden NOT promoted (nothing published)")
        _run(["sudo", "chmod", "644", candidate])
        _write_small(str(candidate_depth_file(candidate)), str(depth))   # travels with the candidate into rotate()
        built = True
    finally:
        _virsh("destroy", dom)
        _virsh("undefine", dom, "--snapshots-metadata")
        _run(["sudo", "rm", "-f", overlay, xml_path, src_copy])   # the private source copy is flattened into the candidate
        if not built:
            # a convert that failed or timed out leaves a full-size partial candidate in the
            # backup dir; _prune_backups deliberately never touches candidates, so nothing else
            # would ever reclaim it and each failed nightly rebake would keep one image of space
            _rm_candidate(candidate)
    return candidate


def _gate_spec(qcow2: str):
    """The PRODUCTION spec (egress policy, exit routing, agent port) with the candidate as its image: the gate
    must judge the candidate under the network posture the workers will run with, and with the same clock sync
    at ready (a golden without qemu-ga gets its clock ONLY from that hook — and both verdicts are clock-bound).
    The pinned IP pool is dropped: the live pool holds those addresses, so the gate learns its own by DHCP."""
    import dataclasses
    from winval_blastbox.vm_pool import authenticode_spec, validate_egress_posture
    from blastbox.host.runtime.vm_compose import VmImageSpec
    spec = dataclasses.replace(authenticode_spec(), name="goldgate", image=VmImageSpec(golden=qcow2), worker_ip_pool="", warm_size=1)
    validate_egress_posture(spec)   # the rooter's spawn-time refusals (an unsupported exit, inetsim without a sink, gateway xor leg), before any build
    return spec


def validate_golden(qcow2: str) -> bool:
    """Boot a throwaway worker off ``qcow2`` and assert the validation gate: a benign signed sample
    is Valid AND (if configured) a known-revoked sample is Revoked. False if the worker won't boot,
    the agent won't answer, or any verdict is wrong — i.e. a broken/regressed golden is rejected."""
    from winval_blastbox.vm_pool import agent_validate, _sync_clock
    c = Path(qcow2)
    if c.is_symlink() or not c.is_file():   # a mistyped path was 'did not boot a healthy worker' — the verdict a corrupt golden gives — after a 240 s wait
        logger.error("GATE FAIL: candidate %s is not a regular file (no such file, or a symlink/directory); nothing was booted", qcow2)
        return False
    if not BENIGN or not Path(BENIGN).is_file():   # the gate ALWAYS validates the benign sample: unset or missing, nothing can be judged (as rotation_preflight rules); `validate` runs no preflight and paid a full boot to find out
        logger.error("GATE FAIL: GOLDEN_BENIGN_SAMPLE=%r is not a file: the gate cannot run; nothing was booted", BENIGN)
        return False
    if REVOKED and not Path(REVOKED).is_file():   # optional: only refused when set and missing
        logger.error("GATE FAIL: GOLDEN_REVOKED_SAMPLE=%r is not a file: the gate cannot run; nothing was booted", REVOKED)
        return False
    try:   # the spec too: a knob blastbox refuses is a GATE FAIL by name, never a traceback (the preflight refuses it earlier still)
        rt = _gate_spec(qcow2).runtime(on_ready=_sync_clock)
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
PREFLIGHT_LOCK_WAIT_S = _env_int("GOLDEN_PREFLIGHT_LOCK_WAIT_S", 1800, floor=0)
RESTART_SETTLE_S = _env_int("GOLDEN_RESTART_SETTLE_S", 90, floor=0)   # how long restart_pool watches a restarted unit before calling it up (0: none)


def rotate(candidate: str) -> None:
    """Back up the current live golden (keep the last N), then promote ``candidate`` into place.

    ONE rotation at a time: the timer's rotate and a manual ``golden_build.py build-and-promote``
    (or two manual runs) must not overlap — two promotions would race on the same bases and
    _sweep_own_temps would unlink the other's copy in flight. A held lock fails FAST, it never
    queues: the second caller reports and exits, the first finishes."""
    import fcntl
    c = Path(candidate)
    if c.is_symlink() or not c.is_file():   # BEFORE the lock and before an hour-long backup copy
        raise NothingPublished(f"candidate {candidate} is not a regular file; golden NOT promoted (nothing published, no backup taken)")   # a RuntimeError escaped main() as a traceback
    try:
        lock_fd = os.open(ROTATE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        _tighten_lock(lock_fd)
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
    needed: str | None = None
    try:
        _promote(candidate)
        _record_chain(candidate)   # BEFORE the prune: it could reclaim an old candidate together with the sidecar this reads
    except SplitState as e:
        needed = e.backup   # the recovery copy the message names: never pruned, whatever GOLDEN_KEEP_N says
        prev = chain_length()
        try:
            want = int(candidate_depth_file(candidate).read_text().strip() or "0")
        except (OSError, ValueError):
            want = MAX_CHAIN
        _record_chain(candidate)   # the DISK twin was published: its depth is the candidate's, and the caller removes the candidate next (a record that stayed at the old depth put the master rebake one cycle late, for good)
        now = chain_length()
        record = (f"The chain record now holds the published twin's depth ({now})" if now == want
                  else f"The published twin's depth ({want}) could NOT be recorded (the record reads {now}; see the log above)")
        raise SplitState(f"{e} {record}; if you restore the disk twin by hand instead of restarting, "
                         f"put the previous depth back: sudo sh -c 'printf {prev} > {_chain_file()}; printf {prev} > {_mirror_file()}'.", backup=e.backup) from e
    finally:
        _prune_backups(candidate, also_keep=needed)   # on EVERY outcome — but never the candidate itself: a promotion that failed with NothingPublished KEEPS it for the printed retry, however old it is


def _backup_current() -> str | None:
    """A CHECKED copy of the live golden into the backup dir (None when there is no golden yet).
    Taken only once a promotion is about to publish — a rotation that publishes nothing must not
    add a full-size copy of the unchanged golden that then evicts a genuinely older rollback
    backup. This backup is what a rollback restores from, what _prune_backups keeps as a
    known-good golden, and what the pool-manager's ExecStartPre copies into RAM after a reboot —
    a truncated one (a timeout, ENOSPC) would pass all three, so rc AND size are checked."""
    if not Path(GOLDEN_BASE_DISK).exists():
        return None
    bak = BACKUP_DIR / f"golden-base.{time.strftime('%Y%m%d-%H%M%S', time.gmtime())}.qcow2"   # never a spawned `date`: a fork failure gave "" and a
    # golden-base..qcow2 no prune matches; UTC: the prune sorts the names, and a local-time stamp went backwards across a DST fall-back
    assert _BACKUP_NAME.match(bak.name), bak
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
    # ... and the pool-manager unit's own <RAM base>.?????? (six characters: never the rotator's
    # .rot.XXXXXX, never the base itself): a start killed mid-copy strands one there, and with the
    # unit stopped or latched nothing else reclaims it — the preflight then refused every rotation
    # for lack of space on /dev/shm. Safe here: this runs under the rotation lock, which the unit's
    # copy also holds, so no such copy is in flight.
    for t in Path(GOLDEN_BASE).parent.glob(Path(GOLDEN_BASE).name + ".??????"):
        if t.is_file() and not t.is_symlink():
            logger.info("removing stranded pool-manager temporary %s", t)
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
            raise NothingPublished(f"refusing to promote: {base} is a symlink or a directory, not a regular file; golden NOT promoted (nothing published)")
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
        if bak:   # nothing changed: a backup of the unchanged golden would only evict a real rollback generation
            _run(["sudo", "rm", "-f", bak])
        raise NothingPublished(f"promotion rename -> {GOLDEN_BASE_DISK} failed (rc={r.returncode}); golden NOT promoted (nothing published)")
    r = _run(["sudo", "mv", "-fT", tmps[1], GOLDEN_BASE])
    if r.returncode == 0:
        return
    _cleanup_tmps()
    # SPLIT STATE: disk = new, RAM = old. Everything below must end in a message that says so —
    # a rollback step that itself fails (mktemp ENOSPC, a store gone read-only) must never
    # replace this diagnostic with "nothing published".
    how = "no backup exists to roll back from (nothing was backed up: no golden was on disk before)"
    intact: str | None = None   # the backup a FAILED rollback leaves for the operator
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
            intact = bak
            how = (f"the automatic rollback from {bak} FAILED ({e}; the backup itself is intact) — "
                   f"restore the disk twin by hand: sudo cp {bak} {GOLDEN_BASE_DISK}")
        except Exception as e:  # anything unexpected in the rollback path: still report the split state
            intact = bak
            how = (f"the automatic rollback from {bak} FAILED ({type(e).__name__}: {e}; the backup itself is intact) — "
                   f"restore the disk twin by hand: sudo cp {bak} {GOLDEN_BASE_DISK}")
    if intact:
        # the prune runs on EVERY rotation and every preflight: under GOLDEN_KEEP_N=0 the next night's would remove the
        # copy this message names. A keep sidecar is honoured by every prune until the operator removes it — written
        # beside the backup, else beside the chain mirror (the root filesystem: the store just refused a write), CHECKED
        mark = _mark_kept(intact)
        if mark:
            how += f"; then remove {mark} (it holds the backup out of the prune until you do)"
        else:
            how += f"; the backup could NOT be marked kept (both sidecar writes failed): copy it off {BACKUP_DIR} NOW, the next prune removes it"
    raise SplitState(f"promotion rename -> {GOLDEN_BASE} failed (rc={r.returncode}) AFTER the disk twin was published: "
                     f"DISK {GOLDEN_BASE_DISK} = new golden, RAM {GOLDEN_BASE} = old golden; {how}. "
                     f"Restart winval-pool-manager after clearing /dev/shm to enact the new golden instead.", backup=intact)


_BACKUP_NAME = re.compile(r"^golden-base\.\d{8}-\d{6}\.qcow2$")


def _mtime(p: Path) -> float | None:
    try:
        return p.stat().st_mtime
    except OSError:   # removed between the glob and the stat (a builder reclaiming its own failed candidate is not under the rotation lock)
        return None


_BUILD_HOLD = re.compile(r"^(golden-base\..*\.qcow2)\.keep\.build-(\d+)(?:\.(\d+))?$")   # <backup>.keep.build-<pid>.<starttime> (a start-less one is an earlier format: always stale)


def validate_graveyard(path: str) -> None:
    """GOLDEN_GRAVEYARD's shape, refused before a build or a rotation: golden_build grants its DIRECTORY to the agent inside a
    PowerShell double-quoted string, so it must be an absolute drive path with a directory below the root (a file at C:\\
    would grant the drive; a relative or UNC path grants nothing) and carry no $, backtick or quote (PowerShell expands or
    ends the string there: C:\\gy$dir granted C:\\gy and said 'ok'). Empty = the graveyard is disabled."""
    if not path:
        return
    d = __import__("ntpath").dirname(path)
    if not re.match(r"^[A-Za-z]:\\[^\\]", d) or any(c in path for c in "$`\"'"):
        hint = (" — the value reads without its backslashes: in winval.env single-quote the whole value, as the file says, or the loader eats them"
                if re.match(r"^[A-Za-z]:[^\\\\]", path) else "")
        raise ValueError(f"GOLDEN_GRAVEYARD={path!r} must be an absolute Windows drive path inside a directory, whose own characters include no $ ` or quote "
                         f"(its directory {d!r} is granted to the agent verbatim in PowerShell); UNC, forward-slash and relative paths are refused{hint}")


def validate_warm_dir(path: str) -> None:
    """GOLDEN_WARM_DIR's shape: pasted verbatim into the same PowerShell double-quoted --warm-cache argument (rotate and build),
    so an absolute drive path with no $, backtick or quote — C:\\corp$us expanded to C:\\corp and warmed nothing, silently.
    Empty = no warm-up."""
    if not path:
        return
    if not re.match(r"^[A-Za-z]:\\[^\\]", path) or any(c in path for c in "$`\"'"):
        hint = (" — the value reads without its backslashes: in winval.env single-quote the whole value, as the file says, or the loader eats them"
                if re.match(r"^[A-Za-z]:[^\\\\]", path) else "")
        raise ValueError(f"GOLDEN_WARM_DIR={path!r} must be an absolute Windows drive directory whose own characters include no $ ` or quote (it is passed verbatim to myatg --warm-cache in PowerShell){hint}")


def _proc_start(pid: str) -> str | None:
    """The process's start time (clock ticks since boot, /proc/<pid>/stat field 22): with the pid it names ONE
    process, so a hold is never honoured for a different builder that later got the same number."""
    try:
        st = Path("/proc", pid, "stat").read_text()
        return st[st.rindex(")") + 2:].split()[19]   # fields after the comm: state is #3, starttime #22 -> index 19 past the ")"
    except (OSError, ValueError, IndexError):
        return None


def build_hold_suffix() -> str | None:
    """The sidecar suffix for THIS process's hold on a base it bakes from (golden_build): <pid>.<starttime>, or None when
    the start time cannot be read — a hold written with a made-up start is stale on arrival, and the next prune would
    remove the protection AND the backup under a live build; the caller refuses to build rather than write that."""
    start = _proc_start(str(os.getpid()))
    return f".keep.build-{os.getpid()}.{start}" if start else None


def _held_backups() -> set[str]:
    """The backups every prune must leave: an operator's <backup>.keep (a split state's recovery marker, theirs to
    remove) and a running build's <backup>.keep.build-<pid>.<starttime> (its backing file, held for exactly as long as that
    builder runs — a build that died holds nothing, and its stale sidecar is removed here). Sidecars live beside
    the backups or beside the chain mirror (where _mark_kept falls back to)."""
    held: set[str] = set()
    for d in (BACKUP_DIR, _mirror_file().parent):
        for kp in d.glob("golden-base.*.qcow2.keep*"):
            if kp.name.endswith(".keep"):
                held.add(str((BACKUP_DIR / kp.name[:-len(".keep")]).resolve()))
                continue
            m = _BUILD_HOLD.match(kp.name)
            if not m:
                continue   # not a hold this code writes (.keep.disabled, .keep~ ...): not its to remove
            if m.group(3) and _is_builder(m.group(2)) and _proc_start(m.group(2)) == m.group(3):
                held.add(str((BACKUP_DIR / m.group(1)).resolve()))
            else:
                logger.info("removing stale build hold %s (its builder is gone)", kp.name)
                _run(["sudo", "rm", "-f", str(kp)])
    return held


def _mark_kept(bak: str, suffix: str = ".keep") -> str | None:
    """Hold ``bak`` out of every prune: a checked sidecar beside it, else beside the chain mirror; None when neither
    could be written (the message must then say the copy is NOT held, not name a sidecar that does not exist).
    ``suffix``: ".keep" for the operator's recovery marker, ".keep.build-<pid>.<starttime>" for a build's hold on its base."""
    for d in (BACKUP_DIR, _mirror_file().parent):
        sc = d / (Path(bak).name + suffix)
        _run(["sudo", "mkdir", "-p", str(d)])
        if _run(["sudo", "touch", str(sc)]).returncode == 0 and sc.exists():
            return str(sc)
        logger.error("could not write the keep sidecar %s", sc)
    return None


def _prune_backups(keep: str | None = None, also_keep: str | None = None) -> None:
    """``keep``: a candidate this run is about to promote (the retry CLI's argument) — never
    reclaimed here however old it is, nor its .chain sidecar. ``also_keep``: the backup a split
    state names as the operator's recovery source (SplitState.backup) — kept whatever KEEP_N is."""
    keep_paths = {str(Path(keep).resolve()), str(Path(keep).resolve()) + ".chain"} if keep else set()   # resolved: a relative retry argument must still match the glob's absolute paths
    if also_keep:
        keep_paths.add(str(Path(also_keep).resolve()))
    keep_paths |= _held_backups()   # a split state's recovery copy (until the operator removes the marker) and a running build's base
    # ONLY real backups (golden-base.<YYYYmmdd-HHMMSS>.qcow2) are counted and pruned: a
    # golden_rotate candidate (.candidate-<ts>), a golden_build image (.built-<ts>) or anything
    # else sharing the directory is neither kept as a rollback golden nor allowed to evict one
    # a candidate kept for a retry (NothingPublished) is reclaimed after CANDIDATE_KEEP_DAYS
    cutoff = time.time() - CANDIDATE_KEEP_DAYS * 86400
    for c in BACKUP_DIR.glob("golden-base.*.qcow2"):
        if str(c.resolve()) in keep_paths:
            continue
        if (".candidate-" in c.name or ".built-" in c.name or ".rebake-src-" in c.name) and (_mtime(c) or float("inf")) < cutoff and not _rebake_src_live(c):   # this prune runs FIRST in the preflight: the same live-builder rule as the stranded sweep
            logger.info("pruning stale candidate %s", c.name)
            _run(["sudo", "rm", "-f", str(c)])
    for sc in BACKUP_DIR.glob("golden-base.*.qcow2.chain"):   # a sidecar whose candidate is gone (and not a build in flight)
        if str(sc.resolve()) in keep_paths:
            continue
        if not Path(str(sc)[:-len(".chain")]).exists() and (_mtime(sc) or float("inf")) < time.time() - 3600:
            _run(["sudo", "rm", "-f", str(sc)])
    rec_t = _mtime(_chain_file())
    if rec_t is not None:   # a marker OLDER than the record was superseded by it: age it out (a newer marker IS the record until a newer record lands)
        for mk in BACKUP_DIR.glob("*.chain.unrecorded"):
            if (_mtime(mk) or float("inf")) < min(rec_t, time.time() - 3600):
                _run(["sudo", "rm", "-f", str(mk)])
    # ordered by MODIFICATION TIME (the name as the tie-break): the names are UTC stamps since round 62 but backups made before
    # that are stamped in local time, and in a zone ahead of UTC they sort lexically NEWER than a fresh backup for hours —
    # the prune then deleted the rollback copy it had just made. The mtime is the promotion time on every backup: _backup_current
    # copies it fresh, a restore copies too, and NOTHING else touches a retained backup (the build touches only a candidate
    # image, the age prune's target; a retained backup used as a base is held out of this prune by its sidecar instead)
    baks = sorted((b for b in BACKUP_DIR.glob("golden-base.*.qcow2") if _BACKUP_NAME.match(b.name)), key=lambda b: (_mtime(b) or 0.0, b.name))
    excess = baks[:-KEEP_N] if KEEP_N > 0 else baks   # 0 = keep none (never "never prune")
    for b in excess:
        if str(b.resolve()) in keep_paths:   # the rotate CLI restoring a BACKUP passes it as the candidate: never the one being restored
            continue
        logger.info("pruning old backup %s", b.name)
        _run(["sudo", "rm", "-f", str(b)])


def _write_small(path: str, text: str) -> bool:
    """Root-owned small file next to a root-owned image, written with the arguments QUOTED and
    the result checked (an unquoted redirect truncated at the first space in the path)."""
    # ATOMIC: printf into a sibling temp, then mv over the record — a redirect truncates BEFORE it
    # writes, and a write that then fails (ENOSPC, a store gone read-only) left a 0-byte record that
    # read as depth 0 and reset the master-rebake counter
    r = _run(["sudo", "sh", "-c", 'printf %s "$1" > "$2.tmp" && mv -f "$2.tmp" "$2"', "sh", text, path])
    if r.returncode != 0:
        logger.error("could not write %s (rc=%s): %s", path, r.returncode, r.stderr.strip()[-200:])
        return False
    return True


def _record_chain(candidate: str) -> None:
    """After EVERY promotion (timer, retry CLI, build-and-promote): the golden's chain depth is
    the promoted candidate's depth — 0 for an image built from the base or the master, its
    source's depth + 1 for a rebake — read from the sidecar build_candidate/golden_build wrote."""
    try:
        depth = int(candidate_depth_file(candidate).read_text().strip() or "0")
    except (OSError, ValueError):
        depth = MAX_CHAIN   # unknown provenance: force the master rebake NEXT cycle (0 would postpone it by MAX_CHAIN cycles)
    # the mirror FIRST (the root filesystem's state dir, not the images store): it is the copy that survives
    # the store refusing writes, and chain_length() reads the newer of the two when they disagree
    _run(["sudo", "mkdir", "-p", str(_mirror_file().parent)])
    mirrored = _write_small(str(_mirror_file()), str(depth))
    if _write_small(str(_chain_file()), str(depth)):
        _run(["sudo", "rm", "-f", str(candidate_depth_file(candidate))])
        if not mirrored:
            _run(["sudo", "rm", "-f", str(_mirror_file())])   # a mirror that cannot be REWRITTEN must not keep an old depth (a reset to 0 would be outranked forever)
            logger.warning("chain depth %s recorded beside the golden but NOT in the mirror %s (root filesystem refused a small write?); the stale mirror was removed", depth, _mirror_file())
        return
    if mirrored:
        _run(["sudo", "rm", "-f", str(_chain_file())])   # same: a stale record must not outlive the promotion (the preflight re-seeds it from the mirror)
        logger.warning("chain depth %s NOT recorded beside %s: the images store refused a small write (read-only? full?); the mirror %s holds it, chain_length() reads it, and the next rotation re-seeds the store's record from it", depth, GOLDEN_BASE_DISK, _mirror_file())
        _run(["sudo", "rm", "-f", str(candidate_depth_file(candidate))])
        return
    kept = _keep_as_unrecorded(candidate)   # neither store took a write: the sidecar is the last copy
    if kept:
        logger.error("chain depth %s NOT recorded for %s nor mirrored at %s (both stores refused a small write); kept as %s, which chain_length() reads — no hand-written record is needed once a store accepts writes again", depth, GOLDEN_BASE_DISK, _mirror_file(), unrecorded_marker(candidate))
    else:
        logger.error("chain depth %s is LOST: not recorded for %s, not mirrored at %s, and the sidecar could not be kept either; the count reads %s — write %s to %s by hand once the store accepts writes, or the master rebake is up to %d cycles late", depth, GOLDEN_BASE_DISK, _mirror_file(), chain_length(), depth, _chain_file(), MAX_CHAIN)


class RestartFailed(RuntimeError):
    """restart_pool() could not bring the pool back: systemctl failed, or the unit did not come up after a reset. Distinct from
    the deliberate no-op (an empty GOLDEN_RESTART_SERVICE, a stopped pool), which returns False: a promotion that succeeded is
    still a success, but a pool left DOWN by the restart is what the timer's exit code must say."""


def restart_pool() -> bool:
    """Re-warm the pool off the freshly promoted golden: warm workers keep the OLD golden's inode
    open (the promotion is a rename) and are only ever snapshot-reverted, never respawned, so
    without this nothing puts the new trust state into service. Every promoting entry point
    calls it; the deploy's unit name is the default so a hand-run promotion re-warms too
    (GOLDEN_RESTART_SERVICE= empty disables it). Returns True only when the restart succeeded."""
    svc = os.environ.get("GOLDEN_RESTART_SERVICE", "winval-pool-manager")
    if not svc:
        logger.warning("GOLDEN_RESTART_SERVICE is empty: the promoted golden is NOT in service until winval-pool-manager is restarted")
        return False
    logger.info("restarting %s to warm off the refreshed golden", svc)
    before = (_run(["sudo", "systemctl", "show", "-p", "NRestarts", "--value", svc]).stdout or "").strip()   # a manual restart does NOT reset
    # the counter (measured on a transient unit: 3 before, 3 right after): only a RISE during the settle window is this restart's failing start
    baseline = int(before) if before.isdigit() else 0
    state = _run(["sudo", "systemctl", "is-failed", svc]).stdout.strip()
    if state == "failed":   # crashed or start-limit-latched: clear the latch and bring it back
        _run(["sudo", "systemctl", "reset-failed", svc])
        r = _run(["sudo", "systemctl", "restart", svc], 3600)
    else:   # running -> restart; deliberately stopped -> stays stopped (try-restart)
        r = _run(["sudo", "systemctl", "try-restart", svc], 4500)   # >= the unit's TimeoutStopSec (15 min) + TimeoutStartSec (55 min): a client killed at 60 min reported "NOT in service" about a restart still succeeding
    if r.returncode != 0:
        raise RestartFailed(f"restart of {svc} FAILED (rc={r.returncode}): the pool is still running the OLD golden, or down, until it is restarted by hand")
    active = _run(["sudo", "systemctl", "is-active", svc]).stdout.strip()
    if active not in ("active", "activating"):
        if state == "failed":   # a reset + restart that did not come up is a failure, not a stopped unit
            raise RestartFailed(f"{svc} is {active or 'not active'} after reset-failed + restart: the pool is DOWN until it is started by hand")
        # try-restart of a stopped unit is a successful no-op
        logger.warning("%s is %s (deliberately stopped?): nothing was restarted; the promoted golden is NOT in service until it is started", svc, active or "not active")
        return False
    # Type=simple: the unit is 'active' the instant systemctl returns, before the manager has read a knob or warmed a worker. A
    # start that fails seconds later shows as the unit's auto-restart (Restart=on-failure counts it in NRestarts, which our own
    # restart does not reset: a rise above the baseline read before it) or, once the start limit latches, as 'failed'. Watch it
    # for a settle window before calling the golden in service.
    deadline = time.time() + RESTART_SETTLE_S
    while time.time() < deadline:
        time.sleep(min(5, max(0.0, deadline - time.time())))
        if _run(["sudo", "systemctl", "is-failed", svc]).stdout.strip() == "failed":
            raise RestartFailed(f"{svc} went 'failed' within {RESTART_SETTLE_S}s of the restart: its start is failing (journalctl -u {svc}); the pool is DOWN")
        restarts = (_run(["sudo", "systemctl", "show", "-p", "NRestarts", "--value", svc]).stdout or "").strip()
        if restarts.isdigit() and int(restarts) > baseline:
            raise RestartFailed(f"{svc} auto-restarted {int(restarts) - baseline} time(s) within {RESTART_SETTLE_S}s of the restart: its start is failing (journalctl -u {svc}); the pool is not up")
    if RESTART_SETTLE_S:
        logger.info("%s still up %ds after the restart", svc, RESTART_SETTLE_S)
    return True


def refresh_and_rotate() -> int:
    """The full gated cycle: build a refreshed candidate, validate it, and ONLY promote if it passes.
    A failing gate keeps the current golden and returns non-zero (surfaced to the cron/alert)."""
    rotation_preflight()   # root, lock, space — BEFORE the hour-long build and gate
    src = rebake_source()   # decided ONCE for this cycle
    if src == MASTER_QCOW2:
        # the master is the PACKER image (the bring-up installs it as GOLDEN_MASTER): no agent, no
        # task, no ACLs — a trust refresh alone would fail at C:\agent\myatg.exe. The chain reset
        # (and GOLDEN_REBAKE_FROM=master) is therefore the full reproducible bake: install + compile
        # + refresh + gate + promote, which records depth 0 and restarts the chain.
        logger.info("rebake from the master %s: running the full golden_build bake (the master carries no agent)", MASTER_QCOW2)
        import golden_build   # sibling module; imported lazily (it imports this one)
        return golden_build.build_and_promote(MASTER_QCOW2)
    candidate = build_candidate(src)
    if not validate_golden(candidate):
        logger.error("REBAKE REJECTED: keeping current golden %s; candidate %s discarded",
                     GOLDEN_BASE_DISK, candidate)
        _rm_candidate(candidate)
        return 1
    try:
        rotate(candidate)
    except NothingPublished as e:
        # nothing changed and the candidate is still gated-good: keep it for a retry instead of
        # throwing away the build and the gate boot (it is reclaimed after CANDIDATE_KEEP_DAYS)
        logger.error("%s — candidate KEPT at %s; retry with: sudo %s %s rotate %s", e, candidate, sys.executable, Path(__file__).resolve(), candidate)
        return 1
    except BaseException:
        _rm_candidate(candidate)
        raise
    _rm_candidate(candidate)
    try:
        restarted = restart_pool()
    except RestartFailed as exc:   # the promotion stands; the pool does not: the timer must say so (non-zero) rather than report a success
        logger.error("REBAKE PROMOTED but the restart FAILED (%s); %d backup(s) retained", exc, KEEP_N)
        return 1
    if restarted:
        logger.info("REBAKE PROMOTED: golden refreshed and in service; %d backup(s) retained", KEEP_N)
    else:
        logger.warning("REBAKE PROMOTED but NOT in service until winval-pool-manager is restarted; %d backup(s) retained", KEEP_N)
    return 0


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cmd = argv[0] if argv else "refresh-and-rotate"
    try:
        return _main(cmd, argv)
    except NothingPublished as e:
        logger.error("%s", e)
        return 1
    except SplitState as e:   # the branch's worst outcome must not be the one failure that reaches the journal as a traceback at info
        logger.error("SPLIT STATE: %s", e)
        return 1
    except RuntimeError as e:   # an in-guest step (_ssh_ps check=True), refresh_result, snapshot_source, the staging upload: one ERROR line, not a traceback at info
        logger.error("%s", e)
        return 1


def _main(cmd: str, argv: list[str]) -> int:
    if cmd == "refresh-and-rotate":
        return refresh_and_rotate()
    if cmd == "validate" and len(argv) > 1:
        return 0 if validate_golden(argv[1]) else 1
    if cmd == "rotate" and len(argv) > 1:
        c = Path(argv[1]); g = Path(GOLDEN_BASE_DISK)
        if c.is_symlink() or not c.is_file():
            # BEFORE the preflight: it takes the lock and PRUNES surplus backups keeping only `keep`, and a mistyped
            # candidate matched no file — the oldest rollback backup was deleted and the refusal then said 'no backup
            # taken'. rotate() has the same guard, but it ran after the preflight had already pruned.
            raise NothingPublished(f"candidate {argv[1]} is not a regular file; golden NOT promoted (nothing published, no backup taken, nothing pruned)")
        # the retry is a promoting entry point too: root, lock, space, a writable chain record — sized by
        # the larger of the candidate and the golden the promotion backs up, with the candidate's own
        # allocation already spent
        rotation_preflight(estimate_bytes=max(c.stat().st_size, g.stat().st_size if g.is_file() else 0) if c.is_file() else None, candidate_built=True, keep=str(c), source_copy=False, gate_samples=False)
        rotate(argv[1])
        try:
            restarted = restart_pool()   # the retry path is a promoting entry point too: warm workers ran the old golden
        except RestartFailed as exc:   # the promotion stands; a pool left down is a non-zero exit, as the timer answers it
            logger.error("PROMOTED but the restart FAILED (%s)", exc)
            return 1
        if restarted:
            logger.info("PROMOTED: golden refreshed and in service")
        else:   # a deliberate no-op (GOLDEN_RESTART_SERVICE empty, a stopped pool at bring-up) is not a failed promotion: 0, as the timer and build-and-promote answer it
            logger.warning("PROMOTED but NOT in service until winval-pool-manager is restarted")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
