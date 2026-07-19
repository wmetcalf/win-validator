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
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

logger = logging.getLogger("winval.golden_rotate")

MASTER_DOMAIN = os.environ.get("GOLDEN_MASTER_DOMAIN", "winserver2025-core")
MASTER_QCOW2 = os.environ.get("GOLDEN_MASTER", "/var/lib/libvirt/images/winserver2025-core.qcow2")
GOLDEN_BASE = os.environ.get("GOLDEN_BASE", "/dev/shm/golden-base.qcow2")
GOLDEN_BASE_DISK = os.environ.get("GOLDEN_BASE_DISK", "/var/lib/libvirt/images/golden-base.qcow2")
BACKUP_DIR = Path(os.environ.get("GOLDEN_BACKUP_DIR", "/var/lib/libvirt/images/golden-backups"))
KEEP_N = int(os.environ.get("GOLDEN_KEEP_N", "5"))
SSH_KEY = os.environ.get("AUTHENTICODE_SSH_KEY", "/home/coz/.ssh/win_golden")
GRAVEYARD = os.environ.get("GOLDEN_GRAVEYARD", "C:\\certgraveyard\\cert_graveyard_database.csv")
BENIGN = os.environ.get("GOLDEN_BENIGN_SAMPLE", "/tmp/whoami.exe")
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


def _ssh_ps(ip: str, ps: str, t: float = 300) -> str:
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    return _run(["ssh", "-n", *_SSH, f"Administrator@{ip}",
                 "powershell -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + enc], t).stdout.strip()


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
    assert _run(["sudo", "qemu-img", "create", "-f", "qcow2", "-b", MASTER_QCOW2, "-F", "qcow2",
                 overlay], 120).returncode == 0, "overlay create failed"
    _run(["sudo", "chmod", "644", overlay])
    # define+boot the overlay domain (reuse the runtime's XML generator for a real worker shape)
    from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime
    rt = LibvirtVmRuntime(LibvirtVmConfig(golden_base=MASTER_QCOW2))
    xml_path = f"/tmp/{dom}.xml"
    Path(xml_path).write_text(rt._domain_xml(dom, overlay))
    assert _virsh("define", xml_path).returncode == 0, "define failed"
    assert _virsh("start", dom).returncode == 0, "start failed"
    try:
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
        out = _ssh_ps(ip, f'$j = C:\\agent\\myatg.exe --refresh {gv} | ConvertFrom-Json; {warm} '
                          '"disallowed=" + $j.disallowed_store_count + " roots=" + $j.roots_synced', 600)
        logger.info("refresh result: %s", out)
        _ssh_ps(ip, "Stop-Computer -Force", 20)
        dl = time.time() + 180
        while time.time() < dl and "shut off" not in _virsh("domstate", dom).stdout:
            time.sleep(3)
        logger.info("flattening overlay -> candidate %s", candidate)
        assert _run(["sudo", "qemu-img", "convert", "-O", "qcow2", overlay, candidate], 900).returncode == 0
        _run(["sudo", "chmod", "644", candidate])
    finally:
        _virsh("destroy", dom)
        _virsh("undefine", dom, "--snapshots-metadata")
        _run(["sudo", "rm", "-f", overlay, xml_path])
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


def rotate(candidate: str) -> None:
    """Back up the current live golden (keep the last N), then promote ``candidate`` into place."""
    _ensure_backup_dir()
    ts = _run(["date", "+%Y%m%d-%H%M%S"]).stdout.strip()
    if Path(GOLDEN_BASE_DISK).exists():
        bak = BACKUP_DIR / f"golden-base.{ts}.qcow2"
        logger.info("backing up current golden -> %s", bak)
        _run(["sudo", "cp", "--reflink=auto", GOLDEN_BASE_DISK, str(bak)], 600)
    logger.info("promoting candidate -> %s (+ %s)", GOLDEN_BASE_DISK, GOLDEN_BASE)
    _run(["sudo", "cp", "--reflink=auto", candidate, GOLDEN_BASE_DISK + ".new"], 600)
    _run(["sudo", "mv", GOLDEN_BASE_DISK + ".new", GOLDEN_BASE_DISK])
    _run(["sudo", "cp", "--reflink=auto", GOLDEN_BASE_DISK, GOLDEN_BASE + ".new"], 600)
    _run(["sudo", "mv", GOLDEN_BASE + ".new", GOLDEN_BASE])
    _run(["sudo", "chmod", "644", GOLDEN_BASE_DISK, GOLDEN_BASE])
    _prune_backups()


def _prune_backups() -> None:
    baks = sorted(BACKUP_DIR.glob("golden-base.*.qcow2"))
    excess = baks[:-KEEP_N] if KEEP_N > 0 else []
    for b in excess:
        logger.info("pruning old backup %s", b.name)
        _run(["sudo", "rm", "-f", str(b)])


def refresh_and_rotate() -> int:
    """The full gated cycle: build a refreshed candidate, validate it, and ONLY promote if it passes.
    A failing gate keeps the current golden and returns non-zero (surfaced to the cron/alert)."""
    candidate = build_candidate()
    if not validate_golden(candidate):
        logger.error("REBAKE REJECTED: keeping current golden %s; candidate %s discarded",
                     GOLDEN_BASE_DISK, candidate)
        _run(["sudo", "rm", "-f", candidate])
        return 1
    rotate(candidate)
    _run(["sudo", "rm", "-f", candidate])
    svc = os.environ.get("GOLDEN_RESTART_SERVICE")
    if svc:  # re-warm the pool off the freshly promoted golden (old warm workers ran the old base)
        logger.info("restarting %s to warm off the refreshed golden", svc)
        _run(["sudo", "systemctl", "restart", svc])
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
