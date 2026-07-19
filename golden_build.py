"""Reproducible golden BUILDER — one declarative, ordered, idempotent pipeline.

Consolidates the hand-run bake_*.py scripts into a single recipe: boot a base WS2025 qcow2 ONCE,
run the ordered provisioner STEPS in-guest, flatten, validation-gate, and promote — so the golden is
rebuildable from a base instead of a pile of one-off bakes. The slow OS install (autounattend on a
genisoimage OEMDRV CD + the send-key boot loop — toolz3's slirpless qemu can't use Packer's qemu
builder) produces the BASE qcow2 once; this builder owns everything layered on top of it.

Each STEP is idempotent (skip-if-already-done) so a re-run is cheap and a partial failure resumes.
Reuses golden_rotate for the libvirt/SSH helpers, the validation GATE, and the backup-rotation
promote — so a freshly built golden ships ONLY if it passes benign==Valid (+ optional revoked).

  build()  base.qcow2 -> overlay -> [steps in order] -> Stop-Computer -> flatten -> candidate.qcow2
  then golden_rotate.validate_golden(candidate) gate, then golden_rotate.rotate(candidate) promote.

  python golden_build.py steps                 # print the ordered recipe (dry run)
  python golden_build.py build [base.qcow2]    # build a candidate (no promote)
  python golden_build.py build-and-promote     # build -> gate -> promote (the full reproducible run)
"""
from __future__ import annotations

import logging
import os
import sys
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)  # import the sibling golden_rotate (libvirt/SSH helpers + gate + rotate)
import golden_rotate as gr

logger = logging.getLogger("winval.golden_build")

BASE_QCOW2 = os.environ.get("GOLDEN_BUILD_BASE", "/var/lib/libvirt/images/winserver2025-base.qcow2")
AGENT_DIR = "C:\\agent"
GRAVEYARD = os.environ.get("GOLDEN_GRAVEYARD", "C:\\certgraveyard\\cert_graveyard_database.csv")
# The myatg validator sources compiled in-guest. Point MYATG_SRC at a myatg checkout
# (github.com/wmetcalf/myatg); defaults to a sibling `../myatg` clone next to this repo.
MYATG_SRC = os.environ.get("MYATG_SRC", os.path.join(os.path.dirname(_HERE), "myatg"))
_MYATG_FILES = ["myatg.cs", "rdp_validate.cs", "http_serve.cs", "service.cs"]
# Host files staged into the guest before the steps run (scp): the myatg sources compiled in-guest
# (native HTTP serve mode — `myatg --serve-http`, superseding the old PowerShell agent shim).
STAGE = [(os.path.join(MYATG_SRC, f), f"{AGENT_DIR}/{f}") for f in _MYATG_FILES]

# Ordered, idempotent in-guest provisioner steps. Each: (name, powershell). The powershell should be
# safe to re-run (check-then-act). The heavy OS hardening / cert-store / graveyard-pull steps are in
# the BASE image; this layer is the worker value-add (agent runtime, perf, trust freshness).
_CSC = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\csc.exe"
STEPS: list[tuple[str, str]] = [
    ("ngen", f"""
        $ngen='C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\ngen.exe'
        if ((& $ngen display System.Management.Automation 2>&1) -match 'not installed') {{
            & $ngen executeQueuedItems | Out-Null }}   # NGen the PS engine so child startup is ~0.5s not ~3s
        'ngen ok'"""),
    ("qemu-ga", r"""
        if (-not (Get-Service QEMU-GA -ErrorAction SilentlyContinue)) {
            $iso = Get-ChildItem 'D:\','E:\' -Filter 'virtio-win-guest-tools.exe' -ErrorAction SilentlyContinue | Select -First 1
            if ($iso) { Start-Process $iso.FullName -ArgumentList '/install','/quiet','/norestart' -Wait }
        }
        'qemu-ga ' + [bool](Get-Service QEMU-GA -ErrorAction SilentlyContinue)"""),
    ("compile-myatg", f"""
        & '{_CSC}' /nologo /r:System.Security.dll /r:System.ServiceProcess.dll /out:{AGENT_DIR}\\myatg.exe {AGENT_DIR}\\myatg.cs {AGENT_DIR}\\rdp_validate.cs {AGENT_DIR}\\http_serve.cs {AGENT_DIR}\\service.cs 2>&1 | Out-File {AGENT_DIR}\\build.log
        if (-not (Test-Path {AGENT_DIR}\\myatg.exe)) {{ throw 'myatg compile failed' }}
        'compiled ' + (Test-Path {AGENT_DIR}\\myatg.exe)"""),
    ("refresh-trust", f"""
        $j = {AGENT_DIR}\\myatg.exe --refresh --gv "{GRAVEYARD}" | ConvertFrom-Json
        'disallowed=' + $j.disallowed_store_count + ' roots=' + $j.roots_synced"""),
    ("netsvc-acls", fr"""
        icacls {AGENT_DIR} /grant "NETWORK SERVICE:(OI)(CI)RX" | Out-Null
        icacls C:\certgraveyard /grant "NETWORK SERVICE:(OI)(CI)RX" | Out-Null
        New-Item -Force -ItemType Directory C:\scan | Out-Null
        icacls C:\scan /grant "NETWORK SERVICE:(OI)(CI)M" | Out-Null
        'acls ok'"""),
    ("http-acl", r"""
        netsh http delete urlacl url=http://+:8765/ 2>$null | Out-Null
        netsh http add urlacl url=http://+:8765/ user="NT AUTHORITY\NETWORK SERVICE" | Out-Null
        New-NetFirewallRule -DisplayName valagent-8765 -Direction Inbound -Protocol TCP -LocalPort 8765 -Action Allow -ErrorAction SilentlyContinue | Out-Null
        'http-acl ok'"""),
    ("onstart-agent", fr"""
        schtasks /delete /tn valagent /f 2>$null | Out-Null
        schtasks /create /tn valagent /tr "{AGENT_DIR}\myatg.exe --serve-http --bind + --port 8765 --allow-insecure --gv {GRAVEYARD}" /sc onstart /ru "NT AUTHORITY\NETWORK SERVICE" /rl LIMITED /f | Out-Null
        (schtasks /query /tn valagent /v /fo list | Select-String 'Task To Run')"""),
]


def build(base: str = BASE_QCOW2) -> str:
    """Boot ``base`` as an overlay, stage files, run the STEPS in order, flatten -> candidate qcow2."""
    missing = [f for f in _MYATG_FILES if not Path(os.path.join(MYATG_SRC, f)).exists()]
    if missing:
        raise SystemExit(
            f"myatg sources not found in MYATG_SRC={MYATG_SRC!r}: {missing}. "
            "Set MYATG_SRC to a myatg checkout (github.com/wmetcalf/myatg) or clone it as ../myatg.")
    ts = gr._run(["date", "+%Y%m%d-%H%M%S"]).stdout.strip()
    dom = f"golden-build-{ts}"
    overlay = f"/dev/shm/{dom}.qcow2"
    candidate = f"{gr.BACKUP_DIR}/golden-base.built-{ts}.qcow2"
    gr._ensure_backup_dir()
    gr._virsh("destroy", dom); gr._virsh("undefine", dom, "--snapshots-metadata")
    gr._run(["sudo", "rm", "-f", overlay])
    assert gr._run(["sudo", "qemu-img", "create", "-f", "qcow2", "-b", base, "-F", "qcow2", overlay], 120).returncode == 0
    gr._run(["sudo", "chmod", "644", overlay])
    from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime
    rt = LibvirtVmRuntime(LibvirtVmConfig(golden_base=base))
    xml = f"/tmp/{dom}.xml"; Path(xml).write_text(rt._domain_xml(dom, overlay))
    assert gr._virsh("define", xml).returncode == 0
    assert gr._virsh("start", dom).returncode == 0
    try:
        mac = gr._mac(dom); ip = None; dl = time.time() + 240
        while time.time() < dl:
            ip = gr._ip_for_mac(mac) if mac else None
            if ip and "READY" in gr._ssh_ps(ip, "'READY'", 15):
                break
            time.sleep(5)
        assert ip, "guest never reachable"
        for src, dst in STAGE:
            if Path(src).exists():
                gr._run(["scp", "-i", gr.SSH_KEY, "-o", "StrictHostKeyChecking=no",
                         "-o", "UserKnownHostsFile=/dev/null", src, f"Administrator@{ip}:{dst}"], 60)
        for name, ps in STEPS:
            logger.info("step %s …", name)
            out = gr._ssh_ps(ip, ps, 600)
            logger.info("  %s -> %s", name, out.replace("\n", " ")[:120])
        gr._ssh_ps(ip, "Stop-Computer -Force", 20)
        dl = time.time() + 180
        while time.time() < dl and "shut off" not in gr._virsh("domstate", dom).stdout:
            time.sleep(3)
        logger.info("flattening -> %s", candidate)
        assert gr._run(["sudo", "qemu-img", "convert", "-O", "qcow2", overlay, candidate], 900).returncode == 0
        gr._run(["sudo", "chmod", "644", candidate])
    finally:
        gr._virsh("destroy", dom); gr._virsh("undefine", dom, "--snapshots-metadata")
        gr._run(["sudo", "rm", "-f", overlay, xml])
    return candidate


def build_and_promote() -> int:
    candidate = build()
    if not gr.validate_golden(candidate):
        logger.error("BUILD REJECTED: candidate %s failed the gate; not promoted", candidate)
        gr._run(["sudo", "rm", "-f", candidate])
        return 1
    gr.rotate(candidate)
    gr._run(["sudo", "rm", "-f", candidate])
    logger.info("BUILD PROMOTED: reproducible golden built + gated + live")
    return 0


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    cmd = argv[0] if argv else "steps"
    if cmd == "steps":
        print("staged files:")
        for s, d in STAGE:
            print(f"  {s} -> {d}")
        print("ordered provisioner steps:")
        for i, (name, _) in enumerate(STEPS, 1):
            print(f"  {i}. {name}")
        return 0
    if cmd == "build":
        print(build(argv[1] if len(argv) > 1 else BASE_QCOW2))
        return 0
    if cmd == "build-and-promote":
        return build_and_promote()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
