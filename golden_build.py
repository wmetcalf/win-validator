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
import tempfile
import sys
import time
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)  # import the sibling golden_rotate (libvirt/SSH helpers + gate + rotate)
import golden_rotate as gr
from winval_blastbox.knobs import agent_port

logger = logging.getLogger("winval.golden_build")

BASE_QCOW2 = os.environ.get("GOLDEN_BUILD_BASE") or gr.MASTER_QCOW2   # the packer's output (golden-packer -> winserver2025-core.qcow2), installed as GOLDEN_MASTER: the ONLY image the repo produces
AGENT_DIR = "C:\\agent"
AGENT_PORT = agent_port()   # the pool's knob: the golden LISTENS on it (URL ACL, firewall, task), so changing it means a rebake
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
GV_ARG = f'--gv "{GRAVEYARD}"' if GRAVEYARD else ""          # the in-guest refresh (quoted; absent when disabled, as in golden_rotate)
import ntpath
GV_DIR = ntpath.dirname(GRAVEYARD) if GRAVEYARD else ""       # the directory the serving agent must READ: the grant below follows the knob, not a literal
GV_GRANT_PS = (f'New-Item -Force -ItemType Directory "{GV_DIR}" | Out-Null\n'   # like C:\scan below: a non-default directory the base image never created failed the grant 40 min into the bake
               f'        icacls "{GV_DIR}" /grant "NETWORK SERVICE:(OI)(CI)RX" | Out-Null\n'
               f'        if ($LASTEXITCODE -ne 0) {{ throw "icacls {GV_DIR} failed ($LASTEXITCODE)" }}') if GV_DIR else ""
WARM_PS = f'{AGENT_DIR}\\myatg.exe --warm-cache "{gr.WARM_DIR}" {GV_ARG} | Out-Null;' if gr.WARM_DIR else ""   # same CRL warm-up as the rotator's rebake
GV_TASK = f'--gv \\"{GRAVEYARD}\\"' if GRAVEYARD else ""   # for the --% (stop-parsing) schtasks line below: schtasks' own argv parser reads \" as a literal quote inside /tr, the documented idiom for a quoted path in a task action; absent when disabled (a bare path with a space silently emptied the graveyard)

LENIENT_STEPS = {"ngen", "compile-myatg"}   # they redirect native stderr (2>&1) and check their result themselves

STEPS: list[tuple[str, str]] = [
    ("ngen", f"""
        $ngen='C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\ngen.exe'
        if (-not (Test-Path $ngen)) {{ throw "ngen.exe not found at $ngen" }}
        if ((& $ngen display System.Management.Automation 2>&1) -match 'not installed') {{
            & $ngen executeQueuedItems | Out-Null   # NGen the PS engine so child startup is ~0.5s not ~3s
            if ($LASTEXITCODE -ne 0) {{ throw "ngen executeQueuedItems exited $LASTEXITCODE" }} }}
        'ngen ok'"""),
    ("qemu-ga", r"""
        if (-not (Get-Service QEMU-GA -ErrorAction SilentlyContinue)) {
            $iso = Get-ChildItem 'D:\','E:\' -Filter 'virtio-win-guest-tools.exe' -ErrorAction SilentlyContinue | Select -First 1
            if ($iso) { Start-Process $iso.FullName -ArgumentList '/install','/quiet','/norestart' -Wait }
        }
        'qemu-ga ' + [bool](Get-Service QEMU-GA -ErrorAction SilentlyContinue)"""),   # optional: the pool falls back to SSH for the clock
    ("compile-myatg", f"""
        cmd /c "schtasks /end /tn valagent >nul 2>&1"   # a base that already carries an agent (the live golden, an old candidate) started it at boot: csc cannot overwrite a running myatg.exe
        Stop-Process -Name myatg -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        & '{_CSC}' /nologo /r:System.Security.dll /r:System.ServiceProcess.dll /out:{AGENT_DIR}\\myatg.exe {AGENT_DIR}\\myatg.cs {AGENT_DIR}\\rdp_validate.cs {AGENT_DIR}\\http_serve.cs {AGENT_DIR}\\service.cs 2>&1 | Out-File {AGENT_DIR}\\build.log
        if ($LASTEXITCODE -ne 0) {{ throw "myatg compile failed ($LASTEXITCODE): see {AGENT_DIR}\\build.log" }}   # csc is native: on a base that already carries an agent, Test-Path alone passed with the OLD binary
        if (-not (Test-Path {AGENT_DIR}\\myatg.exe)) {{ throw 'myatg compile failed' }}
        'compiled ' + (Test-Path {AGENT_DIR}\\myatg.exe)"""),
    ("refresh-trust", gr.refresh_ps(GV_ARG, WARM_PS)),   # fails hard in-guest; counts checked below
    ("netsvc-acls", fr"""
        # icacls is a NATIVE command: PowerShell 5.1 raises on its stderr only when redirected, and its exit
        # code is never a terminating error — test $LASTEXITCODE after each, or a failed grant would ship
        # (the agent runs as NETWORK SERVICE: unreadable graveyard = no graveyard hits, silently)
        icacls {AGENT_DIR} /grant "NETWORK SERVICE:(OI)(CI)RX" | Out-Null
        if ($LASTEXITCODE -ne 0) {{ throw "icacls {AGENT_DIR} failed ($LASTEXITCODE)" }}
        {GV_GRANT_PS}
        New-Item -Force -ItemType Directory C:\scan | Out-Null
        icacls C:\scan /grant "NETWORK SERVICE:(OI)(CI)M" | Out-Null
        if ($LASTEXITCODE -ne 0) {{ throw "icacls C:\scan failed ($LASTEXITCODE)" }}
        New-Item -Force -ItemType Directory C:\ProgramData\myatg\uploads | Out-Null
        icacls C:\ProgramData\myatg /grant "NETWORK SERVICE:(OI)(CI)M" | Out-Null   # the agent's upload dir (http_serve.cs): without a grant its write probe fails and it falls back to a %TEMP% path no Defender exclusion covers
        if ($LASTEXITCODE -ne 0) {{ throw "icacls C:\ProgramData\myatg failed ($LASTEXITCODE)" }}
        'acls ok'"""),
    ("http-acl", fr"""
        cmd /c "netsh http delete urlacl url=http://+:{AGENT_PORT}/ >nul 2>&1"   # cmd swallows the stderr: under Stop, PowerShell 5.1 turns a native command's REDIRECTED stderr (2>$null too) into a terminating error, and a fresh image has no ACL to delete
        netsh http add urlacl url=http://+:{AGENT_PORT}/ user="NT AUTHORITY\NETWORK SERVICE" | Out-Null
        if ($LASTEXITCODE -ne 0) {{ throw "netsh http add urlacl failed ($LASTEXITCODE)" }}   # native: see netsvc-acls
        New-NetFirewallRule -DisplayName valagent-{AGENT_PORT} -Direction Inbound -Protocol TCP -LocalPort {AGENT_PORT} -Action Allow -ErrorAction SilentlyContinue | Out-Null
        'http-acl ok'"""),
    ("onstart-agent", fr"""
        cmd /c "schtasks /delete /tn valagent /f >nul 2>&1"   # same: a fresh image has no valagent task, and its 'cannot find the file' would end the step
        # --% hands the rest of the line to schtasks VERBATIM: PowerShell 5.1 neither escapes nor preserves quotes
        # embedded in a native argument (a `" inside "..." reaches schtasks unescaped and splits /tr), so the line
        # is written in schtasks' own syntax — /tr "... --gv \"path\"" — with no PowerShell string in between
        schtasks --% /create /tn valagent /tr "{AGENT_DIR}\myatg.exe --serve-http --bind + --port {AGENT_PORT} --allow-insecure {GV_TASK}" /sc onstart /ru "NT AUTHORITY\NETWORK SERVICE" /rl LIMITED /f
        if ($LASTEXITCODE -ne 0) {{ throw "schtasks /create failed ($LASTEXITCODE)" }}
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
    try:
        gr.validate_graveyard(GRAVEYARD)   # the NETWORK SERVICE grant follows the knob's directory: the shape is refused before anything is built
        gr.validate_warm_dir(gr.WARM_DIR)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    base_is_golden = os.path.realpath(base) == os.path.realpath(gr.GOLDEN_BASE_DISK)
    held_keep: str | None = None   # a .keep sidecar this build holds on a retained backup it backs on (removed in the finally)
    if Path(os.path.realpath(base)).parent == Path(os.path.realpath(str(gr.BACKUP_DIR))):
        # a base chosen from inside the backup dir (an old candidate) is the running build's BACKING file
        # for hours; a concurrent rotation's preflight prunes candidates older than CANDIDATE_KEEP_DAYS,
        # and this build holds no lock while it runs — freshen the mtime so the prune leaves it alone
        if not os.path.isfile(base):   # a typo'd path must not be CREATED by the touch (a 0-byte backup-shaped file would join the rollback set)
            raise SystemExit(f"base {base} does not exist")
        gr._run(["sudo", "touch", os.path.realpath(base)])
        if gr._BACKUP_NAME.match(Path(os.path.realpath(base)).name):   # the file the overlay backs on, as the touch above and the hold below name it: a symlink to a retained backup was touched but never held, and the count prune could take it mid-build
            # a RETAINED backup as the base: the age prune leaves it, the COUNT prune (GOLDEN_KEEP_N) does not — a rotation
            # landing during the build evicted the overlay's backing file. A hold named after THIS build's pid: honoured only
            # while this builder runs (a build that died pins nothing), and distinct from the operator's .keep marker and
            # from another build's hold on the same base
            suffix = gr.build_hold_suffix()
            if suffix is None:   # an unverifiable hold would be reclaimed under this build: refuse rather than bake on a base the prune may take
                raise SystemExit(f"cannot read this process's start time (/proc/{os.getpid()}/stat): refusing to build from the retained backup {base}, whose hold could not be kept")
            held_keep = gr._mark_kept(os.path.realpath(base), suffix=suffix)
            if held_keep is None:   # neither sidecar location took the write: an unheld base is one the count prune may take mid-build
                raise SystemExit(f"could not hold the retained backup {base} out of the prune (no sidecar could be written beside it or beside the chain mirror): refusing to build from it")
    # chain depth is a property of the SOURCE, not of which builder ran: the packer base or the
    # master is depth 0, the live golden is its depth + 1, anything else is unknown provenance
    if base_is_golden:
        depth = -1   # read under the copy's lock below (an unlocked read could pair a new golden with the old depth)
    elif os.path.realpath(base) in (os.path.realpath(BASE_QCOW2), os.path.realpath(gr.MASTER_QCOW2)):
        depth = 0
    else:
        depth = gr.MAX_CHAIN
    base_src = base
    xfd, xml = tempfile.mkstemp(prefix=f"{dom}-", suffix=".xml")   # O_EXCL, unpredictable (see golden_rotate)
    os.close(xfd)
    built = False
    try:   # from here every exit — a failed overlay, XML, define or start included — destroys the domain + overlay
        # the live golden is a promotion target another process can rename over (qcow2 backs by
        # PATH): overlay a private copy of it, as golden_rotate does; the packer base is never renamed
        if base_is_golden:
            _, base_src, at = gr.snapshot_source(ts, base)
            depth = at + 1
        else:
            base_src = base
        r = gr._run(["sudo", "qemu-img", "create", "-f", "qcow2", "-b", base_src, "-F", "qcow2", overlay], 120)
        if r.returncode != 0:   # a missing/unreadable base fails HERE, before any domain is defined: say so, with qemu-img's own words
            raise SystemExit(f"cannot create the build overlay on {base_src} (rc {r.returncode}): {(r.stderr or '').strip()[-400:]}")
        gr._run(["sudo", "chmod", "644", overlay])
        from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime
        rt = LibvirtVmRuntime(LibvirtVmConfig(golden_base=base_src))   # the same image the overlay is backed by
        Path(xml).write_text(rt._domain_xml(dom, overlay))
        for step, args in (("define", (xml,)), ("start", (dom,))):   # virsh's own words, as one logged line — never a bare assert
            r = gr._virsh(step, *args)
            if r.returncode != 0:
                raise gr.NothingPublished(f"virsh {step} failed for the build domain {dom} (rc {r.returncode}): {(r.stderr or '').strip()[-400:]}")
        mac = gr._mac(dom); ip = None; ready = False; dl = time.time() + 240
        while time.time() < dl:
            ip = gr._ip_for_mac(mac) if mac else None
            if ip and "READY" in gr._ssh_ps(ip, "'READY'", 15):
                ready = True
                break
            time.sleep(5)
        if not ready:   # an address without an answer is the usual shape of a WRONG KEY, said so here rather than as scp's 'Permission denied'
            raise gr.NothingPublished(f"guest {ip or 'never got an address'} did not answer over ssh within 240s: is {gr.SSH_KEY} the key the image authorises "
                                      "(the packer build's keys/build_key — the image accepts no other)?")
        # the packer image has no agent directory: scp cannot create a parent, so the first upload
        # of a build from the master failed before any step ran
        gr._ssh_ps(ip, f"New-Item -Force -ItemType Directory '{AGENT_DIR}' | Out-Null", 60, check=True)
        for src, dst in STAGE:
            if Path(src).exists():
                r = gr._run(["scp", "-i", gr.SSH_KEY, "-o", "StrictHostKeyChecking=no",
                             "-o", "UserKnownHostsFile=/dev/null", src, f"Administrator@{ip}:{dst}"], 60)
                if r.returncode != 0:   # an unchecked upload would compile the base image's stale copy
                    raise RuntimeError(f"staging {src} -> {dst} failed (rc={r.returncode}): {r.stderr.strip()[-300:]}")
        for name, ps in STEPS:
            logger.info("step %s …", name)
            # EVERY step is checked: a throw, a native failure or a timeout raises with the
            # guest's stderr, so a build never flattens an image a step failed to prepare
            # every step under Stop: a failing cmdlet is a terminating error and a non-zero exit
            # (a native command's failure is still only $LASTEXITCODE — steps that run one test it)
            # cmdlet steps run under Stop so a failing cmdlet is a terminating error; the two steps
            # that capture NATIVE stderr with 2>&1 (ngen, csc) must not — under Stop a benign stderr
            # line becomes a NativeCommandError — and they assert their own outcome instead
            strict = name not in LENIENT_STEPS
            out = gr._ssh_ps(ip, ("$ErrorActionPreference = 'Stop'; " if strict else "") + ps, 600, check=True)
            logger.info("  %s -> %s", name, out.replace("\n", " ")[:120])
            if name == "refresh-trust":
                gr.refresh_result(out)
            if name == "qemu-ga" and "False" in out:   # optional (the pool syncs the clock over SSH without it): report, never block the build
                logger.warning("qemu-ga is not installed in the guest (no virtio-win-guest-tools.exe on D:/E:); the pool will use the SSH clock fallback")
        gr._ssh_ps(ip, "Stop-Computer -Force", 20)
        dl = time.time() + 180
        state = ""
        while time.time() < dl and "shut off" not in (state := gr._virsh("domstate", dom).stdout):
            time.sleep(3)
        if "shut off" not in state:   # never flatten a running domain (a crash-inconsistent image the gate may still pass)
            raise gr.NothingPublished(f"guest {dom} did not shut off within 180s (domstate: {state.strip() or 'unknown'}); refusing to flatten a running domain into a candidate")
        logger.info("flattening -> %s", candidate)
        rc = gr._run(["sudo", "qemu-img", "convert", "-O", "qcow2", overlay, candidate], gr.CONVERT_TIMEOUT_S).returncode
        if rc != 0:
            raise gr.NothingPublished(f"flatten (qemu-img convert) {'timed out after %ds' % gr.CONVERT_TIMEOUT_S if rc == 124 else 'failed (rc=%s)' % rc}")
        gr._run(["sudo", "chmod", "644", candidate])
        built = True
    finally:
        gr._virsh("destroy", dom); gr._virsh("undefine", dom, "--snapshots-metadata")
        gr._run(["sudo", "rm", "-f", overlay, xml] + ([base_src] if base_src != base else []))   # the private base copy is flattened into the candidate
        if held_keep:
            gr._run(["sudo", "rm", "-f", held_keep])   # the backup is the prune's again
        if not built:
            gr._rm_candidate(candidate)   # a failed/timed-out convert leaves a full-size partial
    gr._write_small(str(gr.candidate_depth_file(candidate)), str(depth))   # travels with the candidate into rotate()
    return candidate


def build_and_promote(base: str = BASE_QCOW2) -> int:
    # root, lock, samples, space — BEFORE the build and the gate; sized by THIS entry point's base
    # (on a first-run host there is no golden and no master to estimate from)
    if not Path(base).is_file():
        raise gr.NothingPublished(f"build base {base} is not a file: set GOLDEN_BUILD_BASE in winval.env (or pass the path) to the post-OS-install image")
    # the run's peak is the larger of the base being built and the GOLDEN the promotion backs up
    # (grown by the agent, ngen images and every cycle's trust state — the lean packer master understates it)
    golden = Path(gr.GOLDEN_BASE_DISK)
    gr.rotation_preflight(estimate_bytes=max(Path(base).stat().st_size, golden.stat().st_size if golden.is_file() else 0),
                          source_copy=os.path.realpath(base) == os.path.realpath(gr.GOLDEN_BASE_DISK),   # only a build FROM the golden takes a private copy
                          keep=base)   # a base chosen from inside the backup dir (an old candidate) must survive the preflight's prune
    candidate = build(base)
    if not gr.validate_golden(candidate):
        logger.error("BUILD REJECTED: candidate %s failed the gate; not promoted", candidate)
        gr._rm_candidate(candidate)
        return 1
    try:
        gr.rotate(candidate)
    except gr.NothingPublished as e:
        logger.error("%s — candidate KEPT at %s; retry with: sudo %s %s rotate %s", e, candidate, sys.executable, Path(gr.__file__).resolve(), candidate)
        return 1
    except BaseException:
        gr._rm_candidate(candidate)
        raise
    gr._rm_candidate(candidate)
    if gr.restart_pool():   # warm workers ran the old golden; without this the build is not "live"
        logger.info("BUILD PROMOTED: reproducible golden built + gated + live")
    else:
        logger.warning("BUILD PROMOTED but NOT live: restart winval-pool-manager to put it in service")
    return 0


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        return _main(argv)
    except gr.NothingPublished as e:
        logger.error("%s", e)
        return 1
    except gr.SplitState as e:   # the worst outcome must not be the one failure that reaches the journal as a traceback
        logger.error("SPLIT STATE: %s", e)
        return 1
    except RuntimeError as e:   # an in-guest step, the staging upload, snapshot_source: one ERROR line, not a traceback at info
        logger.error("%s", e)
        return 1


def _main(argv: list[str]) -> int:
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
    if cmd == "build-and-promote":   # optional base path, like `build`; else GOLDEN_BUILD_BASE
        return build_and_promote(argv[1] if len(argv) > 1 else BASE_QCOW2)
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
