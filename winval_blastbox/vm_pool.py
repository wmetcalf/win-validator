"""Phase 3 — drive the authenticode VM workers through blastbox's generic WarmPool.

Replaces the bespoke round-robin ``WorkerPool`` with ``WarmPool`` over ``LibvirtVmRuntime``,
built from a ``vm_compose`` spec. The pool gets warm-spawn / burst / health / spawn-rate-limit
and the reuse-after-N path for free; ``jobs_per_recycle`` comes from the engine's risk×cost
declaration (``AuthenticodeEngine.jobs_per_recycle``), defaulting to the safe 1.

``WarmVmPool`` exposes the same ``start()/validate(path)/shutdown()`` surface the engine used
before, so ``engine.get_pool()`` swaps cleanly. ``validate()`` claims a warm slot, talks the
length-prefixed myatg protocol to its agent ``endpoint``, and releases it (reuse-with-recycle
handled by the pool).
"""
from __future__ import annotations

import base64
import datetime
import json
import logging
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request

from blastbox.host.netwire import parse_egress_ports, parse_strict_bool
from blastbox.host.runtime.libvirt_egress import ExitRouting, VmEgressPolicy
from blastbox.host.runtime.vm_compose import VmImageSpec, VmWorkerSpec

from .knobs import agent_port, env_int

logger = logging.getLogger("winval.vm_pool")


def pool_size() -> int:
    """AUTHENTICODE_POOL_SIZE — the ONE reader for the warm size and the claim concurrency: an empty or
    non-numeric value is a warning plus the default (2) instead of a bare traceback that latches the
    unit failed; 0 or less (a pool that could never warm) is raised to 1."""
    return env_int("AUTHENTICODE_POOL_SIZE", 2, floor=1)


# Per-job myatg overrides that are safe to vary per REQUEST (myatg exposes them as query params on
# --serve-http). `gv` (graveyard) and `max-size` are server-global — baked into the golden's serve
# startup — so they are NOT here; a per-job gv/tier can't be applied and the engine says so.
_PER_REQUEST_PARAMS = ("rev", "scripts")

# the guest agent's verdict is read in full and then written twice (the artifact and the envelope's
# authenticode_json field) and copied once more into JOB_ROOT by the pool-manager: a VM that answers
# with gigabytes (a myatg fault on a crafted sample) would fill the host. Bounded here, at the source.
AGENT_RESPONSE_MAX = env_int("WINVAL_AGENT_RESPONSE_MB", 64, floor=1) * (1 << 20)


def agent_validate(endpoint: tuple[str, int], path: str, timeout: float = 60.0,
                   params: dict | None = None) -> dict:
    """Validate a file via the myatg guest agent's HTTP API:
    ``POST http://<ip>:<port>/validate?name=<filename>[&rev=..&scripts=..]`` with the raw file bytes
    as the body, returning the verdict JSON. The filename is passed for extension-based routing
    (.rdp / script SIP type) only — myatg verdicts are content-hashed, so the base name is irrelevant.
    ``params`` carries per-request myatg overrides (``rev`` / ``scripts``); myatg validates the values
    itself and falls back to its startup defaults on an unknown one."""
    host, port = endpoint
    with open(path, "rb") as fh:
        data = fh.read()
    q = {"name": os.path.basename(path)}
    for k in _PER_REQUEST_PARAMS:
        if params and params.get(k):
            q[k] = str(params[k])
    url = f"http://{host}:{port}/validate?" + urllib.parse.urlencode(q)
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        body = r.read(AGENT_RESPONSE_MAX + 1)
    if len(body) > AGENT_RESPONSE_MAX:
        raise RuntimeError(f"the guest agent's verdict exceeds {AGENT_RESPONSE_MAX} bytes (WINVAL_AGENT_RESPONSE_MB); "
                           "refusing to publish it")
    return json.loads(body)




def _egress_ports(raw: str | None) -> tuple[int, ...] | None:
    ports = parse_egress_ports(raw)
    if ports and raw:
        def _kept(t: str) -> bool:   # the PARSER's own verdict per token (isdigit()/int() re-derived it wrongly: '²' raised, '+443' was reported dropped though honoured)
            try:
                return bool(parse_egress_ports(t))
            except ValueError:
                return False
        dropped = [t for t in re.split(r"[,\s]+", raw.strip()) if t and not _kept(t)]
        if dropped:   # blastbox's parser skips a token it cannot read (a range, a name) silently: the operator must hear which
            logger.warning("AUTHENTICODE_EGRESS_PORTS=%r: %s dropped (comma- or space-separated port NUMBERS 1..65535 only); allowing %s", raw, dropped, list(ports))
    if ports is None and raw is not None:   # PRESENT but parsing to nothing (blank included) is CLOSED, as vm_compose._ports reads a YAML value
        logger.error("AUTHENTICODE_EGRESS_PORTS=%r parses to no port at all (comma- or space-separated numbers 1..65535): the allowlist is CLOSED, not open", raw)
        return ()
    return ports


def validate_egress_posture(spec: VmWorkerSpec) -> None:
    """The refusals LibvirtEgress.apply() makes at worker spawn (a routed exit without ExitRouting, inetsim
    without a FakeNet sink, an unsupported exit driver, a shared-router VPN with gateway xor leg), checked
    without a worker: the rotation preflight refuses a bad posture before the hour-long build, and the pool
    refuses it before booting a VM. The rooter's own check stays the enforcement; this only moves the error
    earlier (the exit sets are imported from blastbox so the two cannot drift apart)."""
    try:   # private names, imported so the sets cannot drift from blastbox's own; a blastbox without them must not escape as an ImportError traceback
        from blastbox.host.runtime.libvirt_egress import _ROUTING_DRIVERS, _SUPPORTED_EXITS
        from blastbox.host.runtime.libvirt_vm import _parse_ip_pool
    except ImportError as exc:
        try:
            import importlib.metadata
            ver = importlib.metadata.version("blastbox")
        except Exception:   # a source checkout on PYTHONPATH has no dist metadata — and PackageNotFoundError IS an ImportError, which must not escape here
            import blastbox
            ver = getattr(blastbox, "__version__", None) or f"an unversioned checkout at {os.path.dirname(blastbox.__file__)}"
        raise RuntimeError(f"the installed blastbox ({ver}) lacks a name this posture check relies on ({exc}); upgrade blastbox (deploy/README.md pins the minimum)") from exc
    if spec.worker_ip_pool:   # parsed only inside LibvirtVmRuntime.__init__ otherwise: the one AUTHENTICODE_* knob that could still fail after the build
        try:
            _parse_ip_pool(spec.worker_ip_pool)
        except ValueError as exc:
            raise ValueError(f"AUTHENTICODE_IP_POOL={spec.worker_ip_pool!r} is not a usable range ({exc})") from exc
    pol, rt = spec.egress, spec.routing
    if pol is None:
        return
    if pol.exit_driver in _ROUTING_DRIVERS and rt is None:
        raise ValueError(f"AUTHENTICODE_EXIT={pol.exit_driver!r} needs the exit routing knobs (a filter-only policy would leak via the host route)")
    if pol.exit_driver == "inetsim" and not (rt and rt.fakenet_addr):
        raise ValueError("AUTHENTICODE_EXIT=inetsim needs AUTHENTICODE_FAKENET_ADDR (the FakeNet sink)")
    if pol.exit_driver not in _SUPPORTED_EXITS:
        raise ValueError(f"AUTHENTICODE_EXIT={pol.exit_driver!r} is not an exit the VM rooter supports ({', '.join(sorted(_SUPPORTED_EXITS))})")
    if pol.exit_driver in ("openvpn", "wireguard") and rt is not None and bool(rt.gateway) != bool(rt.leg):
        raise ValueError(f"AUTHENTICODE_EXIT={pol.exit_driver!r} shared-router mode needs BOTH AUTHENTICODE_GATEWAY and AUTHENTICODE_LEG (got gateway={rt.gateway!r}, leg={rt.leg!r})")


def authenticode_spec() -> VmWorkerSpec:
    """Build the authenticode VM-worker spec from AUTHENTICODE_* env (golden, pool size, agent,
    optional egress: AUTHENTICODE_EXIT/EGRESS_PORTS/BLOCK_INTERNAL/VPN_TABLE/...)."""
    exit_driver = os.environ.get("AUTHENTICODE_EXIT")
    egress = routing = None
    if exit_driver:
        egress = VmEgressPolicy(
            exit_driver=exit_driver,
            # blastbox's own fail-closed parsers: a typo in a SECURITY knob must raise (BLOCK_INTERNAL=treu) or be
            # dropped (a port outside 1..65535), never read as "off" or written into a broken --dports —
            # and a value GIVEN but wholly unparsable ('8080-8090', 'http,https') is a CLOSED allowlist (), never
            # None, which the rooter reads as "no allowlist: ACCEPT" (blastbox's own YAML path does the same)
            egress_ports=_egress_ports(os.environ.get("AUTHENTICODE_EGRESS_PORTS")),
            block_internal=parse_strict_bool(os.environ.get("AUTHENTICODE_BLOCK_INTERNAL")),
        )
        routing = ExitRouting(
            vpn_table=os.environ.get("AUTHENTICODE_VPN_TABLE", "vpn"),
            vpn_tun=os.environ.get("AUTHENTICODE_VPN_TUN", "tun0"),
            fakenet_addr=os.environ.get("AUTHENTICODE_FAKENET_ADDR") or None,
            gateway=os.environ.get("AUTHENTICODE_GATEWAY") or None,
            leg=os.environ.get("AUTHENTICODE_LEG") or None,
        )
    return VmWorkerSpec(
        name="authenticode",
        image=VmImageSpec(golden=os.environ.get("AUTHENTICODE_GOLDEN_BASE", "/dev/shm/golden-base.qcow2")),
        agent_port=agent_port(),
        warm_size=pool_size(),
        egress=egress,
        routing=routing,
        # Assign+enforce (blastbox >= 0.1.18): when AUTHENTICODE_IP_POOL is set (e.g.
        # "192.168.122.200-192.168.122.249", one /16, sized >= POOL_SIZE), blastbox reserves + pins a
        # fixed IP per worker so a root-compromised guest can't re-IP around the egress rooter. Empty
        # ⇒ DHCP-learning (clean-traffic CTRL_IP_LEARNING=dhcp).
        worker_ip_pool=os.environ.get("AUTHENTICODE_IP_POOL", ""),
    )


def _smoke(slot) -> bool:
    """Health smoke test: send a known benign signed sample to the agent and assert the expected
    verdict — proves the OS is up, the agent returns, AND cert validation actually works (not just
    a port-open check). Opt-in via AUTHENTICODE_SMOKE_SAMPLE (default expected status Valid)."""
    sample = os.environ.get("AUTHENTICODE_SMOKE_SAMPLE")
    expect = os.environ.get("AUTHENTICODE_SMOKE_EXPECT", "Valid")
    try:
        v = agent_validate(slot.endpoint, sample, timeout=30.0)
    except Exception:
        return False
    return isinstance(v, dict) and v.get("status") == expect


def _warm_crl(slot) -> None:
    """Pre-snapshot CRL/OCSP warm: validate every benign sample in AUTHENTICODE_WARM_DIR with
    online revocation, so the major CAs' CRLs are fetched+cached and the snapshot captures a hot
    cache (warm-restores then serve revocation from cache, no per-job live fetch)."""
    warm_dir = os.environ.get("AUTHENTICODE_WARM_DIR")
    if not warm_dir or not os.path.isdir(warm_dir):
        return
    for name in sorted(os.listdir(warm_dir)):
        p = os.path.join(warm_dir, name)
        if os.path.isfile(p):
            try:
                agent_validate(slot.endpoint, p, timeout=40.0)
            except Exception:
                pass  # best-effort warm; one bad sample must not block the snapshot


def _sync_clock(slot) -> None:
    """FALLBACK clock sync (CAPE model) — the runtime prefers the libvirt-native `virsh domtime
    --sync` (qemu-ga) and only calls this when qemu-ga isn't connected. The system clock IS the
    cert-trust decision (validity windows, revocation freshness), so we still want a real time set.
    Like CAPE's analyzer ``set_clock`` (KERNEL32.SetLocalTime), SSH in and ``Set-Date`` — but feed
    the host's UTC and convert to the guest's local TZ in-guest (``.ToLocalTime()``), so the guest's
    UTC ends up equal to real UTC regardless of the guest timezone. Offline, no NTP. Best-effort."""
    utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # base64 -EncodedCommand avoids the SSH→PowerShell quoting minefield; parse as UTC ('Z') then
    # ToLocalTime so Set-Date (which sets LOCAL time) lands the correct UTC for any guest TZ.
    ps = f"Set-Date -Date ([DateTime]::Parse('{utc}').ToLocalTime()) | Out-Null"
    enc = base64.b64encode(ps.encode("utf-16-le")).decode()
    key = os.environ.get("AUTHENTICODE_SSH_KEY", "/etc/winval/win_golden")
    try:
        subprocess.run(
            ["ssh", "-n", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
             "-o", "ConnectTimeout=10", "-i", key, f"Administrator@{slot.ip}",
             "powershell -NoProfile -EncodedCommand " + enc],
            capture_output=True, text=True, timeout=30)
    except Exception:
        pass


class WarmVmPool:
    """Engine-facing adapter: a WarmPool of VM workers with a ``validate(path)`` surface."""

    def __init__(self, *, jobs_per_recycle: int = 1, claim_timeout_s: float = 180.0) -> None:
        self._last_reap = ""
        # smoke + CRL-warm are opt-in via env; clock-sync (on_ready) is always on — a stale clock at
        # boot or after revert would corrupt validity/revocation verdicts.
        smoke_sample = os.environ.get("AUTHENTICODE_SMOKE_SAMPLE")
        if smoke_sample and not os.path.isfile(smoke_sample):   # a directory (the warm dir, transposed) would fail every worker closed with no reason
            # fail FAST and NAME THE CAUSE: with the variable set and the file missing, every
            # worker would fail the smoke gate and the pool would report only "no worker became
            # warm" — the error would never say why
            raise RuntimeError(f"AUTHENTICODE_SMOKE_SAMPLE={smoke_sample!r} is not a file; put a benign signed sample there or unset it")
        health_check = _smoke if smoke_sample else None
        warm_dir = os.environ.get("AUTHENTICODE_WARM_DIR")
        if warm_dir and not os.path.isdir(warm_dir):
            # the same rule as the smoke sample: set but missing must fail HERE, by name — _warm_crl
            # would otherwise skip silently and every snapshot would carry a cold CRL/OCSP cache
            raise RuntimeError(f"AUTHENTICODE_WARM_DIR={warm_dir!r} is not a directory; put the benign signed samples there or unset it")
        pre_snapshot = _warm_crl if warm_dir else None
        spec = authenticode_spec()
        validate_egress_posture(spec)   # by name, before a single VM boots (the rooter would refuse at spawn, after the boot)
        self._pool = spec.build_pool(
            jobs_per_recycle=jobs_per_recycle, health_check=health_check,
            pre_snapshot=pre_snapshot, on_ready=_sync_clock)
        self._claim_timeout_s = claim_timeout_s

    def start(self, wait_warm_s: float = 300.0, stop_event=None) -> None:
        """Launch the pool and block until at least one worker is warm (so the first scan isn't a
        ~60s cold boot) — mirrors the old synchronous pool's start(). `stop_event` (the pool-manager's
        SIGTERM flag) ends the wait early. On EVERY exit but success — the deadline, a stop request,
        ^C or SystemExit raised inside the poll — the pool this call started is reaped here:
        WarmPool.stop() is the only thing that destroys the domains its spawn loop already defined and
        started (overlays on /dev/shm, guest RAM), and no caller can, because engine.get_pool()
        publishes the pool only after this returns."""
        self._pool.start()
        warm = False
        why = "no worker became warm within timeout"
        try:
            deadline = time.time() + wait_warm_s
            while time.time() < deadline:
                if self._pool.idle_count >= 1:  # idle_count is a @property
                    warm = True
                    return
                if stop_event is not None and stop_event.is_set():
                    why = "stop requested during the warm-up"
                    break
                time.sleep(2)
        finally:
            if not warm:
                self._reap("failed warm-up")
        raise RuntimeError(f"WarmVmPool: {why} ({self._last_reap})")

    def _reap(self, what: str) -> int:
        """WarmPool.stop() RETURNS the slots it could not destroy (a failed `virsh destroy` leaves the guest
        running with its overlay and egress rules): say so by count, never 'stopped' when it was not."""
        try:
            left = int(self._pool.stop() or 0)
        except Exception:  # noqa: BLE001
            logger.error("WarmVmPool: stop after a %s raised; workers may still be running (virsh list)", what, exc_info=True)
            self._last_reap = "the workers' state is UNKNOWN: stop raised, check virsh list"
            return -1
        if left:
            logger.error("WarmVmPool: %d worker(s) could NOT be reaped after a %s: still running with overlay and egress rules (virsh list)", left, what)
            self._last_reap = f"{left} worker(s) could NOT be reaped, check virsh list"
        else:
            self._last_reap = "the workers it started were stopped"
        return left

    def validate(self, path: str, params: dict | None = None) -> dict:
        slot = self._pool.claim(timeout_s=self._claim_timeout_s)
        if slot is None:
            raise RuntimeError("no warm VM worker available")
        try:
            return agent_validate(slot.endpoint, path, params=params)  # type: ignore[attr-defined]
        finally:
            self._pool.release(slot)

    def shutdown(self) -> None:
        self._reap("shutdown")
