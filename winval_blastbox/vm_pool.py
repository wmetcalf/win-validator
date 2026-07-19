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
import os
import subprocess
import time
import urllib.parse
import urllib.request

from blastbox.host.runtime.libvirt_egress import ExitRouting, VmEgressPolicy
from blastbox.host.runtime.vm_compose import VmImageSpec, VmWorkerSpec


def agent_validate(endpoint: tuple[str, int], path: str, timeout: float = 60.0) -> dict:
    """Validate a file via the myatg guest agent's HTTP API:
    ``POST http://<ip>:<port>/validate?name=<filename>`` with the raw file bytes as the body,
    returning the verdict JSON. The filename is passed for extension-based routing (.rdp / script
    SIP type) only — myatg verdicts are content-hashed, so the base name is irrelevant."""
    host, port = endpoint
    with open(path, "rb") as fh:
        data = fh.read()
    url = f"http://{host}:{port}/validate?name=" + urllib.parse.quote(os.path.basename(path))
    req = urllib.request.Request(
        url, data=data, method="POST", headers={"Content-Type": "application/octet-stream"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _ports(v: str | None) -> tuple[int, ...] | None:
    return tuple(int(x) for x in v.replace(",", " ").split()) if v else None


def authenticode_spec() -> VmWorkerSpec:
    """Build the authenticode VM-worker spec from AUTHENTICODE_* env (golden, pool size, agent,
    optional egress: AUTHENTICODE_EXIT/EGRESS_PORTS/BLOCK_INTERNAL/VPN_TABLE/...)."""
    exit_driver = os.environ.get("AUTHENTICODE_EXIT")
    egress = routing = None
    if exit_driver:
        egress = VmEgressPolicy(
            exit_driver=exit_driver,
            egress_ports=_ports(os.environ.get("AUTHENTICODE_EGRESS_PORTS")),
            block_internal=os.environ.get("AUTHENTICODE_BLOCK_INTERNAL", "").lower() in ("1", "true", "yes"),
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
        agent_port=int(os.environ.get("AUTHENTICODE_AGENT_PORT", "8765")),
        warm_size=int(os.environ.get("AUTHENTICODE_POOL_SIZE", "2")),
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
    key = os.environ.get("AUTHENTICODE_SSH_KEY", "/home/coz/.ssh/win_golden")
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
        # smoke + CRL-warm are opt-in via env; clock-sync (on_ready) is always on — a stale clock at
        # boot or after revert would corrupt validity/revocation verdicts.
        health_check = _smoke if os.environ.get("AUTHENTICODE_SMOKE_SAMPLE") else None
        pre_snapshot = _warm_crl if os.environ.get("AUTHENTICODE_WARM_DIR") else None
        self._pool = authenticode_spec().build_pool(
            jobs_per_recycle=jobs_per_recycle, health_check=health_check,
            pre_snapshot=pre_snapshot, on_ready=_sync_clock)
        self._claim_timeout_s = claim_timeout_s

    def start(self, wait_warm_s: float = 300.0) -> None:
        """Launch the pool and block until at least one worker is warm (so the first scan isn't a
        ~60s cold boot) — mirrors the old synchronous pool's start()."""
        self._pool.start()
        deadline = time.time() + wait_warm_s
        while time.time() < deadline:
            if self._pool.idle_count >= 1:  # idle_count is a @property
                return
            time.sleep(2)
        raise RuntimeError("WarmVmPool: no worker became warm within timeout")

    def validate(self, path: str) -> dict:
        slot = self._pool.claim(timeout_s=self._claim_timeout_s)
        if slot is None:
            raise RuntimeError("no warm VM worker available")
        try:
            return agent_validate(slot.endpoint, path)  # type: ignore[attr-defined]
        finally:
            self._pool.release(slot)

    def shutdown(self) -> None:
        self._pool.stop()
