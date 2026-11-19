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
import socket
import subprocess
import time
import http.client
import urllib.error
import urllib.parse
import urllib.request

from blastbox.host.pool import WarmPool
from blastbox.host.runtime.vm_compose import VmImageSpec, VmWorkerSpec

from .netns_isolation import NetnsVmRuntime, host_addr, netns_opener

from .knobs import agent_port, env_int

logger = logging.getLogger("winval.vm_pool")


def golden_base() -> str:
    """AUTHENTICODE_GOLDEN_BASE as the three readers agree to read it (this spec, golden_rotate.GOLDEN_BASE, the unit's pre-start):
    stripped, blank is the default, and a byte outside printable ASCII is refused by name — a pasted U+00A0 is what Python would
    strip and a C-locale shell cannot, and three readers naming two files is the one thing that must never happen."""
    raw = (os.environ.get("AUTHENTICODE_GOLDEN_BASE") or "").strip(" \t") or "/dev/shm/golden-base.qcow2"   # space and tab only, as the unit's
    # sed trims: a newline (which sed cannot reach at the front of a value), a no-break space or any control byte reaches the check below on every side
    if not all(32 <= ord(c) < 127 for c in raw):
        raise RuntimeError(f"AUTHENTICODE_GOLDEN_BASE={raw!r} carries a character outside printable ASCII (a pasted U+00A0?): only a plain ASCII path is supported")
    return raw


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


def check_sample(path: str) -> None:
    """Open, stat and close the sample on the HOST before any worker is claimed: a missing file, a directory or
    an unreadable one is the caller's problem, never evidence about a worker (it used to be read inside the try
    that files worker faults). No read here: the bytes are read once, by agent_validate."""
    with open(path, "rb") as fh:
        os.fstat(fh.fileno())


try:
    from blastbox.host.pool import release_kwargs   # the subset of dirty/fault THIS pool's release accepts (blastbox >= 0.1.33)
except ImportError:   # an older blastbox: pass what ITS release() accepts (0.1.26 takes dirty but no fault) rather than swap the real exception for an ImportError in the error path
    import inspect

    def release_kwargs(fn, *, dirty: bool, fault: str | None = None, fault_stage: str | None = None) -> dict:   # type: ignore[misc]
        try:
            accepted = inspect.signature(fn).parameters
        except (TypeError, ValueError):
            return {}
        var_kw = any(p.kind is inspect.Parameter.VAR_KEYWORD for p in accepted.values())   # a release(**kwargs) takes everything, as blastbox's own helper reads it
        return {k: v for k, v in (("dirty", dirty), ("fault", fault), ("fault_stage", fault_stage)) if var_kw or k in accepted}
    logger.warning("this blastbox has no release_kwargs: only what its release() accepts is passed (install blastbox >= 0.1.33 for worker/job evidence)")


def fault_of(exc: BaseException) -> str:
    """Whose evidence a failed validation is, for blastbox's release(dirty=True, fault=...) — three values with
    three meanings in blastbox's pool: 'worker' is NEGATIVE (two in a row evict the worker), 'job' is POSITIVE
    (a served job: it resets the worker's streak and cancels a base rebuild), 'unknown' is NEUTRAL (revert the
    worker, touch no streak). Every dirty release snapshot-reverts the worker, so a wedged guest is restored
    whichever value is filed; the value decides only what the pool LEARNS.
    'worker': the agent could not be reached at all — connection refused, host unreachable (urllib wraps those in
    URLError) — a rebooting guest, one that lost its IP, a dead listener. No sample explains that, and the pool
    may act on it. A timeout wrapped in URLError is NOT here: urllib wraps a timeout during the body send exactly
    like a connect timeout, and a large sample that stalls the agent while it is still being sent would evict.
    'job': the agent answered with HTTP: an error status, an oversize or unparsable body. That is the sample's
    doing; filing it as the worker's let four crafted samples through the unauthenticated ingress empty the pool.
    'unknown': the agent ACCEPTED the connection and then gave no usable answer — a read timeout, a reset or a
    disconnect mid-request, a torn response. A sample that crashes or stalls myatg and a wedged agent look the
    same from here, and the revert restores the agent either way (it is an ONSTART task, restored with the
    snapshot); filing it as 'worker' let one crash sample, sent twice, evict a healthy worker, and as 'job' it
    would count a crash as proof of health."""
    if isinstance(exc, urllib.error.HTTPError):
        return "job"
    if isinstance(exc, urllib.error.URLError):   # no HTTP answer: the reason says whether the agent was ever reached
        reason = exc.reason
        if isinstance(reason, (ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout)):
            # accepted, then gone or stalled while the request was still being sent — urllib wraps a timeout during the
            # body send the same way as a connect timeout, and a large sample that stalls the agent must not evict it;
            # a frozen guest is reverted on every attempt either way (the revert is what un-freezes it)
            return "unknown"
        return "worker"   # refused, unreachable
    if isinstance(exc, (TimeoutError, socket.timeout, ConnectionResetError, BrokenPipeError, http.client.HTTPException)):
        return "unknown"   # a read timeout; RemoteDisconnected/ECONNRESET after the request; BadStatusLine/IncompleteRead
    if isinstance(exc, OSError):
        return "worker"
    return "job"   # RuntimeError (oversize verdict), ValueError (not JSON): an HTTP answer arrived


def agent_validate(endpoint: tuple[str, int], path: str, timeout: float = 60.0,
                   params: dict | None = None, netns: str | None = None) -> dict:
    """Validate a file via the myatg guest agent's HTTP API:
    ``POST http://<ip>:<port>/validate?name=<filename>[&rev=..&scripts=..]`` with the raw file bytes
    as the body, returning the verdict JSON. The filename is passed for extension-based routing
    (.rdp / script SIP type) only — myatg verdicts are content-hashed, so the base name is irrelevant.
    ``params`` carries per-request myatg overrides (``rev`` / ``scripts``); myatg validates the values
    itself, reading an unknown rev as online and an unknown scripts as native (the engine sends those explicitly).
    ``netns`` is the worker's private network namespace (netns_isolation): the connection is made from inside it, the only
    place the guest's address exists."""
    host, port = endpoint
    size = os.stat(path).st_size
    q = {"name": os.path.basename(path)}
    for k in _PER_REQUEST_PARAMS:
        if params and params.get(k):
            q[k] = str(params[k])
    url = f"http://{host}:{port}/validate?" + urllib.parse.urlencode(q)
    # the body is STREAMED from the file (http.client sends a file object in blocks when Content-Length is given): the whole
    # sample used to be read into memory first — two gigabytes of host RAM per in-flight job at the default 1024 MiB cap
    with open(path, "rb") as fh:
        req = urllib.request.Request(
            url, data=fh, method="POST", headers={"Content-Type": "application/octet-stream", "Content-Length": str(size)})
        if not netns:   # never the host namespace: there, the guest's address may be some other VM on libvirt's default network
            raise ValueError("agent_validate needs the worker's network namespace (slot.netns): no host-namespace fallback")
        opener = netns_opener(netns)
        with opener.open(req, timeout=timeout) as r:
            body = r.read(AGENT_RESPONSE_MAX + 1)
    if len(body) > AGENT_RESPONSE_MAX:
        raise RuntimeError(f"the guest agent's verdict exceeds {AGENT_RESPONSE_MAX} bytes (WINVAL_AGENT_RESPONSE_MB); "
                           "refusing to publish it")
    return json.loads(body)




# The host-firewall egress knobs of the rooter era. Isolation is now a private network namespace per worker (netns_isolation):
# no host iptables/nftables/ebtables rule, no br_netfilter, no libvirt network or nwfilter — and so no egress. Any of these set to
# a value that asks for egress is refused by name rather than silently ignored.
EGRESS_EXITS_REMOVED = ("drop", "direct", "openvpn", "wireguard", "tor", "inetsim")
OBSOLETE_EGRESS_KNOBS = ("AUTHENTICODE_EGRESS_PORTS", "AUTHENTICODE_VPN_TABLE", "AUTHENTICODE_VPN_TUN", "AUTHENTICODE_FAKENET_ADDR",
                         "AUTHENTICODE_GATEWAY", "AUTHENTICODE_LEG", "AUTHENTICODE_IP_POOL",
                         "AUTHENTICODE_LIBVIRT_NETWORK")   # the golden's agent rule used to admit that network's host address;
# the workers now call from AUTHENTICODE_AGENT_CALLER, so a set LIBVIRT_NETWORK means an existing golden may admit another address   # each asked for egress or a shared network;
# AUTHENTICODE_BLOCK_INTERNAL only ever RESTRICTED a worker, and a namespace already blocks everything it blocked: it is ignored


def exit_driver() -> str:
    """AUTHENTICODE_EXIT as the pool reads it: unset, blank or ``none`` (any case) is ``none``, the only posture there is.
    Every other value named an exit that installed host firewall rules (blastbox's rooter) and is refused by name."""
    raw = (os.environ.get("AUTHENTICODE_EXIT") or "").strip()
    if not raw or raw.lower() == "none":
        return "none"
    raise ValueError(f"AUTHENTICODE_EXIT={raw!r}: host-side egress exits ({', '.join(EGRESS_EXITS_REMOVED)}) were removed — they installed "
                     "iptables chains on the host. Workers are isolated in a private network namespace with no egress; "
                     "set AUTHENTICODE_EXIT=none (or unset it)")


def validate_egress_posture(spec: VmWorkerSpec | None = None) -> None:
    """The network posture, checked without a worker (the rotation preflight before the hour-long build, the pool before
    booting a VM): the exit is none, no rooter-era knob is set, and the namespace addressing (AUTHENTICODE_AGENT_CALLER) parses.
    ``spec`` is accepted for the callers that hold one: it must carry no egress policy, routing or IP pool."""
    exit_driver()
    stale = [k for k in OBSOLETE_EGRESS_KNOBS if (os.environ.get(k) or "").strip()]
    if stale:
        raise ValueError(f"{', '.join(stale)} configured host-firewall egress or a shared libvirt network, both removed: workers are isolated "
                         "in a private network namespace with no egress. Remove the knob(s) from winval.env (for AUTHENTICODE_LIBVIRT_NETWORK: "
                         "set AUTHENTICODE_AGENT_CALLER to the host address on that network, the one your golden's agent rule admits)")
    if spec is not None and (spec.egress is not None or spec.routing is not None or spec.worker_ip_pool):
        raise ValueError("the worker spec carries host-side egress (an egress policy, exit routing or an IP pool): not available under namespace isolation")
    host_addr()


def authenticode_spec() -> VmWorkerSpec:
    """Build the authenticode VM-worker spec from AUTHENTICODE_* env (golden, pool size, agent port). The network is NOT in the
    spec: build_runtime() puts every worker's NIC in its own network namespace (netns_isolation), with no egress."""
    exit_driver()   # a rooter-era exit is refused here, by name, wherever the spec is built
    return VmWorkerSpec(
        name="authenticode",
        image=VmImageSpec(golden=golden_base()),
        agent_port=agent_port(),
        warm_size=pool_size(),
        egress=None,
        routing=None,
        nwfilter="",   # no libvirt nwfilter (ebtables on the host): the NIC is a private tap, not a bridge port
        worker_ip_pool="",
    )


def build_runtime(spec: VmWorkerSpec, *, health_check=None, pre_snapshot=None, on_ready=None) -> NetnsVmRuntime:
    """The ONE place a worker runtime is made (the pool and the rotation's gate): namespace isolation, never a libvirt network."""
    return NetnsVmRuntime(spec.to_vm_config(health_check=health_check, pre_snapshot=pre_snapshot, on_ready=on_ready))


def build_pool(spec: VmWorkerSpec, *, jobs_per_recycle: int, health_check=None, pre_snapshot=None, on_ready=None) -> WarmPool:
    """VmWorkerSpec.build_pool's WarmPool, over build_runtime()'s runtime (the same knobs it passes)."""
    rt = build_runtime(spec, health_check=health_check, pre_snapshot=pre_snapshot, on_ready=on_ready)
    return WarmPool(
        runtime=rt,  # type: ignore[arg-type]  # a VmSlot runtime, as vm_compose passes it
        warm_size=spec.warm_size,
        concurrent_ceiling=spec.concurrent_ceiling,
        spawn_rate_limit=spec.spawn_rate_limit,
        jobs_per_recycle=jobs_per_recycle,
        max_jobs_per_slot=spec.max_jobs_per_slot,
        warming_timeout_s=rt.cfg.boot_timeout_s + 60,
    )


def slot_netns(slot) -> str | None:
    """The worker's private namespace (set by NetnsVmRuntime.spawn); None for a slot from anything else."""
    return getattr(slot, "netns", None)


AGENT_STATUSES = frozenset({"Valid", "Revoked", "Distrusted", "UntrustedRoot", "HashMismatch", "Expired", "NotYetValid", "UnknownError",
                            "NotSigned"})   # the agent's verdict vocabulary (myatg's README + rdp_validate.cs); ContentUnverified is a UI flag
                                            # (content_verified false), never a status


def smoke_expect() -> str:
    """AUTHENTICODE_SMOKE_EXPECT, the status the smoke sample must validate to: stripped, blank is Valid, and it must name a status
    the agent can return (case-insensitively) — a typo (Vaild) could never match, and every worker would fail the gate with only
    'no worker became warm' to show for it. Refused by name, like the sample and the warm dir beside it."""
    raw = (os.environ.get("AUTHENTICODE_SMOKE_EXPECT") or "").strip() or "Valid"
    for status in AGENT_STATUSES:
        if status.lower() == raw.lower():
            return status
    raise RuntimeError(f"AUTHENTICODE_SMOKE_EXPECT={raw!r} is not a status the agent maps (one of {', '.join(sorted(AGENT_STATUSES))}; an unmapped "
                       "PowerShell status passes through the agent verbatim and is not accepted here)")


def _smoke(slot) -> bool:
    """Health smoke test: send a known benign signed sample to the agent and assert the expected
    verdict — proves the OS is up, the agent returns, AND cert validation actually works (not just
    a port-open check). Opt-in via AUTHENTICODE_SMOKE_SAMPLE (default expected status Valid)."""
    sample = (os.environ.get("AUTHENTICODE_SMOKE_SAMPLE") or "").strip()
    expect = smoke_expect()
    try:
        v = agent_validate(slot.endpoint, sample, timeout=30.0, netns=slot_netns(slot))
    except Exception:
        return False
    return isinstance(v, dict) and str(v.get("status", "")).strip().lower() == expect.lower()


def _warm_crl(slot) -> None:
    """Pre-snapshot CRL/OCSP warm: validate every benign sample in AUTHENTICODE_WARM_DIR with
    online revocation, so the major CAs' CRLs are fetched+cached and the snapshot captures a hot
    cache (warm-restores then serve revocation from cache, no per-job live fetch)."""
    warm_dir = (os.environ.get("AUTHENTICODE_WARM_DIR") or "").strip()   # read as the guard in __init__ reads it: a padded path is the same dir
    if not warm_dir or not os.path.isdir(warm_dir):
        return
    for name in sorted(os.listdir(warm_dir)):
        p = os.path.join(warm_dir, name)
        if os.path.isfile(p):
            try:
                agent_validate(slot.endpoint, p, timeout=40.0, netns=slot_netns(slot))
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
        ns = slot_netns(slot)
        subprocess.run(
            (["ip", "netns", "exec", ns] if ns else []) + ["ssh", "-F", "/dev/null", "-n", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
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
        smoke_sample = (os.environ.get("AUTHENTICODE_SMOKE_SAMPLE") or "").strip()   # stripped like every knob: whitespace-only is unset
        if smoke_sample and not os.path.isfile(smoke_sample):   # a directory (the warm dir, transposed) would fail every worker closed with no reason
            # fail FAST and NAME THE CAUSE: with the variable set and the file missing, every
            # worker would fail the smoke gate and the pool would report only "no worker became
            # warm" — the error would never say why
            raise RuntimeError(f"AUTHENTICODE_SMOKE_SAMPLE={smoke_sample!r} is not a file; put a benign signed sample there or unset it")
        if smoke_sample:
            smoke_expect()   # refused by name here, at start, not at the first health check
        health_check = _smoke if smoke_sample else None
        warm_dir = (os.environ.get("AUTHENTICODE_WARM_DIR") or "").strip()
        if warm_dir and not os.path.isdir(warm_dir):
            # the same rule as the smoke sample: set but missing must fail HERE, by name — _warm_crl
            # would otherwise skip silently and every snapshot would carry a cold CRL/OCSP cache
            raise RuntimeError(f"AUTHENTICODE_WARM_DIR={warm_dir!r} is not a directory; put the benign signed samples there or unset it")
        pre_snapshot = _warm_crl if warm_dir else None
        spec = authenticode_spec()
        validate_egress_posture(spec)   # by name, before a single VM boots
        self._pool = build_pool(
            spec, jobs_per_recycle=jobs_per_recycle, health_check=health_check,
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
        check_sample(path)   # a host-side open error is answered before a worker is claimed (see check_sample)
        slot = self._pool.claim(timeout_s=self._claim_timeout_s)
        if slot is None:
            raise RuntimeError("no warm VM worker available")
        try:
            verdict = agent_validate(slot.endpoint, path, params=params, netns=slot_netns(slot))  # type: ignore[attr-defined]
        except (KeyboardInterrupt, SystemExit):
            self._pool.release(slot, **release_kwargs(self._pool.release, dirty=True))   # the slot ran something: revert it; nobody's evidence
            raise
        except Exception as exc:
            # a bare release counted every failure as proof of health (it reset the slot's streak and its siblings'),
            # so a wedged guest was never evicted; filing every failure as a WORKER fault let crafted samples evict
            # healthy workers. fault_of() says whose evidence it is; either way the worker is reverted before reuse.
            self._pool.release(slot, **release_kwargs(self._pool.release, dirty=True, fault=fault_of(exc)))
            raise
        self._pool.release(slot)
        return verdict

    def shutdown(self) -> None:
        self._reap("shutdown")
