"""Worker network isolation by a PRIVATE NETWORK NAMESPACE per VM — no host firewall rules at all.

Each VM worker's NIC is a tap device that lives in its own network namespace (``wvn-<sid>``). That
namespace holds exactly two interfaces, ``lo`` and the tap, one /24 between the host side of the tap
(AUTHENTICODE_AGENT_CALLER, default 192.168.122.1 — the one address the golden's agent-port firewall
rule admits) and the guest, and NO route anywhere else. So, structurally rather than by rule:

* the guest cannot reach the host: none of the host's addresses exist in its namespace;
* the guest cannot reach a sibling: every worker has its own namespace, there is no shared bridge;
* the guest cannot reach the internet: the namespace has no uplink and no default route.

The host (this pool-manager, root) reaches the guest's agent by opening its socket INSIDE the
worker's namespace (``setns`` on a short-lived thread; the socket keeps its namespace for its whole
life). DHCP for the guest is a dnsmasq bound to the tap inside the namespace (no DNS: ``--port=0``).

Nothing here writes to the host's nftables/iptables/ebtables, loads a kernel module, sets a sysctl in
the host namespace, or creates a libvirt network or nwfilter: ``nft list ruleset`` is unchanged by a
worker's whole life. This replaces blastbox's rooter (per-worker FORWARD/INPUT chains + nwfilter
clean-traffic + br_netfilter), which needed all of those.

Lifecycle (driven by blastbox's LibvirtVmRuntime; only the network-specific steps are overridden):
  spawn    netns add -> tuntap add (host ns) -> [blastbox: overlay, define, start; the domain opens
           the tap by name] -> tap moved into the netns, addressed, up -> dnsmasq in the netns
  revert   libvirt restarts QEMU on snapshot-revert and reopens the tap BY NAME in the host
           namespace, so the tap is moved home (down, unaddressed) for the revert and back after it,
           whatever the revert's outcome
  reap     [blastbox: destroy, undefine, rm overlay] -> dnsmasq stopped -> tap + netns deleted. A
           failed destroy (the guest may still run) leaves the namespace in place: still contained.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket
import subprocess
import threading
import urllib.request
from http.client import HTTPConnection
from pathlib import Path

from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime, VmSlot

logger = logging.getLogger("winval.netns")

NETNS_PREFIX = "wvn-"      # ip netns name: wvn-<16 hex sid>
TAP_PREFIX = "wvt"         # tap name: wvt<first 12 hex of the sid> = 15 chars, IFNAMSIZ-1
NETNS_DIR = "/run/netns"   # where `ip netns add` binds the namespace (iproute2's fixed location)
DEFAULT_HOST_ADDR = "192.168.122.1"
GUEST_HOST_OFFSET = 10     # the first guest address is network + 10; one address per live worker
_INTERFACE_RE = re.compile(r"<interface type='network'>.*?</interface>", re.S)
_HEX = re.compile(r"[0-9a-f]{16}")


def _run(argv: list[str], timeout: float = 60) -> subprocess.CompletedProcess:
    """Never raises: a timeout or a missing binary is a non-zero result, as blastbox's own runner reads them."""
    try:
        return subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "timeout")
    except OSError as exc:
        return subprocess.CompletedProcess(argv, 127, "", str(exc))


def _spawn_dhcp(argv: list[str]) -> subprocess.Popen:
    return subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def netns_socket(netns: str, family: int = socket.AF_INET, type_: int = socket.SOCK_STREAM) -> socket.socket:
    """A socket created INSIDE the named network namespace (it stays there for its whole life, whichever thread uses it).
    The setns runs on a throwaway thread, so no thread of this process ever changes namespace. Needs CAP_SYS_ADMIN (root)."""
    if not re.fullmatch(re.escape(NETNS_PREFIX) + r"[0-9a-f]{16}", netns):
        raise ValueError(f"not a worker namespace name: {netns!r}")
    box: dict = {}

    def _inside() -> None:
        try:
            fd = os.open(os.path.join(NETNS_DIR, netns), os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.setns(fd, os.CLONE_NEWNET)
            finally:
                os.close(fd)
            box["sock"] = socket.socket(family, type_)
        except BaseException as exc:  # noqa: BLE001 — re-raised on the caller's thread
            box["exc"] = exc

    t = threading.Thread(target=_inside, name=f"setns-{netns}", daemon=True)
    t.start()
    t.join()
    if "exc" in box:
        raise box["exc"]
    return box["sock"]


def netns_connect(netns: str, address: tuple[str, int], timeout: float) -> socket.socket:
    s = netns_socket(netns)
    try:
        s.settimeout(timeout)
        s.connect(address)
        return s
    except BaseException:
        s.close()
        raise


class _NetnsHTTPConnection(HTTPConnection):
    netns: str = ""

    def connect(self) -> None:
        self.sock = netns_connect(self.netns, (self.host, self.port), self.timeout)


def netns_opener(netns: str) -> urllib.request.OpenerDirector:
    """A urllib opener whose HTTP connections are made inside ``netns`` — urllib's own error mapping (HTTPError for an HTTP
    status, URLError wrapping a connect failure) is kept, which is what vm_pool.fault_of reads."""
    conn_cls = type("NetnsHTTPConnection", (_NetnsHTTPConnection,), {"netns": netns})

    class _Handler(urllib.request.HTTPHandler):
        def http_open(self, req):  # noqa: ANN001
            return self.do_open(conn_cls, req)

    opener = urllib.request.OpenerDirector()
    for h in (_Handler(), urllib.request.HTTPDefaultErrorHandler(), urllib.request.HTTPErrorProcessor()):
        opener.add_handler(h)
    return opener   # no proxy handler, no redirect handler, no other scheme: the agent is one plain-HTTP endpoint


def host_addr() -> ipaddress.IPv4Interface:
    """The host side of every worker's tap: AUTHENTICODE_AGENT_CALLER (the address the golden's agent-port rule admits,
    golden_build.agent_caller) on a /24. A value that is not one IPv4 address is refused by name."""
    raw = (os.environ.get("AUTHENTICODE_AGENT_CALLER") or "").strip() or DEFAULT_HOST_ADDR
    try:
        addr = ipaddress.IPv4Address(raw)
    except ValueError as exc:
        raise ValueError(f"AUTHENTICODE_AGENT_CALLER={raw!r} is not one IPv4 address") from exc
    iface = ipaddress.IPv4Interface(f"{addr}/24")
    if int(addr) - int(iface.network.network_address) in (0, 255):
        raise ValueError(f"AUTHENTICODE_AGENT_CALLER={raw!r} is its /24's network or broadcast address")
    return iface


def netns_name(sid: str) -> str:
    return NETNS_PREFIX + sid


def tap_name(sid: str) -> str:
    return TAP_PREFIX + sid[:12]


class NetnsVmRuntime(LibvirtVmRuntime):
    """blastbox's libvirt VM runtime with the worker NIC in a private network namespace (see the module docstring).

    Refuses a config that asks for host-side egress (an egress policy, exit routing, an IP pool reserved on a libvirt
    network): those are the rooter's host-firewall mechanisms this runtime exists to remove."""

    def __init__(self, config: LibvirtVmConfig) -> None:
        if config.egress_policy is not None or config.exit_routing is not None:
            raise ValueError("host-side egress (blastbox's rooter: iptables chains on the host) is not available under "
                             "namespace isolation; a worker has no egress (AUTHENTICODE_EXIT=none)")
        if config.worker_ip_pool:
            raise ValueError("AUTHENTICODE_IP_POOL reserves addresses on a shared libvirt network; namespace isolation "
                             "addresses every worker privately: unset it")
        super().__init__(config)
        self._host = host_addr()
        net = self._host.network
        host_off = int(self._host.ip) - int(net.network_address)
        self._guest_offsets = [o for o in range(GUEST_HOST_OFFSET, 255) if o != host_off]
        self._lock = threading.Lock()
        self._by_sid: dict[str, dict] = {}   # sid -> {"netns", "tap", "guest", "dhcp"}
        self._by_domain: dict[str, str] = {}
        self._sweep_orphans()

    # ---- addressing -----------------------------------------------------------------------------
    def _alloc_guest(self, sid: str) -> str:
        with self._lock:
            used = {v["guest"] for v in self._by_sid.values()}
            for off in self._guest_offsets:
                ip = str(self._host.network.network_address + off)
                if ip not in used:
                    self._by_sid[sid] = {"netns": netns_name(sid), "tap": tap_name(sid), "guest": ip, "dhcp": None}
                    return ip
        raise RuntimeError("no free guest address left in the worker /24")

    def netns_of(self, slot: VmSlot) -> str | None:
        rec = self._by_sid.get(slot.slot_id)
        return rec["netns"] if rec else None

    def _rec_for_ip(self, ip: str) -> dict | None:
        for rec in list(self._by_sid.values()):
            if rec["guest"] == ip:
                return rec
        return None

    # ---- host commands --------------------------------------------------------------------------
    def _ip(self, *args: str, check: bool = True) -> subprocess.CompletedProcess:
        r = _run((["sudo"] if self.cfg.sudo else []) + ["ip", *args])
        if check and r.returncode != 0:
            raise RuntimeError(f"ip {' '.join(args)} failed (rc {r.returncode}): {(r.stderr or '').strip()[:200]}")
        return r

    def _tap_into_netns(self, rec: dict) -> None:
        """Move the tap into its namespace and address it. The tap has NO address and is DOWN while it is in the host
        namespace (a move between namespaces brings it down and drops its addresses), so the host never forwards for it."""
        ns, tap = rec["netns"], rec["tap"]
        self._ip("link", "set", "dev", tap, "netns", ns)
        self._ip("-n", ns, "link", "set", "dev", "lo", "up")
        # no IPv6 on the tap: the guest would otherwise reach the namespace's link-local address (nothing listens; less surface)
        r = _run((["sudo"] if self.cfg.sudo else []) + ["ip", "netns", "exec", ns, "sysctl", "-q", "-w", f"net.ipv6.conf.{tap}.disable_ipv6=1"])
        if r.returncode != 0:
            logger.warning("%s: IPv6 not disabled on %s inside %s (rc %s); the namespace still has no route out", rec["netns"], tap, ns, r.returncode)
        self._ip("-n", ns, "addr", "replace", str(self._host), "dev", tap)
        self._ip("-n", ns, "link", "set", "dev", tap, "up")

    def _tap_home(self, rec: dict) -> bool:
        """Back to the host namespace (down, unaddressed) so libvirt can reopen it by name."""
        return self._ip("-n", rec["netns"], "link", "set", "dev", rec["tap"], "netns", "1", check=False).returncode == 0

    def _start_dhcp(self, rec: dict) -> None:
        guest, tap = rec["guest"], rec["tap"]
        argv = (["sudo"] if self.cfg.sudo else []) + [
            "ip", "netns", "exec", rec["netns"], "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--port=0",
            "--leasefile-ro", "--bind-dynamic", f"--interface={tap}", "--except-interface=lo",
            f"--dhcp-range={guest},{guest},255.255.255.0,infinite",
            "--dhcp-option=3", "--dhcp-option=6",   # no router, no DNS server: there is nothing to route to or resolve with
        ]
        rec["dhcp"] = _spawn_dhcp(argv)

    def _stop_dhcp(self, rec: dict) -> None:
        p = rec.get("dhcp")
        rec["dhcp"] = None
        if p is None:
            return
        try:
            p.terminate()
            p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            try:
                p.kill()
            except Exception:  # noqa: BLE001
                logger.warning("%s: dnsmasq could not be stopped", rec["netns"], exc_info=True)

    def _teardown(self, sid: str) -> None:
        rec = self._by_sid.get(sid)
        if rec is None:
            return
        self._stop_dhcp(rec)
        self._ip("-n", rec["netns"], "link", "del", "dev", rec["tap"], check=False)
        self._ip("link", "del", "dev", rec["tap"], check=False)   # still in the host namespace (a spawn that failed before the move)
        r = self._ip("netns", "del", rec["netns"], check=False)
        if r.returncode != 0 and Path(NETNS_DIR, rec["netns"]).exists():
            logger.warning("%s: namespace not removed (rc %s): %s", rec["netns"], r.returncode, (r.stderr or "").strip()[:160])
        with self._lock:
            self._by_sid.pop(sid, None)
            for d, s in list(self._by_domain.items()):
                if s == sid:
                    self._by_domain.pop(d, None)

    def _sweep_orphans(self) -> None:
        """A previous life's namespaces whose domain no longer exists: removed (the tap inside goes with it). A namespace whose
        domain still exists is left alone — its guest is contained in it, and destroying a domain is not this runtime's call."""
        r = self._ip("netns", "list", check=False)
        for line in (r.stdout or "").splitlines():
            name = line.split()[0] if line.split() else ""
            if not name.startswith(NETNS_PREFIX) or not _HEX.fullmatch(name[len(NETNS_PREFIX):]):
                continue
            sid = name[len(NETNS_PREFIX):]
            st = self._virsh("domstate", f"bbvm-{sid}")
            if st.returncode == 0:
                logger.warning("netns %s: its domain bbvm-%s still exists; left in place", name, sid)
                continue
            if "domain not found" not in (st.stderr or "").lower() and "failed to get domain" not in (st.stderr or "").lower():
                continue   # libvirt did not answer: unknown, not absent
            self._ip("-n", name, "link", "del", "dev", tap_name(sid), check=False)
            self._ip("netns", "del", name, check=False)
            logger.info("removed orphaned worker namespace %s", name)

    # ---- LibvirtVmRuntime overrides -------------------------------------------------------------
    def _assert_egress_is_governed(self) -> None:
        """No libvirt network is involved: the worker's NIC is a private tap (see _domain_xml)."""

    def _assert_subnet_matches_network(self) -> None:
        """The subnet is this runtime's own (host_addr()), not a libvirt network's."""

    def _ip_for_mac(self, mac: str | None) -> str | None:
        return None   # the address is assigned, never learnt from the host's neighbour table

    def _domain_xml(self, name: str, overlay: str, *, mac: str | None = None, assigned_ip: str | None = None) -> str:
        xml = super()._domain_xml(name, overlay, mac=mac, assigned_ip=None)
        sid = self._by_domain.get(name)
        if sid is None:
            raise RuntimeError(f"{name}: no namespace was prepared for this domain")
        tap = self._by_sid[sid]["tap"]
        nic = (f"<interface type='ethernet'><target dev='{tap}' managed='no'/>"
               f"<model type='{self.cfg.nic_model}'/></interface>")
        xml, n = _INTERFACE_RE.subn(nic, xml)
        if n != 1 or "type='network'" in xml or "<filterref" in xml:
            raise RuntimeError(f"{name}: the domain XML's network interface could not be replaced exactly once "
                               "(blastbox's XML changed?); refusing to define a worker on a libvirt network")
        return xml

    def _alloc_overlay_name(self) -> tuple[str, str, str]:
        sid, name, overlay = super()._alloc_overlay_name()
        self._alloc_guest(sid)
        with self._lock:
            self._by_domain[name] = sid
        rec = self._by_sid[sid]
        try:
            self._ip("netns", "add", rec["netns"])
            self._ip("tuntap", "add", "dev", rec["tap"], "mode", "tap", "vnet_hdr")
        except Exception:
            self._teardown(sid)
            raise
        return sid, name, overlay

    def spawn(self) -> VmSlot:
        slot = super().spawn()   # its own failure path reaps (-> our teardown via reap)
        rec = self._by_sid.get(slot.slot_id)
        try:
            if rec is None:
                raise RuntimeError(f"{slot.domain}: spawned without a prepared namespace")
            self._tap_into_netns(rec)
            self._start_dhcp(rec)
            slot.ip = rec["guest"]
            slot.netns = rec["netns"]   # type: ignore[attr-defined]  # read by vm_pool's agent transport
            return slot
        except Exception:
            self.reap(slot)
            raise

    def _port_up(self, ip: str, timeout: float = 2) -> bool:
        rec = self._rec_for_ip(ip)
        if rec is None:
            return False   # never probe a guest address in the HOST namespace
        try:
            netns_connect(rec["netns"], (ip, self.cfg.agent_port), timeout).close()
            return True
        except OSError:
            return False

    def _virsh(self, *a: str, timeout: float = 90) -> subprocess.CompletedProcess:
        if not a or a[0] != "snapshot-revert":
            return super()._virsh(*a, timeout=timeout)
        sid = self._by_domain.get(a[1]) if len(a) > 1 else None
        rec = self._by_sid.get(sid) if sid else None
        if rec is None:
            return super()._virsh(*a, timeout=timeout)
        # libvirt restarts QEMU on a revert and reopens the tap BY NAME in the host namespace: bring it home for the revert
        # (down, unaddressed) and put it back whatever the revert did — a tap left at home is unreachable, never exposed
        moved = self._tap_home(rec)
        try:
            return super()._virsh(*a, timeout=timeout)
        finally:
            if moved:
                try:
                    self._tap_into_netns(rec)
                except Exception:  # noqa: BLE001 — the agent then never answers; recycle() raises and the pool reaps the slot
                    logger.warning("%s: tap not returned to its namespace after the revert", rec["netns"], exc_info=True)

    def reap(self, slot: VmSlot) -> None:
        super().reap(slot)   # raises (slot quarantined) when the guest may still run: the namespace then stays, containing it
        self._teardown(slot.slot_id)
