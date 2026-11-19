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

import fcntl
import ipaddress
import logging
import os
import re
import socket
import subprocess
import threading
import time
import urllib.request
from http.client import HTTPConnection
from pathlib import Path

from blastbox.host.runtime.libvirt_vm import LibvirtVmConfig, LibvirtVmRuntime, VmSlot

logger = logging.getLogger("winval.netns")

NETNS_PREFIX = "wvn-"      # ip netns name: wvn-<16 hex sid>
TAP_PREFIX = "wvt"         # tap name: wvt<first 12 hex of the sid> = 15 chars, IFNAMSIZ-1
NETNS_DIR = "/run/netns"   # where `ip netns add` binds the namespace (iproute2's fixed location)
LOCK_DIR = "/run/winval/netns"   # <sid>.lock, flock'ed by the process that owns the worker for the worker's whole life: the orphan
# sweep of ANOTHER process (the rotation gate beside the live pool, a restart) never touches a namespace or tap whose owner is alive
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
    # its own session, so a stop can signal the whole group; `ip netns exec` and setpriv both exec, so the child IS dnsmasq
    import tempfile
    err = tempfile.TemporaryFile()   # a file, never a pipe: a pipe nobody drains would block dnsmasq once it fills
    p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err, start_new_session=True)
    p.errfile = err   # type: ignore[attr-defined]
    return p


DHCP_UID = 65534   # nobody/nogroup: dnsmasq runs unprivileged from its first instruction (see _start_dhcp)


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
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)   # as http.client's own connect: no Nagle stall on the body tail


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

    # ---- ownership ------------------------------------------------------------------------------
    @staticmethod
    def _lock_path(sid: str) -> str:
        return os.path.join(LOCK_DIR, f"{sid}.lock")

    @staticmethod
    def _take_lock(sid: str, *, create: bool = False, wait_s: float = 0.0) -> int | None:
        """flock LOCK_DIR/<sid>.lock: the descriptor when this process now owns the sid, None when another live process holds it
        (or, without ``create``, when there is no lock file at all — a probe never creates one). The lock dies with its holder,
        so a crashed owner's sid is free to sweep. The descriptor is returned only when it still names the file at the path: a
        file unlinked between this open and the flock (a sweep reclaiming it) would be a lock nobody else can see, so the open
        is retried. An owner may wait ``wait_s`` for a sweep's momentary probe of its own fresh sid to pass."""
        path = NetnsVmRuntime._lock_path(sid)
        if create:
            NetnsVmRuntime._lock_dir()
        deadline = time.monotonic() + wait_s
        while True:
            try:
                fd = os.open(path, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | (os.O_CREAT if create else 0), 0o600)
            except FileNotFoundError:
                return None
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                if time.monotonic() >= deadline:
                    return None
                time.sleep(0.05)
                continue
            try:
                same = os.fstat(fd).st_ino == os.stat(path, follow_symlinks=False).st_ino
            except FileNotFoundError:
                same = False
            except BaseException:
                os.close(fd)   # never leak a HELD lock: it would read as a live owner for this process's whole life
                raise
            if same:
                return fd
            os.close(fd)   # unlinked under us: the next open creates (owner) or finds nothing (probe)
            if not create:
                return None

    @staticmethod
    def _lock_dir() -> None:
        """LOCK_DIR exists, is a real directory, owned by this uid and 0700: makedirs leaves an existing directory's owner
        and mode as they are, and a writable lock directory is one where anyone can plant or hide an owner."""
        os.makedirs(LOCK_DIR, mode=0o700, exist_ok=True)
        st = os.lstat(LOCK_DIR)
        import stat as _stat
        if not _stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise RuntimeError(f"{LOCK_DIR} is not a directory owned by this uid: refusing to keep worker ownership locks there")
        if _stat.S_IMODE(st.st_mode) != 0o700:
            os.chmod(LOCK_DIR, 0o700)

    @staticmethod
    def _drop_lock(sid: str, fd: int | None) -> None:
        """Unlink, then release: only ever by the holder, so no one can be holding the file being removed."""
        if fd is None:
            return
        try:
            os.unlink(NetnsVmRuntime._lock_path(sid))
        except OSError:
            pass
        os.close(fd)

    @staticmethod
    def _held_sids() -> list[str]:
        """sids whose lock a LIVE process holds (this one included). A free lock file found here is a dead owner's: reclaimed
        under its own lock (an owner that opened it meanwhile re-checks the inode after its flock and re-creates)."""
        try:
            names = os.listdir(LOCK_DIR)
        except OSError:
            return []
        held = []
        for n in names:
            sid = n[:-5] if n.endswith(".lock") else ""
            if not _HEX.fullmatch(sid):
                continue
            try:
                fd = NetnsVmRuntime._take_lock(sid)
            except OSError as exc:   # not a lock file (a directory, a symlink): treated as held, never touched, never fatal
                logger.warning("lock entry %s unusable (%s): its worker id is left alone", n, exc)
                held.append(sid)
                continue
            if fd is None:
                if os.path.lexists(NetnsVmRuntime._lock_path(sid)):
                    held.append(sid)
            else:
                NetnsVmRuntime._drop_lock(sid, fd)
        return held

    # ---- addressing -----------------------------------------------------------------------------
    def _alloc_guest(self, sid: str) -> str:
        lock = self._take_lock(sid, create=True, wait_s=2.0)   # a fresh random id: only a sweep's momentary probe can hold it
        if lock is None:
            raise RuntimeError(f"worker id {sid} is held by another live process")
        with self._lock:
            used = {v["guest"] for v in self._by_sid.values()}
            for off in self._guest_offsets:
                ip = str(self._host.network.network_address + off)
                if ip not in used:
                    self._by_sid[sid] = {"netns": netns_name(sid), "tap": tap_name(sid), "guest": ip, "dhcp": None, "lock": lock}
                    return ip
        self._drop_lock(sid, lock)
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
        if r.returncode != 0:   # fail closed: the guest would otherwise share link-local IPv6 with the namespace
            raise RuntimeError(f"{ns}: IPv6 not disabled on {tap} (rc {r.returncode}): {(r.stderr or '').strip()[:200]}")
        self._ip("-n", ns, "addr", "replace", str(self._host), "dev", tap)
        self._ip("-n", ns, "link", "set", "dev", tap, "up")

    def _tap_home(self, rec: dict) -> bool:
        """Back to the host namespace (down, unaddressed) so libvirt can reopen it by name."""
        return self._ip("-n", rec["netns"], "link", "set", "dev", rec["tap"], "netns", "1", check=False).returncode == 0

    def _start_dhcp(self, rec: dict) -> None:
        """dnsmasq is the ONE host process the guest can send packets to, so it holds as little as it can run with: started
        through setpriv as nobody, no_new_privs, with CAP_NET_RAW alone in every set (its DHCP needs raw sockets; they reach
        only the worker namespace's own interfaces). Never CAP_NET_ADMIN: started as root, dnsmasq keeps CAP_NET_ADMIN of
        the init user namespace after dropping its uid — enough, from inside the worker namespace, to move the tap into the
        host namespace. Binding the DHCP port without CAP_NET_BIND_SERVICE is allowed by
        ip_unprivileged_port_start=0, a sysctl of the WORKER namespace only; replies are broadcast (no ARP injection without
        CAP_NET_ADMIN). No pid file (the default is the host's /run/dnsmasq.pid, shared by every worker), no lease file.
        Not prefixed with sudo: this process is root (netns_socket's setns needs it), and a sudo parent would not relay the stop."""
        guest, tap, ns = rec["guest"], rec["tap"], rec["netns"]
        r = _run(["ip", "netns", "exec", ns, "sysctl", "-q", "-w", "net.ipv4.ip_unprivileged_port_start=0"])
        if r.returncode != 0:
            raise RuntimeError(f"{ns}: ip_unprivileged_port_start not set (rc {r.returncode}): {(r.stderr or '').strip()[:200]}")
        argv = [
            "ip", "netns", "exec", ns,
            "setpriv", f"--reuid={DHCP_UID}", f"--regid={DHCP_UID}", "--clear-groups", "--inh-caps=-all,+net_raw",
            "--ambient-caps=-all,+net_raw", "--bounding-set=-all,+net_raw", "--no-new-privs",
            "dnsmasq", "--keep-in-foreground", "--conf-file=/dev/null", "--port=0", "--pid-file=",
            "--leasefile-ro", "--bind-dynamic", f"--interface={tap}", "--except-interface=lo", "--dhcp-broadcast",
            f"--dhcp-range={guest},{guest},255.255.255.0,infinite",
            "--dhcp-option=3", "--dhcp-option=6",   # no router, no DNS server: there is nothing to route to or resolve with
        ]
        p = _spawn_dhcp(argv)
        rec["dhcp"] = p
        try:
            p.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            return   # running
        f = getattr(p, "errfile", None)
        err = b""
        if f is not None:
            f.seek(0)
            err = f.read(4096)
        raise RuntimeError(f"{ns}: dnsmasq exited at start (rc {p.returncode}): {err.decode('utf-8', 'replace').strip()[:200]}")

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
                p.wait(timeout=10)
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
        self._drop_lock(sid, rec.get("lock"))

    def _domain_absent(self, sid: str) -> bool:
        st = self._virsh("domstate", f"bbvm-{sid}")
        err = (st.stderr or "").lower()
        return st.returncode != 0 and ("domain not found" in err or "failed to get domain" in err)   # an unanswering libvirt is unknown, not absent

    def _sweep_orphans(self) -> None:
        """A previous life's namespaces and host-namespace taps: removed when no live process owns their worker id (the
        ownership lock, see LOCK_DIR) AND its domain is confirmed absent. A namespace whose domain still exists is left alone —
        its guest is contained in it, and destroying a domain is not this runtime's call."""
        r = self._ip("netns", "list", check=False)
        for line in (r.stdout or "").splitlines():
            name = line.split()[0] if line.split() else ""
            if not name.startswith(NETNS_PREFIX) or not _HEX.fullmatch(name[len(NETNS_PREFIX):]):
                continue
            sid = name[len(NETNS_PREFIX):]
            try:
                lock = self._take_lock(sid, create=True)
            except OSError as exc:
                logger.warning("netns %s: its lock entry is unusable (%s); left in place", name, exc)
                continue
            # held for the whole removal (created if absent: an owner's file exists before its namespace). The owner flocks
            # BEFORE `netns add`, so a namespace whose lock this process can take has no live owner, and none can appear meanwhile
            if lock is None:
                continue   # a live process (the pool beside a rotation gate, or the gate beside the pool) owns it
            try:
                if not self._domain_absent(sid):
                    logger.warning("netns %s: its domain bbvm-%s may still exist; left in place", name, sid)
                    continue
                self._ip("-n", name, "link", "del", "dev", tap_name(sid), check=False)
                self._ip("netns", "del", name, check=False)
                logger.info("removed orphaned worker namespace %s", name)
            finally:
                self._drop_lock(sid, lock)
        # a tap still in the host namespace (a death between `tuntap add` and the move, or inside a revert window): DOWN and
        # unaddressed, but persistent. Its name carries the first 12 hex of the id; removed when no live owner or domain matches
        r = self._ip("-o", "link", "show", "type", "tun", check=False)
        held = self._held_sids()   # AFTER listing the taps: an owner flocks before it creates its tap, so every tap listed above
        # that has a live owner is held by now (the reverse order let an owner flock and create its tap between the two reads)
        if not r.stdout:
            return
        dl = self._virsh("list", "--all", "--name")
        if dl.returncode != 0:   # libvirt did not answer: a tap's domain is unknown, not absent (as for the namespaces above)
            logger.warning("orphan tap sweep skipped: virsh list failed (rc %s)", dl.returncode)
            return
        domains = dl.stdout or ""   # a substring test below: a 12-hex prefix finds its 16-hex domain name
        for line in (r.stdout or "").splitlines():
            m = re.match(r"\d+:\s+(" + re.escape(TAP_PREFIX) + r"[0-9a-f]{12})[:@]", line)
            if not m:
                continue
            tap = m.group(1)
            prefix = tap[len(TAP_PREFIX):]
            if any(h.startswith(prefix) for h in held) or f"bbvm-{prefix}" in domains:
                continue
            self._ip("link", "del", "dev", tap, check=False)
            logger.info("removed orphaned worker tap %s", tap)

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

    def is_ready(self, slot: VmSlot) -> bool:
        if slot.slot_id not in self._by_sid:
            return False   # torn down (an inline reap of a failed finalize): its address may already be another worker's
        return super().is_ready(slot)

    def recycle(self, slot: VmSlot, ready_timeout_s: float = 60.0) -> None:
        if slot.slot_id not in self._by_sid:
            raise RuntimeError(f"{slot.domain}: its namespace is gone; cannot recycle")
        super().recycle(slot, ready_timeout_s)

    def reap(self, slot: VmSlot) -> None:
        try:
            super().reap(slot)
        except Exception:
            # the base raises in two cases: destroy failed (the guest may still run — the namespace stays, containing it), or
            # the guest is gone and a later cleanup step failed (the overlay rm): then nothing is left to contain
            if self._domain_absent(slot.domain[len("bbvm-"):]):
                self._teardown(slot.slot_id)
            raise
        self._teardown(slot.slot_id)
