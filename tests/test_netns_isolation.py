"""Every VM worker lives in its own network namespace, and nothing touches the host firewall.

The runtime is blastbox's LibvirtVmRuntime with the network-specific steps replaced; these tests
drive the REAL runtime with every host command recorded instead of run, and assert on what it
would have run: the namespace and tap around each domain, the move into the namespace after the
start, the move home around a revert, the teardown after the guest is gone -- and that no command
ever reaches iptables, nftables, ebtables, a kernel module, a host sysctl or a libvirt network.
"""
from __future__ import annotations

import http.server
import socket
import subprocess
import threading
import urllib.error

import pytest

import blastbox.host.runtime.libvirt_vm as libvirt_vm
import winval_blastbox.netns_isolation as ni

FIREWALL = ("iptables", "ip6tables", "iptables-save", "iptables-restore", "nft", "ebtables", "modprobe", "insmod")


class Host:
    """Records every command; answers the few whose output the runtime reads."""

    def __init__(self):
        self.cmds: list[list[str]] = []
        self.defined_xml: list[str] = []
        self.fail: dict[str, tuple[int, str]] = {}   # first word(s) -> (rc, stderr)
        self.netns_list = ""
        self.host_taps = ""
        self.domains = ""
        self.domstate: dict[str, tuple[int, str, str]] = {}
        self.dhcp: list = []

    def run(self, argv, timeout=60, **_):
        argv = list(argv)
        if argv and argv[0] == "sudo":
            argv = argv[1:]
        self.cmds.append(argv)
        if argv[:1] == ["virsh"] and "define" in argv:
            with open(argv[-1]) as fh:
                self.defined_xml.append(fh.read())
        key = " ".join(a for a in argv if not a.startswith("-c") and a != "qemu:///system")
        for prefix, (rc, err) in self.fail.items():
            if key.startswith(prefix):
                return subprocess.CompletedProcess(argv, rc, "", err)
        if argv[:1] == ["test"]:
            return subprocess.CompletedProcess(argv, 1, "", "")   # no overlay of that name yet
        if argv[:3] == ["ip", "netns", "list"]:
            return subprocess.CompletedProcess(argv, 0, self.netns_list, "")
        if argv[:3] == ["ip", "-o", "link"]:
            return subprocess.CompletedProcess(argv, 0, self.host_taps, "")
        if argv[:2] == ["virsh", "list"]:
            return subprocess.CompletedProcess(argv, 0, self.domains, "")
        if argv[:2] == ["virsh", "domstate"]:
            rc, out, err = self.domstate.get(argv[2], (0, "running\n", ""))
            return subprocess.CompletedProcess(argv, rc, out, err)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def spawn_dhcp(self, argv):
        argv = list(argv)   # verbatim: a sudo parent here is a regression (it would not relay the stop)
        self.cmds.append(argv)

        class P:
            terminated = False

            def terminate(self):
                P.terminated = True

            returncode = None

            def wait(self, timeout=None):
                if not P.terminated:
                    raise subprocess.TimeoutExpired("dnsmasq", timeout)
                return 0

            def kill(self):
                pass
        p = P()
        self.dhcp.append(p)
        return p

    def index(self, pred) -> int:
        for i, c in enumerate(self.cmds):
            if pred(c):
                return i
        raise AssertionError(f"no such command in {self.cmds}")


@pytest.fixture
def host(monkeypatch, tmp_path):
    monkeypatch.setattr(ni, "LOCK_DIR", str(tmp_path / "locks"))
    h = Host()
    monkeypatch.setattr(libvirt_vm, "_run", h.run)
    monkeypatch.setattr(ni, "_run", h.run)
    monkeypatch.setattr(ni, "_spawn_dhcp", h.spawn_dhcp)
    return h


def runtime(**over):
    cfg = libvirt_vm.LibvirtVmConfig(golden_base="/dev/shm/golden.qcow2", agent_port=8765, nwfilter="", **over)
    return ni.NetnsVmRuntime(cfg)


def test_spawn_builds_the_namespace_around_the_domain(host):
    rt = runtime()
    slot = rt.spawn()
    sid = slot.slot_id
    ns, tap = f"wvn-{sid}", f"wvt{sid[:12]}"
    assert slot.netns == ns and slot.ip == "192.168.122.10"
    add = host.index(lambda c: c == ["ip", "netns", "add", ns])
    tuntap = host.index(lambda c: c == ["ip", "tuntap", "add", "dev", tap, "mode", "tap", "vnet_hdr"])
    start = host.index(lambda c: c[:1] == ["virsh"] and "start" in c)
    move = host.index(lambda c: c == ["ip", "link", "set", "dev", tap, "netns", ns])
    addr = host.index(lambda c: c == ["ip", "-n", ns, "addr", "replace", "192.168.122.1/24", "dev", tap])
    up = host.index(lambda c: c == ["ip", "-n", ns, "link", "set", "dev", tap, "up"])
    port = host.index(lambda c: c == ["ip", "netns", "exec", ns, "sysctl", "-q", "-w", "net.ipv4.ip_unprivileged_port_start=0"])
    dhcp = host.index(lambda c: c[:5] == ["ip", "netns", "exec", ns, "setpriv"])
    assert add < tuntap < start < move < addr < up < port < dhcp
    dns = host.cmds[dhcp]
    assert "--port=0" in dns and f"--interface={tap}" in dns and "--pid-file=" in dns
    # unprivileged from its first instruction: the guest-facing process can never move the tap out of the namespace
    pre = dns[: dns.index("dnsmasq")]
    assert {"--reuid=65534", "--bounding-set=-all,+net_raw", "--inh-caps=-all,+net_raw", "--ambient-caps=-all,+net_raw",
            "--no-new-privs"} <= set(pre)
    assert not any("net_admin" in w for w in dns)
    assert "sudo" not in dns
    assert "--dhcp-range=192.168.122.10,192.168.122.10,255.255.255.0,infinite" in dns


def test_the_domain_nic_is_the_private_tap_never_a_libvirt_network(host):
    rt = runtime()
    slot = rt.spawn()
    (xml,) = host.defined_xml
    assert f"<interface type='ethernet'><target dev='wvt{slot.slot_id[:12]}' managed='no'/>" in xml
    assert "type='network'" not in xml and "<filterref" not in xml and "<source network" not in xml


def test_no_command_ever_touches_the_host_firewall_or_a_libvirt_network(host):
    rt = runtime()
    a, b = rt.spawn(), rt.spawn()
    rt._virsh("snapshot-revert", a.domain, "clean")
    rt.reap(a)
    rt.reap(b)
    for c in host.cmds:
        assert c[0] not in FIREWALL, c
        assert not any(w in FIREWALL for w in c), c
        if "sysctl" in c:   # only inside a worker namespace, never the host's
            assert c[:3] == ["ip", "netns", "exec"] and c[3].startswith("wvn-"), c
        if c[:1] == ["virsh"]:
            assert not any(w.startswith(("net-", "nwfilter")) for w in c), c


def test_two_workers_get_two_namespaces_and_two_addresses(host):
    rt = runtime()
    a, b = rt.spawn(), rt.spawn()
    assert a.netns != b.netns and a.ip != b.ip
    rt.reap(a)
    c = rt.spawn()
    assert c.ip == "192.168.122.10"   # a reaped worker's address is free again


def test_the_host_address_follows_the_agent_caller_knob(host, monkeypatch):
    monkeypatch.setenv("AUTHENTICODE_AGENT_CALLER", "10.9.8.1")
    slot = runtime().spawn()
    assert slot.ip == "10.9.8.10"
    assert ["ip", "-n", slot.netns, "addr", "replace", "10.9.8.1/24", "dev", f"wvt{slot.slot_id[:12]}"] in host.cmds


@pytest.mark.parametrize("rc", [0, 1])
def test_a_revert_takes_the_tap_home_and_back_whatever_it_returns(host, rc):
    rt = runtime()
    slot = rt.spawn()
    ns, tap = slot.netns, f"wvt{slot.slot_id[:12]}"
    host.cmds.clear()
    if rc:
        host.fail["virsh snapshot-revert"] = (1, "error: Failed to revert snapshot")
    assert rt._virsh("snapshot-revert", slot.domain, "clean").returncode == rc
    home = host.index(lambda c: c == ["ip", "-n", ns, "link", "set", "dev", tap, "netns", "1"])
    revert = host.index(lambda c: c[:1] == ["virsh"] and "snapshot-revert" in c)
    back = host.index(lambda c: c == ["ip", "link", "set", "dev", tap, "netns", ns])
    readdr = host.index(lambda c: c[:5] == ["ip", "-n", ns, "addr", "replace"])
    assert home < revert < back < readdr


def test_reap_tears_the_namespace_down_after_the_guest_is_gone(host):
    rt = runtime()
    slot = rt.spawn()
    host.cmds.clear()
    rt.reap(slot)
    destroy = host.index(lambda c: c[:1] == ["virsh"] and "destroy" in c)
    nsdel = host.index(lambda c: c == ["ip", "netns", "del", slot.netns])
    assert destroy < nsdel
    assert host.dhcp[0].terminated


def test_a_failed_destroy_leaves_the_namespace_containing_the_guest(host):
    rt = runtime()
    slot = rt.spawn()
    host.cmds.clear()
    host.fail["virsh destroy"] = (1, "error: internal error: something broke")
    with pytest.raises(RuntimeError):
        rt.reap(slot)
    assert ["ip", "netns", "del", slot.netns] not in host.cmds


def test_a_failed_start_removes_what_it_built(host):
    rt = runtime()
    host.fail["virsh start"] = (1, "error: failed")
    with pytest.raises(RuntimeError):
        rt.spawn()
    ns = next(c[3] for c in host.cmds if c[:3] == ["ip", "netns", "add"])
    assert ["ip", "netns", "del", ns] in host.cmds
    assert rt._by_sid == {}


def test_a_failed_move_into_the_namespace_reaps_the_worker(host):
    rt = runtime()
    host.fail["ip link set dev wvt"] = (2, "RTNETLINK answers: Invalid argument")
    with pytest.raises(RuntimeError):
        rt.spawn()
    assert any(c[:1] == ["virsh"] and "destroy" in c for c in host.cmds[-12:])
    assert rt._by_sid == {}


def test_the_agent_probe_runs_inside_the_slots_namespace_only(host, monkeypatch):
    seen = []

    def fake_connect(ns, addr, timeout):
        seen.append((ns, addr))
        return socket.socket()
    monkeypatch.setattr(ni, "netns_connect", fake_connect)
    rt = runtime()
    slot = rt.spawn()
    assert rt._port_up(slot.ip) is True
    assert seen == [(slot.netns, (slot.ip, 8765))]
    monkeypatch.setattr(libvirt_vm.LibvirtVmRuntime, "_port_up", lambda *a, **k: pytest.fail("probed in the HOST namespace"))
    assert rt._port_up("192.168.122.99") is False and len(seen) == 1   # an address no worker holds is never probed


@pytest.mark.parametrize("over", [{"worker_ip_pool": "192.168.122.200-192.168.122.210"}])
def test_host_side_egress_configs_are_refused(host, over):
    with pytest.raises(ValueError):
        runtime(**over)


def test_an_egress_policy_is_refused(host):
    from blastbox.host.runtime.libvirt_egress import VmEgressPolicy
    with pytest.raises(ValueError, match="iptables"):
        runtime(egress_policy=VmEgressPolicy(exit_driver="direct"))


def test_orphaned_namespaces_of_absent_domains_are_removed_others_left(host):
    gone, live = "a" * 16, "b" * 16
    host.netns_list = f"wvn-{gone}\nwvn-{live} (id: 3)\nsomeone-elses\nwvn-notahexsid\n"
    host.domstate[f"bbvm-{gone}"] = (1, "", "error: failed to get domain 'bbvm-aaaa'")
    host.domstate[f"bbvm-{live}"] = (0, "running\n", "")
    runtime()
    assert ["ip", "netns", "del", f"wvn-{gone}"] in host.cmds
    assert ["ip", "netns", "del", f"wvn-{live}"] not in host.cmds
    assert not any(c[:3] == ["ip", "netns", "del"] and c[3] in ("someone-elses", "wvn-notahexsid") for c in host.cmds)


def test_an_unanswering_libvirt_is_not_read_as_an_absent_domain(host):
    sid = "c" * 16
    host.netns_list = f"wvn-{sid}\n"
    host.domstate[f"bbvm-{sid}"] = (1, "", "error: failed to connect to the hypervisor")
    runtime()
    assert ["ip", "netns", "del", f"wvn-{sid}"] not in host.cmds


def test_the_xml_swap_fails_closed_when_blastbox_changes_shape(host, monkeypatch):
    rt = runtime()
    monkeypatch.setattr(libvirt_vm.LibvirtVmRuntime, "_domain_xml", lambda self, *a, **k: "<domain><devices></devices></domain>")
    with pytest.raises(RuntimeError, match="libvirt network"):
        rt.spawn()


def test_netns_socket_refuses_a_name_that_is_not_a_workers():
    for bad in ("", "../../proc/1/ns/net", "wvn-XYZ", "cni-1234"):
        with pytest.raises(ValueError):
            ni.netns_socket(bad)


class _Agent(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        self.rfile.read(int(self.headers["Content-Length"]))
        code = 500 if "fail" in self.path else 200
        body = b'{"status": "Valid"}'
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture
def agent(monkeypatch):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Agent)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    used = []

    def fake_connect(ns, addr, timeout):   # the namespace is the test host's own: what matters is that the agent call goes through here
        used.append(ns)
        return socket.create_connection(addr, timeout)
    monkeypatch.setattr(ni, "netns_connect", fake_connect)
    yield srv.server_address, used
    srv.shutdown()


def test_the_agent_call_goes_through_the_namespace_and_keeps_urllibs_errors(agent, tmp_path):
    from winval_blastbox.vm_pool import agent_validate, fault_of
    (addr, used) = agent
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" * 100)
    assert agent_validate(addr, str(sample), netns="wvn-" + "d" * 16) == {"status": "Valid"}
    assert used == ["wvn-" + "d" * 16]
    with pytest.raises(urllib.error.HTTPError) as exc:
        agent_validate(addr, str(tmp_path / "s.exe"), netns="wvn-" + "d" * 16, params={"rev": "fail"})
    assert fault_of(exc.value) == "job"


def test_a_refused_agent_in_the_namespace_is_a_worker_fault(monkeypatch, tmp_path):
    from winval_blastbox.vm_pool import agent_validate, fault_of

    def refused(ns, addr, timeout):
        raise ConnectionRefusedError(111, "Connection refused")
    monkeypatch.setattr(ni, "netns_connect", refused)
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    with pytest.raises(urllib.error.URLError) as exc:
        agent_validate(("192.168.122.10", 8765), str(sample), netns="wvn-" + "e" * 16)
    assert fault_of(exc.value) == "worker"


def _hold(sid):
    """Another live process owning a worker id: its own open + flock of the same lock file."""
    import fcntl
    import os
    os.makedirs(ni.LOCK_DIR, exist_ok=True)
    fd = os.open(os.path.join(ni.LOCK_DIR, f"{sid}.lock"), os.O_RDWR | os.O_CREAT)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    return fd


def test_the_sweep_never_takes_a_namespace_another_live_process_owns(host):
    """The rotation gate builds its runtime while the pool runs: a pool worker mid-spawn has a namespace but no domain yet."""
    sid = "f" * 16
    fd = _hold(sid)
    host.netns_list = f"wvn-{sid}\n"
    host.domstate[f"bbvm-{sid}"] = (1, "", "error: failed to get domain")
    runtime()
    assert ["ip", "netns", "del", f"wvn-{sid}"] not in host.cmds
    import os
    os.close(fd)
    runtime()   # the owner is gone: now it is an orphan
    assert ["ip", "netns", "del", f"wvn-{sid}"] in host.cmds


def test_a_gate_runtime_beside_a_spawning_pool_leaves_its_namespace(host):
    pool = runtime()
    slot = pool.spawn()
    host.netns_list = f"{slot.netns}\n"
    host.domstate[slot.domain] = (1, "", "error: failed to get domain")   # as between `netns add` and `virsh define`
    runtime()
    assert ["ip", "netns", "del", slot.netns] not in host.cmds


def test_orphaned_host_namespace_taps_are_removed_owned_ones_left(host):
    gone, owned, defined = "1" * 16, "2" * 16, "3" * 16
    fd = _hold(owned)
    host.host_taps = "".join(f"{i}: wvt{s[:12]}: <BROADCAST> mtu 1500\n" for i, s in enumerate((gone, owned, defined), 40)) + "50: tun0: <POINTOPOINT>\n"
    host.domains = f"bbvm-{defined}\n"
    runtime()
    assert ["ip", "link", "del", "dev", f"wvt{gone[:12]}"] in host.cmds
    assert ["ip", "link", "del", "dev", f"wvt{owned[:12]}"] not in host.cmds
    assert ["ip", "link", "del", "dev", f"wvt{defined[:12]}"] not in host.cmds
    assert ["ip", "link", "del", "dev", "tun0"] not in host.cmds
    import os
    os.close(fd)


def test_a_reap_that_fails_after_the_guest_is_gone_still_tears_down(host):
    rt = runtime()
    slot = rt.spawn()
    host.fail["rm -f"] = (1, "rm: cannot remove: Device or resource busy")
    host.domstate[slot.domain] = (1, "", "error: failed to get domain")
    with pytest.raises(RuntimeError):
        rt.reap(slot)
    assert ["ip", "netns", "del", slot.netns] in host.cmds
    assert host.dhcp[0].terminated and rt._by_sid == {}


def test_a_torn_down_slot_is_never_probed_in_anothers_namespace(host, monkeypatch):
    seen = []
    monkeypatch.setattr(ni, "netns_connect", lambda ns, addr, timeout: seen.append(ns) or socket.socket())
    rt = runtime()
    a = rt.spawn()
    rt.reap(a)
    b = rt.spawn()
    assert b.ip == a.ip
    assert rt.is_ready(a) is False and seen == []
    with pytest.raises(RuntimeError):
        rt.recycle(a)


def test_a_dnsmasq_that_dies_at_start_fails_the_spawn(host, monkeypatch):
    class Dead:
        returncode = 2
        stderr = None

        def wait(self, timeout=None):
            return 2

        def terminate(self):
            pass

        def kill(self):
            pass
    monkeypatch.setattr(ni, "_spawn_dhcp", lambda argv: Dead())
    rt = runtime()
    with pytest.raises(RuntimeError, match="dnsmasq exited"):
        rt.spawn()
    assert rt._by_sid == {}


def test_ipv6_left_on_fails_the_spawn_closed(host):
    host.fail["ip netns exec"] = (1, "sysctl: permission denied")
    import re as _re
    with pytest.raises(RuntimeError, match="IPv6 not disabled"):
        runtime().spawn()
    assert not any(c[:2] == ["ip", "-n"] and c[-1] == "up" and _re.match(r"wvt", c[-2]) for c in host.cmds), "the tap came up with IPv6 on"


def test_agent_validate_never_falls_back_to_the_host_namespace(tmp_path):
    from winval_blastbox.vm_pool import agent_validate
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    with pytest.raises(ValueError, match="namespace"):
        agent_validate(("192.168.122.10", 8765), str(sample))


def test_every_production_agent_call_carries_the_slots_namespace(monkeypatch, tmp_path):
    """validate, the smoke and the CRL warm all go through the slot's namespace (dropping netns= from any is caught here)."""
    import types
    import winval_blastbox.vm_pool as vp
    seen = []
    monkeypatch.setattr(vp, "agent_validate", lambda endpoint, path, timeout=60.0, params=None, netns=None: seen.append(netns) or {"status": "Valid"})
    slot = types.SimpleNamespace(endpoint=("192.168.122.10", 8765), netns="wvn-" + "a" * 16, ip="192.168.122.10")
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ")
    monkeypatch.setenv("AUTHENTICODE_SMOKE_SAMPLE", str(sample))
    monkeypatch.setenv("AUTHENTICODE_WARM_DIR", str(tmp_path))
    vp._smoke(slot)
    vp._warm_crl(slot)

    class Pool:
        def claim(self, timeout_s):
            return slot

        def release(self, s, **kw):
            pass
    pool = vp.WarmVmPool.__new__(vp.WarmVmPool)
    pool._pool, pool._claim_timeout_s = Pool(), 1
    pool.validate(str(sample))
    assert seen and all(ns == slot.netns for ns in seen), seen


def test_the_clock_fallback_ssh_runs_inside_the_namespace(monkeypatch):
    import types
    import winval_blastbox.vm_pool as vp
    argv = []
    monkeypatch.setattr(vp.subprocess, "run", lambda a, **k: argv.append(a))
    vp._sync_clock(types.SimpleNamespace(netns="wvn-" + "a" * 16, ip="192.168.122.10"))
    assert argv[0][:4] == ["ip", "netns", "exec", "wvn-" + "a" * 16]


def test_the_golden_admits_exactly_the_address_the_workers_call_from(monkeypatch):
    import golden_build
    assert golden_build.agent_caller() == str(ni.host_addr().ip) == "192.168.122.1"
    monkeypatch.setenv("AUTHENTICODE_AGENT_CALLER", "10.20.30.1")
    assert golden_build.agent_caller() == str(ni.host_addr().ip) == "10.20.30.1"


def test_the_namespace_connection_disables_nagle(agent):
    (addr, _) = agent
    conn = ni._NetnsHTTPConnection(*addr, timeout=5)
    conn.netns = "wvn-" + "d" * 16
    conn.connect()
    assert conn.sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0
    conn.close()


def test_an_unanswering_libvirt_never_frees_a_host_namespace_tap(host):
    sid = "4" * 16
    host.host_taps = f"40: wvt{sid[:12]}: <BROADCAST> mtu 1500\n"
    host.fail["virsh list"] = (1, "error: failed to connect to the hypervisor")
    runtime()
    assert ["ip", "link", "del", "dev", f"wvt{sid[:12]}"] not in host.cmds


def test_a_lock_probe_never_creates_and_reclaims_a_dead_owners_file(host):
    import os
    os.makedirs(ni.LOCK_DIR, exist_ok=True)
    assert ni.NetnsVmRuntime._take_lock("9" * 16) is None and not os.path.exists(os.path.join(ni.LOCK_DIR, "9" * 16 + ".lock"))
    stale = os.path.join(ni.LOCK_DIR, "8" * 16 + ".lock")
    open(stale, "w").close()   # a crashed owner's file: no flock on it
    assert ni.NetnsVmRuntime._held_sids() == [] and not os.path.exists(stale)
    fd = _hold("7" * 16)
    assert ni.NetnsVmRuntime._held_sids() == ["7" * 16]
    os.close(fd)


def test_an_owner_whose_file_was_reclaimed_under_it_relocks_the_new_one(host, monkeypatch):
    """An owner that opened its file just before a sweep unlinked it must not keep a lock nobody else can see."""
    import os
    sid = "6" * 16
    path = os.path.join(ni.LOCK_DIR, sid + ".lock")
    real_flock, done = ni.fcntl.flock, []

    def flock(fd, op):
        if not done:   # between the owner's open and its flock, a sweep reclaims the (unlocked) file
            done.append(1)
            os.unlink(path)
        return real_flock(fd, op)
    monkeypatch.setattr(ni.fcntl, "flock", flock)
    fd = ni.NetnsVmRuntime._take_lock(sid, create=True)
    assert fd is not None and os.fstat(fd).st_ino == os.stat(path).st_ino
    os.close(fd)


def test_the_tap_sweep_lists_taps_before_reading_the_owners(host, monkeypatch):
    order = []
    real = ni.NetnsVmRuntime._held_sids
    monkeypatch.setattr(ni.NetnsVmRuntime, "_held_sids", staticmethod(lambda: order.append("held") or real()))
    real_run = host.run

    def run(argv, timeout=60, **k):
        if list(argv)[-2:] == ["type", "tun"]:
            order.append("taps")
        return real_run(argv, timeout, **k)
    monkeypatch.setattr(ni, "_run", run)
    host.host_taps = "40: wvt" + "5" * 12 + ": <BROADCAST>\n"
    runtime()
    assert order.index("taps") < order.index("held"), order


def _gate(gr, monkeypatch, tmp_path, verdicts):
    import types
    import winval_blastbox.vm_pool as vp
    benign, revoked = tmp_path / "b.exe", tmp_path / "r.exe"
    benign.write_bytes(b"MZ")
    revoked.write_bytes(b"MZ")
    cand = tmp_path / "c.qcow2"
    cand.write_bytes(b"q")
    monkeypatch.setattr(gr, "BENIGN", str(benign))
    monkeypatch.setattr(gr, "REVOKED", str(revoked))
    slot = types.SimpleNamespace(endpoint=("192.168.122.10", 8765), netns="wvn-" + "a" * 16)
    rt = types.SimpleNamespace(spawn_ready=lambda timeout_s: slot, reap=lambda s: None)
    monkeypatch.setattr(vp, "build_runtime", lambda spec, **k: rt)
    sent = verdicts.setdefault("_sent", [])
    monkeypatch.setattr(vp, "agent_validate", lambda ep, sample, **k: sent.append(k.get("params")) or verdicts["r" if sample.endswith("r.exe") else "b"])
    return gr.validate_golden(str(cand))


VALID_ONLINE = {"status": "Valid", "chain": {"revoked": False, "revocation_checked": "online"}}


@pytest.mark.parametrize("rev, passes", [
    ({"status": "Revoked", "chain": {"revoked": True, "revocation_checked": "offline"}}, True),
    ({"status": "Distrusted", "chain": {"revoked": False, "revocation_checked": "unknown"}}, True),   # on the Disallowed list
    ({"status": "Valid", "chain": {"revoked": False, "revocation_checked": "unknown"}}, False),   # lost entry / uncheckable: fails
    ({"status": "Valid", "chain": {"revoked": False, "revocation_checked": "online"}}, False),
    ({"status": "Valid", "chain": {"revoked": False, "revocation_checked": "none"}}, False),
    ({"status": "Valid"}, False),
    ({"status": "UntrustedRoot", "chain": {"revoked": False, "revocation_checked": "unknown"}}, False),
    ({"status": "Distrusted", "chain": {"revoked": False, "revocation_checked": "none"}}, False),   # Disallowed sample, revocation OFF
])
def test_the_revoked_half_of_the_gate_offline(gr, monkeypatch, tmp_path, rev, passes):
    assert _gate(gr, monkeypatch, tmp_path, {"b": VALID_ONLINE, "r": rev}) is passes


def test_an_unusable_lock_entry_never_aborts_the_runtime_or_leaks_a_lock(host):
    import os
    os.makedirs(ni.LOCK_DIR, exist_ok=True)
    os.mkdir(os.path.join(ni.LOCK_DIR, "c" * 16 + ".lock"))           # a directory where a lock file belongs
    os.symlink("/etc/passwd", os.path.join(ni.LOCK_DIR, "d" * 16 + ".lock"))
    host.netns_list = f"wvn-{'c' * 16}\nwvn-{'d' * 16}\n"
    host.domstate[f"bbvm-{'c' * 16}"] = host.domstate[f"bbvm-{'d' * 16}"] = (1, "", "error: failed to get domain")
    runtime()   # constructs
    assert not any(c[:3] == ["ip", "netns", "del"] for c in host.cmds)


def test_a_stat_failure_after_the_flock_releases_the_lock(host, monkeypatch):
    import fcntl
    import os
    real = os.stat
    monkeypatch.setattr(ni.os, "stat", lambda p, **k: (_ for _ in ()).throw(PermissionError(13, "denied")) if str(p).endswith(".lock") else real(p, **k))
    with pytest.raises(PermissionError):
        ni.NetnsVmRuntime._take_lock("e" * 16, create=True)
    fd = os.open(os.path.join(ni.LOCK_DIR, "e" * 16 + ".lock"), os.O_RDWR)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)   # free: nothing leaked it
    os.close(fd)


def test_a_loose_lock_directory_is_tightened(host):
    import os
    os.makedirs(ni.LOCK_DIR, mode=0o777, exist_ok=True)
    os.chmod(ni.LOCK_DIR, 0o1777)
    ni.NetnsVmRuntime._lock_dir()
    assert os.stat(ni.LOCK_DIR).st_mode & 0o7777 == 0o700


def test_a_benign_judged_with_revocation_off_fails_the_gate(gr, monkeypatch, tmp_path):
    rev = {"status": "Distrusted", "chain": {"revoked": False, "revocation_checked": "unknown"}}
    off = {"status": "Valid", "chain": {"revoked": False, "revocation_checked": "none"}}
    assert _gate(gr, monkeypatch, tmp_path, {"b": off, "r": rev}) is False


def test_taking_a_lock_tightens_and_vets_the_lock_directory(host):
    import os
    os.makedirs(ni.LOCK_DIR, exist_ok=True)
    os.chmod(ni.LOCK_DIR, 0o1777)
    fd = ni.NetnsVmRuntime._take_lock("b" * 16, create=True)
    os.close(fd)
    assert os.stat(ni.LOCK_DIR).st_mode & 0o7777 == 0o700


def test_a_symlinked_lock_directory_is_refused(host, tmp_path, monkeypatch):
    import os
    real = tmp_path / "elsewhere"
    real.mkdir()
    link = tmp_path / "linked"
    os.symlink(real, link)
    monkeypatch.setattr(ni, "LOCK_DIR", str(link))
    with pytest.raises(RuntimeError, match="not a directory owned"):
        ni.NetnsVmRuntime._take_lock("b" * 16, create=True)


@pytest.mark.parametrize("benign, passes", [
    ({"status": "Valid"}, False),                                                          # no chain: revocation unjudgeable
    ({"status": "Valid", "chain": {"revoked": False}}, False),                             # field missing
    ({"status": "Valid", "chain": {"revoked": False, "revocation_checked": "off"}}, False),
    ({"status": "Valid", "chain": {"revoked": False, "revocation_checked": "unknown"}}, True),
])
def test_the_gate_judges_only_verdicts_whose_revocation_it_can_see(gr, monkeypatch, tmp_path, benign, passes):
    rev = {"status": "Distrusted", "chain": {"revoked": False, "revocation_checked": "unknown"}}
    assert _gate(gr, monkeypatch, tmp_path, {"b": benign, "r": rev}) is passes


def test_the_gate_sends_the_knobs_production_sends_and_honours_rev_none_by_choice(gr, monkeypatch, tmp_path):
    monkeypatch.setenv("AUTHENTICODE_REV", "none")
    off = {"status": "Valid", "chain": {"revoked": False, "revocation_checked": "none"}}
    rev = {"status": "Distrusted", "chain": {"revoked": False, "revocation_checked": "none"}}
    verdicts = {"b": off, "r": rev}
    assert _gate(gr, monkeypatch, tmp_path, verdicts) is True
    assert verdicts["_sent"] and all(p == {"rev": "none"} for p in verdicts["_sent"])
