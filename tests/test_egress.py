"""The pool-manager's network posture is fixed: a private network namespace per worker, no egress.

The rooter era's exits (direct, drop, openvpn, wireguard, tor, inetsim) and their knobs installed
iptables chains and needed br_netfilter on the host. They are gone; a value that asks for one is a
refusal by name, never silently ignored -- the operator must learn the worker has no egress.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def refuse(monkeypatch):
    """Call the real start refusal with a given environment and report what it said."""
    import winval_blastbox.pool_manager as pool_manager

    def call(knobs, workers=2):
        for key, value in knobs.items():
            monkeypatch.setenv(key, value)
        try:
            pool_manager._refuse_open_egress(workers)
            return "proceeds"
        except SystemExit as exc:
            return str(exc)

    return call


def test_an_unset_exit_is_no_egress_and_proceeds(refuse):
    assert refuse({}) == "proceeds"


@pytest.mark.parametrize("value", ["none", "NONE", " none "])
def test_none_proceeds_for_any_pool_size(refuse, value):
    assert refuse({"AUTHENTICODE_EXIT": value}, workers=8) == "proceeds"


@pytest.mark.parametrize("value", ["direct", "drop", "openvpn", "wireguard", "tor", "inetsim", "socks"])
def test_every_host_firewall_exit_is_refused_by_name(refuse, value):
    said = refuse({"AUTHENTICODE_EXIT": value})
    assert f"AUTHENTICODE_EXIT='{value}'" in said
    assert "iptables" in said and "AUTHENTICODE_EXIT=none" in said


@pytest.mark.parametrize("knob", ["AUTHENTICODE_EGRESS_PORTS", "AUTHENTICODE_VPN_TABLE", "AUTHENTICODE_VPN_TUN",
                                  "AUTHENTICODE_FAKENET_ADDR", "AUTHENTICODE_GATEWAY", "AUTHENTICODE_LEG", "AUTHENTICODE_IP_POOL",
                                  "AUTHENTICODE_LIBVIRT_NETWORK"])
def test_a_rooter_era_knob_is_refused_not_ignored(refuse, knob):
    said = refuse({"AUTHENTICODE_EXIT": "none", knob: "x"})
    assert knob in said
    if knob == "AUTHENTICODE_LIBVIRT_NETWORK":   # the remedy, not only the refusal: the golden admits that network's address
        assert "AUTHENTICODE_AGENT_CALLER" in said


def test_block_internal_only_ever_restricted_so_it_is_ignored(refuse):
    assert refuse({"AUTHENTICODE_BLOCK_INTERNAL": "1"}) == "proceeds"


def test_a_malformed_host_address_is_refused(refuse):
    assert "AUTHENTICODE_AGENT_CALLER" in refuse({"AUTHENTICODE_AGENT_CALLER": "Any"})


def test_missing_host_tools_are_named(refuse, monkeypatch):
    import winval_blastbox.pool_manager as pool_manager
    monkeypatch.setattr(pool_manager, "_which", lambda name, path=None: None if name == "dnsmasq" else f"/usr/sbin/{name}")
    said = refuse({})
    assert "dnsmasq" in said and "not found" in said


def test_the_spec_never_carries_host_egress():
    from winval_blastbox.vm_pool import authenticode_spec
    spec = authenticode_spec()
    assert spec.egress is None and spec.routing is None
    assert spec.nwfilter == "" and spec.worker_ip_pool == ""
