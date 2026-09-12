"""The pool-manager refuses to start a posture that would put workers on the network.

Two rules, both refusals rather than warnings:

* A worker started with no exit driver reaches the libvirt network's plain NAT and the
  host's own listeners. Naming no driver is not a default, it is a refusal -- and the
  way to run with no egress policy on purpose is to say so.
* Several workers share one bridge, so unless something actually drops worker-to-worker
  traffic they can reach each other. The three things that count are the explicit
  block, a port allowlist that does not admit the agent's own port, and the exit driver
  whose chain ends in a drop.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def refuse(monkeypatch, tmp_path):
    """Call the real refusal with a given posture and report what it said."""
    import winval_blastbox.pool_manager as pool_manager

    sysctl_on = tmp_path / "on"
    sysctl_on.write_text("1\n")
    sysctl_off = tmp_path / "off"
    sysctl_off.write_text("0\n")
    files = {"on": str(sysctl_on), "off": str(sysctl_off), "absent": str(tmp_path / "absent")}

    def call(knobs, workers=2, sysctl="on"):
        for key in [k for k in __import__("os").environ if k.startswith("AUTHENTICODE_")]:
            monkeypatch.delenv(key, raising=False)
        for key, value in knobs.items():
            monkeypatch.setenv(key, value)
        # a path no worker boots from: these tests are about the network, not the image
        monkeypatch.setenv("AUTHENTICODE_GOLDEN_BASE", "/nonexistent/golden.qcow2")
        monkeypatch.setattr(pool_manager, "BRIDGE_NF_SYSCTL", files[sysctl])
        try:
            pool_manager._refuse_open_egress(workers)
            return "proceeds"
        except SystemExit as exc:
            return str(exc)
        except Exception as exc:  # a fail-closed parser in blastbox itself
            return f"{type(exc).__name__}: {exc}"

    return call


def test_an_unset_exit_driver_is_refused_and_the_opt_out_is_named(refuse):
    said = refuse({})
    assert "AUTHENTICODE_EXIT is not set" in said
    assert "AUTHENTICODE_EXIT=none" in said, "the refusal does not say how to opt out"


def test_no_policy_on_purpose_proceeds(refuse):
    assert refuse({"AUTHENTICODE_EXIT": "none"}, workers=4, sysctl="absent") == "proceeds"


def test_a_single_worker_has_no_sibling_to_reach(refuse):
    assert refuse({"AUTHENTICODE_EXIT": "direct"}, workers=1, sysctl="absent") == "proceeds"


def test_siblings_with_nothing_dropping_them_are_refused(refuse):
    said = refuse({"AUTHENTICODE_EXIT": "direct"})
    assert "AUTHENTICODE_BLOCK_INTERNAL=1" in said
    # the refusal names all three ways out, not just the first
    assert "AUTHENTICODE_EGRESS_PORTS" in said and "AUTHENTICODE_EXIT=drop" in said, said
    assert "run one worker" in said, said


def test_the_block_is_not_believed_when_the_kernel_cannot_enforce_it(refuse):
    """Bridged traffic only reaches iptables when br_netfilter says so."""
    said = refuse({"AUTHENTICODE_EXIT": "direct", "AUTHENTICODE_BLOCK_INTERNAL": "1"}, sysctl="off")
    assert "br_netfilter" in said
    said = refuse(
        {"AUTHENTICODE_EXIT": "direct", "AUTHENTICODE_BLOCK_INTERNAL": "1"}, sysctl="absent"
    )
    assert "br_netfilter" in said


def test_the_block_with_the_kernel_behind_it_proceeds(refuse):
    assert (
        refuse({"AUTHENTICODE_EXIT": "direct", "AUTHENTICODE_BLOCK_INTERNAL": "1"}) == "proceeds"
    )


def test_an_allowlist_that_excludes_the_agent_port_drops_siblings(refuse):
    assert (
        refuse({"AUTHENTICODE_EXIT": "direct", "AUTHENTICODE_EGRESS_PORTS": "53,80,443"})
        == "proceeds"
    )


def test_an_allowlist_that_admits_the_agent_port_does_not(refuse):
    """The agent port is the one a sibling would use to drive another worker."""
    said = refuse({"AUTHENTICODE_EXIT": "direct", "AUTHENTICODE_EGRESS_PORTS": "53,80,443,8765"})
    assert "EGRESS_PORTS" in said


def test_the_configured_agent_port_is_the_one_checked(refuse):
    said = refuse(
        {
            "AUTHENTICODE_EXIT": "direct",
            "AUTHENTICODE_EGRESS_PORTS": "53,9000",
            "AUTHENTICODE_AGENT_PORT": "9000",
        }
    )
    assert "EGRESS_PORTS" in said


def test_the_drop_exit_needs_no_second_opinion(refuse):
    assert refuse({"AUTHENTICODE_EXIT": "drop"}) == "proceeds"


def test_a_typo_in_the_boolean_is_never_read_as_off(refuse):
    said = refuse({"AUTHENTICODE_EXIT": "direct", "AUTHENTICODE_BLOCK_INTERNAL": "treu"})
    assert said.startswith("ValueError"), said
