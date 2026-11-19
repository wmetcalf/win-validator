"""The pre-upgrade gate: a posture that would break the box is refused before the move.

deploy/upgrade.sh checks the operator's winval.env against the same rules the
pool-manager applies at start and the rotation applies before it promotes, so a bad knob
is a refusal with the tree untouched rather than a service that will not come back.

Two rules about WHEN a verdict is fatal:

* A knob the pool-manager reads bites only when something starts, so without --restart
  it is a warning.
* A knob the ROTATION reads bites on a timer, and both halves of the upgrade install and
  reload that timer -- so it is fatal in both, and it gets its own pass, because the
  helper prints one verdict and a start-time knob would otherwise mask it.
"""
from __future__ import annotations

import subprocess

import pytest

from conftest import REPO, run_upgrade_gate


def write_env(tmp_path, **knobs):
    path = tmp_path / "winval.env"
    path.write_text("".join(f"{k}={v}\n" for k, v in knobs.items()))
    return path


class TestTheRotationsOwnKnob:
    """GOLDEN_BASE is the rotator's old name for the RAM base and nothing else reads it,
    so a rotation started with it promotes to a path no worker boots from."""

    def test_an_old_name_pointing_elsewhere_is_refused(self, tmp_path):
        env = write_env(tmp_path, AUTHENTICODE_EXIT="direct", GOLDEN_BASE="/dev/shm/mine.qcow2")
        verdict = run_upgrade_gate("rotation", env)
        assert verdict.startswith("rotation:"), verdict
        assert "OLD name" in verdict and "rename" in verdict

    def test_an_old_name_naming_the_same_path_is_accepted(self, tmp_path):
        env = write_env(
            tmp_path,
            AUTHENTICODE_EXIT="direct",
            AUTHENTICODE_GOLDEN_BASE="/dev/shm/mine.qcow2",
            GOLDEN_BASE="/dev/shm/mine.qcow2",
        )
        assert run_upgrade_gate("rotation", env) == "ok"

    def test_a_blank_new_name_does_not_silence_it(self, tmp_path):
        """A blank value resolves to the default, which is not what the old name says."""
        env = write_env(
            tmp_path,
            AUTHENTICODE_EXIT="direct",
            AUTHENTICODE_GOLDEN_BASE="",
            GOLDEN_BASE="/dev/shm/mine.qcow2",
        )
        assert "OLD name" in run_upgrade_gate("rotation", env)

    def test_it_has_its_own_pass_so_no_start_time_knob_masks_it(self, tmp_path):
        """The egress helper prints the pool-manager's FIRST complaint and stops. If the
        rotation's knob were judged there it would never be reached on a file that also
        has a start-time problem -- which is most files that have this one."""
        env = write_env(
            tmp_path,
            AUTHENTICODE_EXIT="none",
            AUTHENTICODE_SMOKE_SAMPLE="/nonexistent/sample.exe",
            GOLDEN_BASE="/dev/shm/mine.qcow2",
        )
        assert "SMOKE_SAMPLE" in run_upgrade_gate("egress", env)
        assert "OLD name" in run_upgrade_gate("rotation", env)


class TestTheManagersKnobs:
    """Judged in the order the pool-manager itself judges them, so the gate names the
    same knob the service would name."""

    def test_an_unset_exit_driver_is_no_egress_and_accepted(self, tmp_path):
        assert run_upgrade_gate("egress", write_env(tmp_path)) == "ok"

    def test_no_egress_policy_on_purpose_is_accepted(self, tmp_path):
        assert run_upgrade_gate("egress", write_env(tmp_path, AUTHENTICODE_EXIT="none")) == "ok"

    @pytest.mark.parametrize("exit_driver", ["direct", "drop", "tor", "openvpn"])
    def test_a_host_firewall_exit_is_refused_with_the_remedy_named(self, tmp_path, exit_driver):
        verdict = run_upgrade_gate("egress", write_env(tmp_path, AUTHENTICODE_EXIT=exit_driver))
        assert verdict.startswith("refuse:") and "AUTHENTICODE_EXIT=none" in verdict and "iptables" in verdict

    def test_a_rooter_era_knob_is_refused(self, tmp_path):
        env = write_env(tmp_path, AUTHENTICODE_EXIT="none", AUTHENTICODE_EGRESS_PORTS="53,80,443")
        assert "AUTHENTICODE_EGRESS_PORTS" in run_upgrade_gate("egress", env)

    def test_block_internal_is_ignored(self, tmp_path):
        assert run_upgrade_gate("egress", write_env(tmp_path, AUTHENTICODE_BLOCK_INTERNAL="1")) == "ok"

    @pytest.mark.parametrize("caller", ["Any", "192.168.122.0", "10.0.0.255"])
    def test_a_namespace_address_the_manager_refuses_is_refused(self, tmp_path, caller):
        assert "AUTHENTICODE_AGENT_CALLER" in run_upgrade_gate("egress", write_env(tmp_path, AUTHENTICODE_AGENT_CALLER=caller))

    def test_the_exit_is_judged_before_the_golden_base(self, tmp_path):
        """Both are wrong; the manager refuses the exit first, so the gate names it first."""
        env = write_env(tmp_path, AUTHENTICODE_EXIT="direct", AUTHENTICODE_GOLDEN_BASE="/dev/shm/g\u00a0b.qcow2")
        verdict = run_upgrade_gate("egress", env)
        assert "AUTHENTICODE_EXIT" in verdict and "GOLDEN_BASE" not in verdict


def case_block():
    """The script's own dispatch on a verdict, lifted out of upgrade.sh."""
    lines = (REPO / "deploy" / "upgrade.sh").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("rverdict=$("))
    end = next(i for i, line in enumerate(lines) if i > start and line == "esac" and i > start + 6)
    return "\n".join(lines[start : end + 1])


@pytest.mark.parametrize("restart", ["yes", "no"])
def test_a_rotation_verdict_is_fatal_in_both_halves(restart, tmp_path):
    """Both halves install the units and reload systemd, so both must refuse a posture
    the weekly rotation would refuse -- otherwise the upgrade lands green and the
    rotation dies on the timer days later."""
    script = case_block()
    script = script.replace(
        'rverdict=$(envfile_py rotation "$ETC/winval.env")',
        'rverdict="rotation: GOLDEN_BASE=... is the rotator\'s OLD name"',
    )
    script = script.replace('verdict=$(envfile_py egress "$ETC/winval.env")', 'verdict=ok')
    proc = subprocess.run(
        ["/bin/sh", "-c", f'ETC=/tmp; restart={restart}\n{script}\necho REACHED-THE-MOVE'],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "REACHED-THE-MOVE" not in proc.stdout
    assert "not moved" in (proc.stdout + proc.stderr)


def test_a_start_time_verdict_only_warns_without_a_restart(tmp_path):
    """The counterpart: nothing starts without --restart, so a start-time knob is said
    loudly and the upgrade proceeds."""
    script = case_block()
    script = script.replace(
        'rverdict=$(envfile_py rotation "$ETC/winval.env")', 'rverdict=ok'
    ).replace(
        'verdict=$(envfile_py egress "$ETC/winval.env")',
        'verdict="malformed: AUTHENTICODE_SMOKE_SAMPLE=... is not a file"',
    )
    proc = subprocess.run(
        ["/bin/sh", "-c", f'ETC=/tmp; restart=no\n{script}\necho REACHED-THE-MOVE'],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0
    assert "REACHED-THE-MOVE" in proc.stdout
    assert "WARNING" in proc.stderr


def test_the_verdict_is_printed_not_echoed(tmp_path):
    """dash's echo expands the backslash escapes a repr() puts in the value, so a knob
    carrying a tab would print as several lines with the escape undone."""
    import re

    text = (REPO / "deploy" / "upgrade.sh").read_text()
    offenders = []
    for number, line in enumerate(text.splitlines(), 1):
        if "$verdict" not in line and "$rverdict" not in line:
            continue
        # the printing command anywhere on the line, not only at its start: one of the
        # three sits inside an `if ...; then ...; fi`, which a start-of-line check misses
        if re.search(r"(^|[;&|]|\bthen\b)\s*echo\s", line):
            offenders.append(f"{number}: {line.strip()}")
    assert offenders == [], offenders
    assert text.count("printf '%s\\n' \"upgrade.sh:") >= 3, "a verdict line stopped using printf"


def test_the_egress_gate_refuses_a_malformed_lock_params(tmp_path):
    # the pool-manager refuses a malformed AUTHENTICODE_LOCK_PARAMS at start (before the orphan recovery): the gate must too
    env = write_env(tmp_path, AUTHENTICODE_EXIT="none", AUTHENTICODE_LOCK_PARAMS="ture")
    v = run_upgrade_gate("egress", env)
    assert "AUTHENTICODE_LOCK_PARAMS" in v and v != "ok"
