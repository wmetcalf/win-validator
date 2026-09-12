"""The pool-manager unit's pre-start, which puts the golden into RAM before any worker.

The RAM base lives on /dev/shm and is gone after a reboot, so the unit re-materialises it
at every start, from the disk golden when there is one and from the master otherwise.
Two rules matter more than the copying:

* A base already on /dev/shm that this unit did not write is not trusted. It is replaced
  from the disk twin -- and where there is NO twin, the start refuses rather than
  overwrite what may be the only golden on the box with an agent-less master.
* With nothing to copy from at all, the start refuses by name instead of starting
  workers against a base that is not there.

The body under test is lifted from the committed unit rather than copied, so these
cannot drift apart.
"""
from __future__ import annotations

import pytest


def ram_base(tmp_path):
    return tmp_path / "shm" / "golden-base.qcow2"


def test_a_fresh_boot_copies_the_disk_golden(tmp_path):
    from conftest import run_unit_prestart

    (tmp_path / "shm").mkdir()
    rc, out = run_unit_prestart(
        tmp_path, str(ram_base(tmp_path)), disk_twin="DISK-TWIN", master="MASTER"
    )
    assert rc == 0, out
    assert ram_base(tmp_path).read_text() == "DISK-TWIN"


def test_with_no_disk_golden_it_falls_back_to_the_master(tmp_path):
    from conftest import run_unit_prestart

    (tmp_path / "shm").mkdir()
    rc, out = run_unit_prestart(tmp_path, str(ram_base(tmp_path)), master="MASTER")
    assert rc == 0, out
    assert ram_base(tmp_path).read_text() == "MASTER"


def test_an_unowned_base_is_replaced_from_the_disk_twin(tmp_path):
    """Something else wrote this; the disk golden is the authority."""
    from conftest import run_unit_prestart

    (tmp_path / "shm").mkdir()
    ram_base(tmp_path).write_text("WRITTEN-BY-SOMETHING-ELSE")
    rc, out = run_unit_prestart(
        tmp_path, str(ram_base(tmp_path)), disk_twin="DISK-TWIN", master="MASTER"
    )
    assert rc == 0, out
    assert ram_base(tmp_path).read_text() == "DISK-TWIN"
    assert "not owned by this unit" in out or "owned by uid" in out


def test_an_unowned_base_with_no_twin_is_kept_and_the_start_refuses(tmp_path):
    """The dangerous one. With no disk golden, overwriting from the master would replace
    the only golden on the box with an image that carries no agent -- so the start
    refuses and leaves what is there for the operator to look at."""
    from conftest import run_unit_prestart

    (tmp_path / "shm").mkdir()
    ram_base(tmp_path).write_text("THE-ONLY-GOLDEN")
    rc, out = run_unit_prestart(tmp_path, str(ram_base(tmp_path)), master="MASTER")
    assert rc == 1, out
    assert ram_base(tmp_path).read_text() == "THE-ONLY-GOLDEN", "the only golden was overwritten"
    assert "refusing to replace the only golden" in out


def test_with_nothing_to_copy_from_the_start_refuses_by_name(tmp_path):
    from conftest import run_unit_prestart

    (tmp_path / "shm").mkdir()
    rc, out = run_unit_prestart(tmp_path, str(ram_base(tmp_path)))
    assert rc == 1
    assert "no golden to materialise" in out
    assert not ram_base(tmp_path).exists()


@pytest.mark.parametrize("key", ["ExecStartPre", "ExecStart"])
def test_the_unit_parses(key):
    """systemd's own parser on the shipped units: an unbalanced quote in a pre-start is
    a unit that never starts, and the failure names a line number, not a knob."""
    import shutil
    import subprocess

    from conftest import REPO

    if not shutil.which("systemd-analyze"):
        pytest.skip("systemd-analyze is not installed")
    units = sorted(REPO.glob("deploy/*.service")) + sorted(REPO.glob("deploy/*.timer"))
    assert units, "no units to check"
    proc = subprocess.run(
        ["systemd-analyze", "verify", "--man=no", *[str(u) for u in units]],
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = proc.stdout + proc.stderr
    for complaint in ("Unbalanced quoting", "Invalid ", "Unknown key", "ignoring"):
        assert complaint not in output, output[-400:]
