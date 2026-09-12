"""The backup of the live golden, taken in the moment before a promotion publishes.

This copy is what a rollback restores from, what retention keeps as a known-good golden,
and what the pool-manager copies into RAM after a reboot. A truncated one would satisfy
all three, so it is copied under a name no reader matches and renamed only once its size
has been checked -- and the rename uses `mv -T`, so a directory or symlink planted at the
destination fails the rename rather than swallowing the copy somewhere nothing sweeps.
"""
from __future__ import annotations

import os
import subprocess

import pytest

from conftest import Completed


@pytest.fixture
def cp_control(gr, golden_tree, monkeypatch):
    """Run the real file commands, but let a test cut the copy short or fail the unlink."""
    state = {"cp": "full", "rm": "ok"}

    def run(argv, timeout=120):
        argv = [str(a) for a in argv if a != "sudo"]
        if argv[0] == "cp":
            src, dst = argv[-2], argv[-1]
            data = open(src, "rb").read()
            with open(dst, "wb") as fh:
                fh.write(data if state["cp"] == "full" else data[: len(data) // 2])
            return Completed(0 if state["cp"] == "full" else 1)
        if argv[0] == "rm" and state["rm"] == "fail":
            return Completed(1)
        if argv[0] in ("rm", "mv", "touch", "mkdir", "chmod"):
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return Completed(proc.returncode, proc.stdout, proc.stderr)
        return Completed(0)

    monkeypatch.setattr(gr, "_run", run)
    return state


def names(gr):
    return sorted(p.name for p in gr.BACKUP_DIR.iterdir())


def test_a_whole_copy_lands_under_the_backup_name(gr, cp_control):
    taken = gr._backup_current()
    assert taken and os.path.isfile(taken)
    assert os.path.getsize(taken) == os.path.getsize(gr.GOLDEN_BASE_DISK)
    assert not any(n.endswith(".part") for n in names(gr))


def test_a_copy_cut_short_publishes_nothing(gr, cp_control):
    cp_control["cp"] = "short"
    with pytest.raises(gr.NothingPublished, match="backup of the current golden"):
        gr._backup_current()
    assert names(gr) == [], "a truncated copy was left where a reader could find it"


def test_a_truncated_copy_whose_cleanup_fails_is_not_a_backup(gr, cp_control):
    """The one that matters: if the unlink after a short copy also fails, whatever is
    left must not be something the rollback set, retention or the unit can mistake for a
    backup -- and the next rotation's sweep must reclaim it."""
    cp_control["cp"] = "short"
    cp_control["rm"] = "fail"
    with pytest.raises(gr.NothingPublished):
        gr._backup_current()
    left = names(gr)
    assert len(left) == 1 and left[0].endswith(".qcow2.part"), left
    assert not gr._BACKUP_NAME.match(left[0])
    assert list(gr.BACKUP_DIR.glob("golden-base.*.qcow2")) == []
    cp_control["rm"] = "ok"
    gr._sweep_own_temps()
    assert names(gr) == []


def test_no_space_is_refused_before_the_copy_starts(gr, cp_control, monkeypatch):
    """The preflight sized this from an estimate; by now the real size is known."""
    copied = []
    real_run = gr._run
    monkeypatch.setattr(gr, "_run", lambda a, t=120: (copied.append(a[:2]), real_run(a, t))[1])
    monkeypatch.setattr(gr.shutil, "disk_usage", lambda p: type("U", (), {"free": 10})())
    with pytest.raises(gr.NothingPublished, match="not enough space"):
        gr._backup_current()
    assert not any("cp" in c for c in copied)


def test_a_directory_at_the_backup_name_swallows_nothing(gr, cp_control, monkeypatch, tmp_path):
    """`mv` without -T moves the source INSIDE a directory at the destination, where no
    sweep would ever find a golden-sized copy."""
    monkeypatch.setattr(gr.time, "strftime", lambda *a: "20260101-000000")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (gr.BACKUP_DIR / "golden-base.20260101-000000.qcow2").symlink_to(elsewhere)
    try:
        gr._backup_current()
    except gr.NothingPublished:
        pass
    assert list(elsewhere.iterdir()) == [], "the copy was moved inside the planted symlink"
