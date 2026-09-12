"""The `rotate <candidate>` retry: what it holds, what it re-dates, and in what order.

When a rotation cannot publish, it keeps the validated candidate and prints the exact
command to retry with. Everything here protects that promise.

The hazard the hold exists for: rotation_preflight releases the rotation lock before
rotate() takes it, and a rotation running in that window prunes candidates past their
retention with no knowledge of this retry -- so the image the printed command names can
be deleted between the two halves of the command itself. The retry therefore takes a
build-style hold, valid only while its own process runs, which every prune honours.

The hazard the ORDER exists for: the preflight refuses a forgotten sudo, a stale knob
name and a malformed posture before it waits on the lock. Taking the lock first turned
a forgotten sudo into a traceback and put a knob refusal behind a thirty-minute wait.
"""
from __future__ import annotations

import os
import time

import pytest


@pytest.fixture
def retry(gr, golden_tree, as_root, monkeypatch):
    """A candidate old enough for the age prune, and the retry wired to run here."""
    # A valid posture: no egress policy, on purpose. The preflight mirrors the
    # pool-manager's own start refusals, and an unset exit driver is the first of them --
    # correct, but not what these tests are about.
    monkeypatch.setenv("AUTHENTICODE_EXIT", "none")
    monkeypatch.setattr(gr, "_is_builder", lambda pid: pid == str(os.getpid()))
    monkeypatch.setattr(gr, "PREFLIGHT_LOCK_WAIT_S", 5)
    candidate = gr.BACKUP_DIR / "golden-base.candidate-20260101-000000.qcow2"
    candidate.write_bytes(b"C" * 4096)
    gr.candidate_depth_file(str(candidate)).write_text("2")
    stale = time.time() - (gr.CANDIDATE_KEEP_DAYS + 2) * 86400
    os.utime(candidate, (stale, stale))
    monkeypatch.setattr(gr, "restart_pool", lambda: True)
    return candidate


def holds(gr):
    return sorted(p.name for p in gr.BACKUP_DIR.glob("*.keep*"))


def test_candidate_survives_a_concurrent_prune_in_the_gap(gr, retry, monkeypatch):
    """The whole point: another rotation's keep-less prune must leave the retry's image."""
    seen = {}

    def rotate_while_another_rotation_prunes(_candidate):
        gr._prune_backups()  # the concurrent rotation, which knows nothing of this retry
        seen["survived"] = retry.is_file()
        seen["holds"] = holds(gr)

    monkeypatch.setattr(gr, "rotate", rotate_while_another_rotation_prunes)
    assert gr._main("rotate", ["rotate", str(retry)]) == 0
    assert seen["survived"], "the prune took the candidate the retry was about to promote"
    assert any(h.startswith(retry.name + ".keep.build-") for h in seen["holds"]), seen["holds"]
    assert holds(gr) == [], "the hold outlived the promotion it was taken for"


def test_a_forgotten_sudo_is_named_as_such(gr, retry, monkeypatch, tmp_path):
    """Root is judged first, so the operator is told to use sudo rather than handed a
    traceback from the lock they were never going to be able to open."""
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    unwritable = tmp_path / "nolock"
    unwritable.mkdir()
    unwritable.chmod(0o555)
    monkeypatch.setattr(gr, "ROTATE_LOCK", str(unwritable / "rotate.lock"))
    with pytest.raises(gr.NothingPublished, match="run as root"):
        gr._main("rotate", ["rotate", str(retry)])
    assert holds(gr) == [], "a run that cannot proceed still wrote a sidecar"


def test_a_stale_knob_is_refused_before_any_lock_wait(gr, retry, monkeypatch):
    """The rotator's old GOLDEN_BASE name is a static refusal: it must not sit behind a
    lock another rotation is holding."""
    monkeypatch.setattr(gr, "LEGACY_GOLDEN_BASE", "/dev/shm/under-the-old-name.qcow2")
    import fcntl

    fd = os.open(gr.ROTATE_LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX)
    try:
        started = time.time()
        with pytest.raises(gr.NothingPublished, match="OLD name"):
            gr._main("rotate", ["rotate", str(retry)])
        assert time.time() - started < 2, "the refusal waited on a lock it did not need"
    finally:
        os.close(fd)


def test_a_lost_race_keeps_the_candidate_and_restarts_its_clock(gr, retry, monkeypatch):
    """Losing the lock race is the case the printed retry is FOR: the candidate stays,
    and its retention clock restarts so the winning rotation's own prune spares it."""
    monkeypatch.setattr(gr, "rotate", _lost_race(gr))
    with pytest.raises(gr.NothingPublished, match="another rotation"):
        gr._main("rotate", ["rotate", str(retry)])
    assert time.time() - retry.stat().st_mtime < 60
    assert time.time() - gr.candidate_depth_file(str(retry)).stat().st_mtime < 60
    gr._prune_backups()  # this process's hold is gone by then; only the clock protects it
    assert retry.is_file()
    assert gr.candidate_depth_file(str(retry)).is_file()


def test_a_retained_backup_is_never_re_dated(gr, retry, monkeypatch, golden_tree):
    """A rollback names a retained backup, and retention orders those by modification
    time. Re-dating one pins the oldest and evicts a newer rollback generation."""
    backup = gr.BACKUP_DIR / "golden-base.20260101-000000.qcow2"
    backup.write_bytes(b"B" * 4096)
    ancient = time.time() - 400 * 86400
    os.utime(backup, (ancient, ancient))
    monkeypatch.setattr(gr, "rotate", _lost_race(gr))
    with pytest.raises(gr.NothingPublished):
        gr._main("rotate", ["rotate", str(backup)])
    assert abs(backup.stat().st_mtime - ancient) < 2, "the rollback image was re-dated"


def test_the_clock_restart_resolves_a_symlinked_sidecar(gr, retry, monkeypatch):
    """is_file() and touch both follow symlinks, so the sidecar name is resolved before
    it is judged: otherwise a link aimed at a retained backup re-dates that backup."""
    victim = gr.BACKUP_DIR / "golden-base.20250101-000000.qcow2"
    victim.write_bytes(b"V" * 4096)
    ancient = time.time() - 400 * 86400
    os.utime(victim, (ancient, ancient))
    sidecar = gr.candidate_depth_file(str(retry))
    sidecar.unlink()
    os.symlink(str(victim), str(sidecar))
    monkeypatch.setattr(gr, "rotate", _lost_race(gr))
    with pytest.raises(gr.NothingPublished):
        gr._main("rotate", ["rotate", str(retry)])
    assert abs(victim.stat().st_mtime - ancient) < 2, "a symlink re-dated a retained backup"
    assert time.time() - retry.stat().st_mtime < 60, "the candidate itself was not refreshed"


def test_a_split_state_re_dates_nothing(gr, retry, monkeypatch):
    """After a split state the disk twin IS published and the remedy is the restart the
    message names. Re-creating the depth sidecar the promotion consumed would make a
    later retry record depth 0 and postpone the rebuild from the master."""
    gr.candidate_depth_file(str(retry)).unlink()
    before = retry.stat().st_mtime

    def split(_candidate):
        raise gr.SplitState("the RAM twin failed and the rollback failed", backup="/x")

    monkeypatch.setattr(gr, "rotate", split)
    with pytest.raises(gr.SplitState):
        gr._main("rotate", ["rotate", str(retry)])
    assert abs(retry.stat().st_mtime - before) < 2
    assert not gr.candidate_depth_file(str(retry)).exists()


def test_a_rollback_gets_no_fabricated_depth(gr, retry, monkeypatch):
    """A retained backup carries no depth sidecar. Creating an empty one reads back as
    depth 0 at the next promotion, postponing the rebuild from the master."""
    backup = gr.BACKUP_DIR / "golden-base.20260202-000000.qcow2"
    backup.write_bytes(b"B" * 4096)
    monkeypatch.setattr(gr, "rotate", _lost_race(gr))
    with pytest.raises(gr.NothingPublished):
        gr._main("rotate", ["rotate", str(backup)])
    assert not gr.candidate_depth_file(str(backup)).exists()


def test_a_refusing_preflight_leaves_no_hold(gr, retry, monkeypatch):
    """The caller only learns the sidecar's name from a preflight that RETURNS, so a
    preflight that refuses after writing one has to remove it itself."""
    os.makedirs(gr.GOLDEN_BASE)  # a directory where the RAM base belongs: refused later
    with pytest.raises(gr.NothingPublished, match="symlink or a directory"):
        gr._main("rotate", ["rotate", str(retry)])
    assert holds(gr) == []


def test_a_mistyped_path_prunes_nothing(gr, retry, monkeypatch):
    """The guard for a path that is not a regular file runs before anything is written.

    Ordering is the whole point of it: the preflight takes the lock and prunes surplus
    backups keeping only the candidate it was given, so a typo used to delete the oldest
    rollback backup and then report that no backup had been taken. Asserting only the
    message would keep passing on the duplicate guard further in, after the prune.
    """
    monkeypatch.setattr(gr, "KEEP_N", 1)
    kept = []
    for stamp in ("20250101-000000", "20260101-000000"):
        backup = gr.BACKUP_DIR / f"golden-base.{stamp}.qcow2"
        backup.write_bytes(b"B" * 4096)
        kept.append(backup)
    before = sorted(p.name for p in gr.BACKUP_DIR.iterdir())
    with pytest.raises(gr.NothingPublished, match="not a regular file"):
        gr._main("rotate", ["rotate", str(gr.BACKUP_DIR / "typo.qcow2")])
    assert sorted(p.name for p in gr.BACKUP_DIR.iterdir()) == before, "a typo pruned a backup"
    assert all(b.is_file() for b in kept)
    assert holds(gr) == []


def _lost_race(gr):
    def rotate(_candidate):
        raise gr.NothingPublished(
            "another rotation is in progress (lock held); golden NOT promoted (nothing published)"
        )

    return rotate
