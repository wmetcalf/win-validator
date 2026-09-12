"""AUTHENTICODE_GOLDEN_BASE is read by four separate things, and they must agree.

The RAM base is named by one knob and read by the worker pool's spec, the rotation, the
pool-manager unit's pre-start (POSIX sh and sed, in the C locale) and the pre-upgrade
gate. Whenever two of them disagreed about what an operator had typed, the result was a
unit that refused to start a posture the rotation had just promoted to, or an upgrade
that landed green and broke the next rotation.

The rule all four implement: trim SPACE and TAB at both ends -- which is all the unit's
sed can reach -- treat what is left as the path, fall back to /dev/shm/golden-base.qcow2
when it is empty, and refuse any byte outside printable ASCII by name. A newline, a
vertical tab or a pasted no-break space is therefore refused rather than quietly trimmed
by the three readers that could trim it and kept by the one that could not.

Each case below is asserted against all four readers.
"""
from __future__ import annotations

import pytest

from conftest import module_global, run_unit_prestart, run_upgrade_gate

DEFAULT = "/dev/shm/golden-base.qcow2"
REFUSED = object()

# raw value an operator can put in winval.env -> the path every reader must land on,
# or REFUSED when every reader must refuse it by name.
CASES = [
    pytest.param("/dev/shm/golden-base.qcow2", DEFAULT, id="plain"),
    pytest.param("/dev/shm/other.qcow2", "/dev/shm/other.qcow2", id="non-default-path"),
    pytest.param("", DEFAULT, id="empty-is-the-default"),
    pytest.param("   ", DEFAULT, id="spaces-only-is-the-default"),
    pytest.param("\t\t", DEFAULT, id="tabs-only-is-the-default"),
    pytest.param("  /dev/shm/other.qcow2  ", "/dev/shm/other.qcow2", id="spaces-trimmed"),
    pytest.param("\t/dev/shm/other.qcow2\t", "/dev/shm/other.qcow2", id="tabs-trimmed"),
    pytest.param("/dev/shm/a b.qcow2", "/dev/shm/a b.qcow2", id="inner-space-kept"),
    pytest.param(" /dev/shm/other.qcow2", REFUSED, id="leading-no-break-space"),
    pytest.param("/dev/shm/gölden.qcow2", REFUSED, id="non-ascii-letter"),
    pytest.param("/dev/shm/a\tb.qcow2", REFUSED, id="inner-tab"),
    pytest.param("/dev/shm/a\x7fb.qcow2", REFUSED, id="delete-byte"),
    pytest.param("\n/dev/shm/other.qcow2", REFUSED, id="leading-newline"),
    pytest.param("/dev/shm/other.qcow2\n", REFUSED, id="trailing-newline"),
    pytest.param("\x0b/dev/shm/other.qcow2", REFUSED, id="leading-vertical-tab"),
    pytest.param("/dev/shm/other.qcow2\x0b", REFUSED, id="trailing-vertical-tab"),
]


@pytest.mark.parametrize("raw,expected", CASES)
def test_worker_pool_spec(raw, expected, monkeypatch):
    """The spec the pool-manager starts workers with (winval_blastbox.vm_pool)."""
    import winval_blastbox.vm_pool as vm_pool

    monkeypatch.setenv("AUTHENTICODE_GOLDEN_BASE", raw)
    if expected is REFUSED:
        with pytest.raises(RuntimeError, match="printable ASCII"):
            vm_pool.golden_base()
    else:
        assert vm_pool.golden_base() == expected


@pytest.mark.parametrize("raw,expected", CASES)
def test_rotation(raw, expected):
    """The rotation's own read, which decides what a promotion publishes to.

    Read in a subprocess because golden_rotate resolves this knob at import; the
    printable-ASCII refusal itself lives in rotation_preflight, so the test applies that
    same rule to the value the module kept.
    """
    kept = module_global("GOLDEN_BASE", {"AUTHENTICODE_GOLDEN_BASE": raw})
    printable = all(32 <= ord(c) < 127 for c in kept)
    if expected is REFUSED:
        assert not printable, f"the rotation kept {kept!r}, which its preflight would accept"
    else:
        assert printable and kept == expected


@pytest.mark.parametrize("raw,expected", CASES)
def test_unit_prestart(raw, expected, tmp_path):
    """The pool-manager unit's pre-start, which materialises the RAM base at boot."""
    rc, out = run_unit_prestart(tmp_path, raw, disk_twin="DISK-TWIN", master="MASTER")
    if expected is REFUSED:
        assert rc == 1, f"the unit accepted {raw!r}: {out[-200:]}"
        assert "printable ASCII" in out, out[-200:]
    else:
        assert rc == 0, out[-300:]
        assert out.count("printable ASCII") == 0


@pytest.mark.parametrize("raw,expected", CASES)
def test_upgrade_gate(raw, expected, tmp_path):
    """The pre-upgrade gate, which must refuse before the tree moves what the
    pool-manager would refuse at its next start."""
    env_file = tmp_path / "winval.env"
    env_file.write_text(f'AUTHENTICODE_EXIT=none\nAUTHENTICODE_GOLDEN_BASE="{raw}"\n')
    verdict = run_upgrade_gate("egress", env_file)
    if expected is REFUSED:
        assert verdict.startswith("malformed:"), verdict
        assert "AUTHENTICODE_GOLDEN_BASE" in verdict, verdict
    else:
        assert verdict == "ok", verdict


def test_the_four_readers_are_the_only_ones():
    """A fifth reader of this knob would be a fifth chance to disagree.

    If this fails, the new reader needs the same trim-and-refuse rule and its own case
    in this file -- not a quiet fourth opinion about what the operator typed.
    """
    from pathlib import Path

    from conftest import REPO

    readers = set()
    for path in list(REPO.glob("*.py")) + list((REPO / "winval_blastbox").glob("*.py")):
        if "AUTHENTICODE_GOLDEN_BASE" in path.read_text():
            readers.add(path.relative_to(REPO).as_posix())
    for path in (REPO / "deploy").iterdir():
        if path.is_file() and "AUTHENTICODE_GOLDEN_BASE" in path.read_text():
            readers.add(path.relative_to(REPO).as_posix())
    code_readers = {r for r in readers if not r.endswith((".md", ".example"))}
    assert code_readers == {
        "golden_rotate.py",
        "winval_blastbox/vm_pool.py",
        "deploy/winval-pool-manager.service",
        "deploy/winval-golden-rotate.service",
        "deploy/upgrade.sh",
    }, sorted(code_readers)
