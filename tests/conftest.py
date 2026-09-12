"""Shared fixtures for the win-validator suite.

No test in this directory needs root, a network, libvirt, qemu, docker or a database.
Each one runs the REAL module code against a temporary tree, with the privileged
commands (`sudo cp`, `sudo mv`, `sudo touch`, ...) executed unprivileged and the
handful of host facts (this process's euid, whether a pid is a builder) stubbed.

Two kinds of behaviour need two kinds of fixture:

* Anything the modules decide at CALL time takes `golden_tree`, which points the
  module's globals at a temporary tree and restores them afterwards.
* Anything decided at IMPORT time -- every knob read into a module global while the
  module is first executed -- can only be exercised in a fresh interpreter, so those
  tests use `module_global`, which imports the module under a given environment in a
  subprocess and hands back the value it computed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

# Knobs the modules read. A developer's own environment must never change a verdict,
# and /etc/winval/winval.env on a real host must never be read by a test.
_KNOB_PREFIXES = ("AUTHENTICODE_", "GOLDEN_", "WINVAL_", "BLASTBOX_")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Every knob unset and no env file, for every test in this directory."""
    for key in list(os.environ):
        if key.startswith(_KNOB_PREFIXES):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("WINVAL_ENV_FILE", "/nonexistent")


@pytest.fixture
def gr(monkeypatch):
    """golden_rotate with its module globals restored after the test.

    The module reads its knobs into globals at import, and these tests deliberately
    re-point those globals at a temporary tree; without the restore the next test in
    the same interpreter would inherit a deleted directory.
    """
    import golden_rotate

    saved = dict(vars(golden_rotate))
    try:
        yield golden_rotate
    finally:
        for name, value in saved.items():
            setattr(golden_rotate, name, value)
        for name in set(vars(golden_rotate)) - set(saved):
            delattr(golden_rotate, name)


class Completed:
    """What golden_rotate._run returns: it never raises, the caller reads returncode."""

    def __init__(self, returncode: int = 0, stdout: str = "", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def unprivileged_run(argv, timeout=120):
    """Stand in for golden_rotate._run: drop the `sudo`, really run the file commands.

    The point of a test here is what the module does with the RESULT of a copy or a
    rename, so the file commands must genuinely happen -- but as this user, in a
    temporary tree. Anything else (virsh, systemctl, qemu-img) answers success without
    running, because no test in this directory asserts on a virtual machine.
    """
    argv = [str(a) for a in argv if a != "sudo"]
    if argv and argv[0] in ("cp", "mv", "rm", "touch", "mkdir", "chmod", "ln", "sh"):
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return Completed(proc.returncode, proc.stdout, proc.stderr)
    return Completed(0)


@pytest.fixture
def golden_tree(gr, monkeypatch, tmp_path):
    """A temporary images store wired into golden_rotate, with the real file commands.

    Returns the tree root. The layout mirrors a host: a disk golden with its chain
    record, a RAM base directory, a backup directory and the off-store chain mirror.
    """
    backups = tmp_path / "backups"
    backups.mkdir()
    mirror_dir = tmp_path / "mirror"
    mirror_dir.mkdir()
    ram = tmp_path / "shm"
    ram.mkdir()

    disk_golden = tmp_path / "golden-base.qcow2"
    disk_golden.write_bytes(b"G" * 4096)
    (tmp_path / "golden-base.qcow2.chain").write_text("1")
    mirror = mirror_dir / "chain"
    mirror.write_text("1")

    monkeypatch.setattr(gr, "_run", unprivileged_run)
    monkeypatch.setattr(gr, "_virsh", lambda *a, **k: Completed(0))
    monkeypatch.setattr(gr, "GOLDEN_BASE_DISK", str(disk_golden))
    monkeypatch.setattr(gr, "GOLDEN_BASE", str(ram / "golden-base.qcow2"))
    monkeypatch.setattr(gr, "BACKUP_DIR", backups)
    monkeypatch.setattr(gr, "ROTATE_LOCK", str(tmp_path / "rotate.lock"))
    monkeypatch.setattr(gr, "CHAIN_MIRROR", str(mirror))
    monkeypatch.setattr(gr, "_mirror_file", lambda: mirror)
    monkeypatch.setattr(gr, "GRAVEYARD", "")
    monkeypatch.setattr(gr, "WARM_DIR", "")
    monkeypatch.setattr(gr, "LEGACY_GOLDEN_BASE", "")
    return tmp_path


@pytest.fixture
def as_root(gr, monkeypatch):
    """Report this process as root: every promoting entry point refuses a non-root run
    first, which would mask the behaviour the test is actually after."""
    monkeypatch.setattr(os, "geteuid", lambda: 0)


def module_global(name: str, env: dict[str, str], module: str = "golden_rotate"):
    """Import `module` in a fresh interpreter under `env` and return repr() of a global.

    Knobs read at import cannot be re-read in this process, so the only honest way to
    test what an operator's winval.env produces is to start a new one.
    """
    code = (
        "import sys; sys.path.insert(0, %r)\n"
        "import %s as m\n"
        "print(repr(getattr(m, %r)))\n" % (str(REPO), module, name)
    )
    full = {k: v for k, v in os.environ.items() if not k.startswith(_KNOB_PREFIXES)}
    full["WINVAL_ENV_FILE"] = "/nonexistent"
    full.update(env)
    proc = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=full, timeout=120
    )
    if proc.returncode != 0:
        raise AssertionError(f"importing {module} failed: {(proc.stdout + proc.stderr)[-400:]}")
    return eval(proc.stdout.strip())  # noqa: S307 - our own repr(), from our own subprocess


def unit_prestart_body() -> str:
    """The pool-manager unit's RAM-base pre-start, as systemd would hand it to /bin/sh.

    Extracted from the committed unit rather than copied, so the test can never drift
    from what is installed: `%%` is systemd's escape for a literal percent and `$$` for
    a literal dollar, and both are undone here exactly as systemd undoes them.
    """
    import re

    unit = (REPO / "deploy" / "winval-pool-manager.service").read_text()
    match = re.search(
        r"^ExecStartPre=/usr/bin/flock -w 1800 \$\{GOLDEN_ROTATE_LOCK\} /bin/sh -c '(.*)'$",
        unit,
        re.M,
    )
    assert match, "the flock pre-start line is not in deploy/winval-pool-manager.service"
    return match.group(1).replace("%%", "%").replace("$$", "$")


def run_unit_prestart(tmp_path, golden_base, *, disk_twin=None, master=None, env=None):
    """Run that pre-start over a temporary images store and report what it did.

    Returns (returncode, combined output). `id` is stubbed to a non-root uid so the
    ownership branch behaves as it does under a real start, where the RAM base found on
    /dev/shm was not written by this unit.
    """
    images = tmp_path / "img"
    images.mkdir(exist_ok=True)
    ram = tmp_path / "shm"
    ram.mkdir(exist_ok=True)
    if disk_twin is not None:
        (images / "golden-base.qcow2").write_text(disk_twin)
    if master is not None:
        (images / "master.qcow2").write_text(master)

    script = tmp_path / "prestart.sh"
    script.write_text("id() { echo 99999; }\n" + unit_prestart_body() + "\n")

    full = {k: v for k, v in os.environ.items() if not k.startswith(_KNOB_PREFIXES)}
    full.update(
        LC_ALL="C",
        AUTHENTICODE_GOLDEN_BASE=golden_base,
        GOLDEN_BASE_DISK=str(images / "golden-base.qcow2"),
        GOLDEN_MASTER=str(images / "master.qcow2"),
    )
    full.update(env or {})
    proc = subprocess.run(
        ["/bin/sh", str(script)],
        capture_output=True,
        text=True,
        cwd=str(tmp_path),
        env=full,
        timeout=120,
    )
    return proc.returncode, proc.stdout + proc.stderr


def run_upgrade_gate(mode: str, env_file, extra_env=None):
    """Run deploy/upgrade.sh's env-file helper in one mode and return its single verdict.

    The helper is sourced out of the script itself, so the rules the gate applies are
    the rules that ship: a copy in the test would be free to disagree with them.
    """
    script = (REPO / "deploy" / "upgrade.sh").read_text().splitlines()
    start = next(i for i, line in enumerate(script) if line.startswith("envfile_py()"))
    end = next(i for i, line in enumerate(script) if i > start and line == "}")
    body = "\n".join(script[start : end + 1])
    full = {k: v for k, v in os.environ.items() if not k.startswith(_KNOB_PREFIXES)}
    full.update(extra_env or {})
    proc = subprocess.run(
        ["/bin/sh", "-c", f"{body}\nenvfile_py {mode} '{env_file}'"],
        capture_output=True,
        text=True,
        env=full,
        timeout=120,
    )
    return (proc.stdout + proc.stderr).strip()
