"""Host-resident runner for the VM-backed ``authenticode`` engine.

blastbox's container dispatcher ``docker run``s a fresh worker per job; that model
doesn't fit a Windows-VM worker (it can't run Python/blastbox). This runner is the
equivalent seam for VM-backed engines: it keeps one long-lived
:class:`~winval_blastbox.engine.AuthenticodeEngine` + its VM pool warm, and drives
each job through :func:`blastbox.worker.harness.run_detonation` **in-process** — the
same function the container harness calls, so the output goes through the identical
seal/confine/validate path and lands as a trusted ``metadata.json``.

``run_detonation`` (not ``harness.main``) is used deliberately: ``main`` runs the
container-only egress-readiness barrier (``/proc/net/route`` polling) which would
block forever host-side. ``run_detonation`` does only detonate + seal.

Usage:
    # one-shot: validate a file, print the sealed envelope
    python -m winval_blastbox.host_runner /path/to/suspect.exe

    # as a library (the P3 orchestrator imports this):
    runner = HostRunner(); runner.warmup()
    env = runner.validate("/path/to/suspect.exe")   # sealed envelope dict
"""
from __future__ import annotations

import json
import signal
import sys
import tempfile
from pathlib import Path

from blastbox.limits import Limits
from blastbox.worker.harness import run_detonation

from .engine import AuthenticodeEngine, shutdown_pool


class HostRunner:
    """Drives the authenticode engine in-process with a warm VM pool."""

    def __init__(self, limits: Limits | None = None) -> None:
        self.engine = AuthenticodeEngine()
        self.limits = limits or Limits.from_env()

    def warmup(self, stop_event=None) -> None:
        """Boot the VM pool up front (otherwise paid on the first validate); `stop_event` ends the wait early."""
        self.engine.warmup(stop_event=stop_event)

    def validate_to_dir(self, input_path: str | Path, output_dir: str | Path) -> dict:
        """Validate ``input_path``, sealing artifacts + metadata.json into ``output_dir``.

        Returns the parsed sealed envelope. ``output_dir`` afterwards holds
        ``metadata.json`` plus the ``authenticode.json`` artifact.
        """
        input_path = Path(input_path)
        output_dir = Path(output_dir)
        envelope = output_dir / "metadata.json"
        if envelope.exists():   # a populated outdir handed back the PREVIOUS run's envelope when this run wrote nothing
            raise FileExistsError(f"{envelope} already exists: validate_to_dir needs an output dir without an envelope")
        rc = run_detonation(
            self.engine,
            input_path=input_path,
            output_dir=output_dir,
            limits=self.limits,
        )
        if rc or not envelope.exists():   # 1 = the envelope could not be written (logged CRITICAL by the harness): there is no verdict to read
            partial = envelope.exists()
            if partial:   # a truncated write (ENOSPC mid-file) leaves a file that is not an envelope and would poison the directory for the next run
                try:
                    envelope.unlink()
                except OSError:
                    pass
            raise RuntimeError(f"run_detonation returned {rc}: no envelope at {envelope}" + (" (a partial file was removed)" if partial else ""))
        return json.loads(envelope.read_text(encoding="utf-8"))

    def validate(self, input_path: str | Path) -> dict:
        """Validate a file in a throwaway output dir; return the sealed envelope."""
        with tempfile.TemporaryDirectory(prefix="authenticode-out-") as out:
            return self.validate_to_dir(input_path, out)

    def shutdown(self) -> None:
        shutdown_pool()


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        print("usage: python -m winval_blastbox.host_runner <file>", file=sys.stderr)
        return 2
    sample = Path(argv[0])
    if not sample.is_file():   # a usage error, said in one line and exit 2: exit 1 is the VM tier's failure (an engine_error envelope)
        print(f"host_runner: {sample} is not a file", file=sys.stderr)
        return 2

    try:
        runner = HostRunner()
    except ValueError as exc:   # Limits.from_env() refuses a bad BLASTBOX_* value loudly: one line, not a traceback
        print(f"host_runner: {exc}", file=sys.stderr)
        return 2

    # Tear the VM pool down cleanly on Ctrl-C / SIGTERM. A signal before a verdict is NOT a success: exit 143
    # (128+SIGTERM), never the 0 that let `host_runner.py sample.exe && ...` carry on with an empty stdout.
    def _term(*_: object) -> None:
        runner.shutdown()
        print("host_runner: stopped by SIGTERM before a verdict", file=sys.stderr)
        sys.exit(143)

    signal.signal(signal.SIGTERM, _term)
    try:
        env = runner.validate(argv[0])
        json.dump(env, sys.stdout, indent=2)
        sys.stdout.write("\n")
        # a sealed engine_error envelope (VM/transport failure) is a FAILURE, as the orchestrator and the
        # pool-manager already treat it: `host_runner.py sample.exe && ...` must not carry on as if validated
        return 1 if env.get("status") == "engine_error" else 0
    finally:
        runner.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
