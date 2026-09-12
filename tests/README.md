# Tests

What these pin is the behaviour a mistake here has already cost at least once: a knob two
components read differently, a refusal that arrived after the thing it was meant to
prevent, an image deleted out from under the command that was about to promote it.

They run the real module code against a temporary tree. Nothing here needs root, a
network, libvirt, qemu, docker or a database — the privileged commands are executed
unprivileged in `tests/conftest.py`, and the handful of host facts (this process's euid,
whether a pid belongs to a builder) are stubbed.

```
pip install "blastbox>=0.1.33" pytest
pytest
```

`tests/conftest.py` holds the fixtures. Two are worth knowing about:

- `golden_tree` points `golden_rotate`'s globals at a temporary images store and restores
  them afterwards, for anything the module decides when it is CALLED.
- `module_global` imports a module in a fresh interpreter under a given environment and
  hands back what it computed, for anything decided when it is IMPORTED — which is every
  knob read into a module global, and therefore untestable any other way in-process.

The shell is tested the same way rather than reimplemented: `unit_prestart_body` lifts
the pool-manager unit's pre-start out of the committed unit file (undoing systemd's `%%`
and `$$` escapes exactly as systemd does), and `run_upgrade_gate` sources the env-file
helper out of `deploy/upgrade.sh`. A copy of either in a test would be free to disagree
with what ships.

## Adding to them

A test earns its place by failing when the fix it describes is undone. Before adding
one, revert the change it covers and watch it go red; a test that passes either way is
worse than none, because it reads like coverage.

## What these do not cover

Worth knowing before trusting a green run, because the gap is large and uneven. The
suite was written around the invariants this branch established, not around the branch's
whole surface, and a reader who assumes otherwise will be wrong in a specific direction.

Reached: the rotation's preflight, retry and backup paths; the worker spec's reading of
the knobs; the refusal that keeps workers off each other's network; the unit's pre-start;
and the env-file half of the upgrade gate.

Not reached at all: `golden_build.py`, `winval_blastbox/ingress.py`,
`winval_blastbox/orchestrator.py`, `winval_blastbox/body_cap.py`, and every line of
`deploy/compose-env.sh`. Barely reached: `winval_blastbox/pool_manager.py`, where only
the egress refusal runs — the claim loop, the job sweep and the kernel-module probe do
not. Of `golden_rotate.py` roughly two functions in five are ever entered; the promotion
itself, the build, the gate boot and the pool restart are not among them, because each
needs libvirt, qemu or systemd.

So a green run means the behaviours listed above still hold. It does not mean the
branch works. Nothing here starts a worker, boots an image or promotes a golden.
