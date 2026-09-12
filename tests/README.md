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
