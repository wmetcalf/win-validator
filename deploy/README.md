# win-validator deployment — the privilege split

Two tiers, separated so the thing handling untrusted HTTP never holds `root`/libvirt/iptables:

```
   client ──HTTP──> [ ingress container ]                         [ host pool-manager ]
                     unprivileged, read-only                       libvirt + iptables + the VM pool
                     no libvirt / no socket                        (egress + tunnel kill-switch — once AUTHENTICODE_EXIT is set)
                          │                                                 ▲
                          │   Postgres JobStore (queue/meta/results)        │ claim_next()
                          └────────────  +  shared job_root dir  ───────────┘
                                          (<id>/input/<file>)
```

The **boundary** is blastbox's own `JobStore` (`BLASTBOX_DATABASE_URL`) + a shared `WINVAL_JOB_ROOT`
directory. The ingress spools the upload + queues a job; the pool-manager claims it, validates it in
a warm VM worker (the sandbox), and writes the verdict back as the job's `result_summary`. A
web-stack compromise of the ingress is contained to an unprivileged container whose only interface
is Postgres + that one directory.

## Bring up

```sh
# the checkout at its canonical path, ROOT-OWNED: the pool-manager runs as root with libvirt and
# iptables, so its interpreter and code must not live in a user-writable tree. The venv needs
# --system-site-packages for the SYSTEM libvirt bindings (libvirt-python is not pip-installable
# without libvirt-dev); prometheus_client is a blastbox import outside its base deps.
sudo git clone https://github.com/wmetcalf/win-validator /opt/win-validator
sudo python3 -m venv --system-site-packages /opt/win-validator/.venv
sudo /opt/win-validator/.venv/bin/pip install "blastbox>=0.1.33" "psycopg[binary,pool]" redis fastapi "uvicorn[standard]" python-multipart prometheus_client
cd /opt/win-validator

# shared job_root (writable by the ingress container's uid + readable by the host pool-manager)
sudo mkdir -p /var/lib/winval/jobs && sudo chown 10001:10001 /var/lib/winval/jobs
# (the pool-manager creates its OWN scratch tree, WINVAL_WORK_ROOT=/var/lib/winval/work, 0700 root, at start:
#  samples are copied and validated there, never inside the ingress-owned job_root. The manager also relies
#  on the host's fs.protected_hardlinks=1 (the kernel default) so the ingress cannot hard-link a root-owned
#  file into a job's input/; the manager refuses any spooled input whose link count is not 1 regardless)

# secrets, root-only: the env file BOTH units read, and the golden's ssh key
sudo git clone https://github.com/wmetcalf/myatg /opt/myatg   # the in-guest agent's sources (MYATG_SRC), compiled by golden_build.py
sudo install -d -m 0700 /etc/winval
sudo test -e /etc/winval/winval.env || sudo install -m 0600 deploy/winval.env.example /etc/winval/winval.env   # first time only (the test runs as root: the dir is 0700); then edit
# the golden's ssh key is the PACKER BUILD's key: the image authorises exactly one public key, the
# throwaway keys/build_key(.pub) golden-packer/build.sh generated (Autounattend writes it with
# Set-Content: the whole authorised list). Build the image first, in its own checkout, per
# golden-packer/README.md; PACKER is that checkout (output/ and keys/ are gitignored, so the
# /opt/win-validator clone never has them).
PACKER=~/win-golden-packer/golden-packer   # the golden-packer DIRECTORY inside that checkout (build.sh, keys/, output/ live there)
sudo install -m 0600 "$PACKER/keys/build_key" /etc/winval/win_golden        # AUTHENTICODE_SSH_KEY: the only key the image accepts

# unprivileged tiers: ingress + Postgres. The password is minted ONCE and written into the env
# file the pool-manager reads — it is baked into the Postgres volume at first start and cannot
# be recovered later. Re-running this block is safe: an existing password is kept (a fresh one
# would lock both tiers out of the `pgdata` volume that holds the first). To start over:
# `sudo docker compose --env-file /etc/winval/compose.env -f deploy/docker-compose.yml down -v`
# and delete the BLASTBOX_DATABASE_URL line from winval.env.
# compose.env carries the SAME password in the two forms compose needs, DERIVED from winval.env's URL every time it
# disagrees (missing, written before the encoded form existed, or the URL was edited). --mint writes a fresh random
# password into winval.env when it has none: greenfield only (deploy/upgrade.sh runs the same script WITHOUT it)
sudo sh deploy/compose-env.sh --mint
# compose.env also takes WINVAL_UPLOAD_MB (the ingress upload cap, default 1024 — set AUTHENTICODE_MAX_UPLOAD_MB in
# winval.env alike) and WINVAL_SPOOL_SIZE (the ingress spool tmpfs, default 2g, keep it >= 2x the cap); add them by hand
# every compose invocation from now on carries the env file, or a later `up` would recreate the
# ingress with the 'winval' fallback password against a volume that holds the real one
sudo docker compose --env-file /etc/winval/compose.env -f deploy/docker-compose.yml up --build -d

# the smoke gates (boot/recycle for the pool, benign==Valid for the rotation) validate a benign
# SIGNED sample — any small Microsoft-signed binary. winval.env.example points both gates at
# this path. Set the two variables in winval.env ONLY once the sample is in place: a set path that
# does not exist fails the pool-manager at start, by name. Without them, readiness is port-open only.
sudo install -d /var/lib/winval/samples && sudo install -m 0644 /path/to/whoami.exe /var/lib/winval/samples/whoami.exe

# privileged tier on the host (libvirt): install the unit, then bake the FIRST golden, then start
sudo cp deploy/winval-pool-manager.service /etc/systemd/system/
sudo systemctl daemon-reload
# the golden the pool boots from does not exist yet: the pool-manager refuses to start with neither a
# golden (GOLDEN_BASE_DISK) nor a master (GOLDEN_MASTER) on disk. Install the packer's output
# (golden-packer/README.md: output/winserver2025-core.qcow2) as GOLDEN_MASTER — the frozen master the
# weekly rebake also returns to every GOLDEN_MAX_CHAIN cycles — then bake the golden from it once:
# build -> gate (the benign sample validates) -> promote; ~30-60 min. It logs "NOT in service"
# because the pool is not running yet — the next line starts it.
sudo install -m 0644 "$PACKER/output/winserver2025-core.qcow2" /var/lib/libvirt/images/winserver2025-core.qcow2   # the packer checkout's output (PACKER, set above)
sudo /opt/win-validator/.venv/bin/python golden_build.py build-and-promote   # from GOLDEN_MASTER (or GOLDEN_BUILD_BASE / an explicit path)
sudo systemctl enable --now winval-pool-manager
```

The unit materialises the RAM base (`AUTHENTICODE_GOLDEN_BASE`, on `/dev/shm`) in
`ExecStartPre` when it is MISSING, or present but not owned by the unit (a worker base configured as the disk golden itself is left
as it is: it is its own source) — `/dev/shm` empties on reboot, so a rebooted host comes
back on its own (an 18 GB copy takes ~20–30 s; the unit's start budget is 55 min: up to 30 min behind a rotation's lock plus the copy on a slow store). Fast
failures — Postgres not up yet, a bad `winval.env` — are retried every 30 s for eight starts, then the
unit latches `failed`: fix the cause and `sudo systemctl reset-failed winval-pool-manager && sudo
systemctl start winval-pool-manager`. A present base owned by the unit is never touched; one owned by anyone else
(libvirt's DAC driver leaves the shared base owned by the qemu user, and /dev/shm is world-writable) is discarded
and materialised afresh — only once a source is known to exist, so a restart never destroys the only golden in service. The
source is `GOLDEN_BASE_DISK`, the on-disk twin `golden_rotate.rotate()` promotes into, so a reboot
never reverts a rotation; `GOLDEN_MASTER` (the frozen packer image) is used only before any
golden has been promoted. The copy is atomic and size-checked, so an interrupted copy never
becomes the base, and it is symlink-safe on world-writable `/dev/shm` (mktemp + `mv -T`; a
planted symlink or directory at the base path is refused). `rotate()` publishes the same way
(mktemp temporaries, `mv -T`, the same refusal), checks every copy — the backup included — before
publishing a golden, and a failed build leaves no candidate behind. The RAM base has ONE name,
`AUTHENTICODE_GOLDEN_BASE`, read by the pool, both units and the rotator.

UI + API at <http://localhost:8099/>.

## Upgrading an existing deployment

The bring-up above is greenfield: its `git clone` fails on a deployed host and its unit copies re-install what
is already there. Upgrade in place instead — and read the list below before the first restart, because the
preserved `/etc/winval/winval.env` changes meaning under this version:

`deploy/upgrade.sh` is a script, not a paste: its `set -e` and refusals never touch your shell, and every
refusal happens before the deployed tree moves (the units and the weekly rotation run from it). It refuses a
dirty tree, a `compose.env` that cannot be derived (`compose-env.sh --check`, nothing written), an argument that
is not a branch on origin (tags are not supported), a detached HEAD on no origin branch (the checkout would
orphan it), and a local branch carrying commits that are not on origin (they fast-forward "successfully" and
would otherwise build the untrusted-facing ingress and install root units from an unreviewed tree). It never
mints a database password. It upgrades BOTH tiers — the ingress container is built from this checkout
(`Dockerfile.ingress` copies `winval_blastbox/`), and this version's ingress changes are the security ones (the
request-body cap, the bounded `/cert` scan) — and re-derives `compose.env`, which now needs a variable a file
written before this version does not carry.

```bash
cd /opt/win-validator && sudo git fetch --prune origin
sudo git show origin/<branch>:deploy/upgrade.sh | sudo sh -s -- <branch>             # code, venv, compose.env; stops before any restart and says what --restart does
sudo git show origin/<branch>:deploy/upgrade.sh | sudo sh -s -- <branch> --restart   # rebuilds the ingress, installs the three unit files + daemon-reload, restarts the pool-manager
```

The script is read from origin rather than from the checkout because a host still on a version without it (it
arrived with this one) has no `deploy/upgrade.sh` to run; once upgraded, `sudo sh deploy/upgrade.sh <branch>`
is the same thing.

The `--restart` step drops in-flight uploads and fails every RUNNING job as *orphaned by a pool-manager restart*
(its sample removed; clients resubmit): drain first if that matters. The pool-manager's first start may wait up
to 30 min behind a rotation's lock, then re-copy the RAM base (below).

- **The pool-manager refuses to start without `AUTHENTICODE_EXIT`** (design change #7): an env file that never named an
  exit driver must gain one (`direct` is the minimum) or the explicit `AUTHENTICODE_EXIT=none`. `upgrade.sh --restart` refuses
  BEFORE the tree moves when the line is missing; without `--restart` it warns. With more than one worker the start also needs
  `AUTHENTICODE_BLOCK_INTERNAL=1` (or `AUTHENTICODE_EGRESS_PORTS`), or the pool-manager refuses by name (design change #8);
  `upgrade.sh --restart` refuses before the move for that too. The unit itself loads `br_netfilter` and sets
  `net.bridge.bridge-nf-call-iptables=1` at every start; a host that cannot load the module is refused by name with the remedy — by
  `upgrade.sh --restart` before the move and by the rotation preflight before a promotion (both probe with a `modprobe` dry run), and by
  the pool-manager itself at start. The next golden bake scopes the agent-port firewall rule to the
  pool-manager's address; a bake refuses if it cannot learn that address (`AUTHENTICODE_AGENT_CALLER` names it by hand).
- **`GOLDEN_KEEP_N=0` now means keep NO rollback backups** (it used to mean prune nothing). The first
  rotation preflight after the upgrade prunes every backup. Set it to the number you want kept (default 5).
- **Backup retention orders by modification time**, not by name: backups made before this version are stamped in local time, the new ones in UTC, and in a zone ahead of UTC the old names sort lexically newer than a fresh backup for hours. The mtime is the promotion time on every backup, so both populations rank alike.
- **The pool-manager unit now owns the RAM base at every start** (`ExecStartPre`): a `/dev/shm` base not owned
  by the unit's uid (libvirt's DAC driver usually leaves it owned by the qemu user) is discarded and re-copied
  from `GOLDEN_BASE_DISK` — up to 30 min behind a rotation's lock plus the copy, inside `TimeoutStartSec=55min`.
  With no disk twin the start refuses rather than replace the only golden with the agent-less master: promote a
  golden to `GOLDEN_BASE_DISK` first. `upgrade.sh --restart` re-installs all three unit files (both services and
  the timer) and reloads systemd: the code moved to `/opt/win-validator`, and the pool-manager unit must run as
  root (its pre-step owns the lock and the RAM base).
- **A preserved env file can refuse the pool-manager at start where it used to run**: `AUTHENTICODE_WARM_DIR` or
  `AUTHENTICODE_SMOKE_SAMPLE` set to a path that does not exist (the old example pointed at a home directory the
  `/opt` move invalidates) fails the start by name; `AUTHENTICODE_EGRESS_PORTS` present but blank is now a CLOSED
  allowlist; every `BLASTBOX_*` value must parse. Diff your env file against `deploy/winval.env.example`.
- **`WINVAL_JOB_RETENTION_DAYS` (default 7)** sweeps terminal and rowless job directories under `WINVAL_JOB_ROOT`
  from the first start: an existing job root loses history older than that unless you raise it first.
- Nothing else in the env file is reinterpreted; every new knob has a default.

## Why each piece is shaped this way

- **ingress** runs `read_only`, `cap_drop: ALL`, `no-new-privileges`, as uid 10001, with only the
  `job_root` volume + a tmpfs `/tmp` writable. It imports `winval_blastbox.ingress` only — the lazy
  package `__init__` keeps the libvirt/engine modules out of its import graph.
- **pool-manager** runs on the host (systemd) because it drives `virsh` + `iptables`. It is never
  bound to a client-facing socket; its inputs are the Postgres queue + the spooled files. Restart it
  to pick up a rebaked golden.
- **Postgres** (not sqlite) is the cross-boundary store — a real broker beats a sqlite file shared
  over a container/host bind-mount. Redis also works as the shared store when BOTH tiers point at it — which the shipped compose does not: its ingress is wired to its own Postgres service, so with this compose the pool-manager's `BLASTBOX_DATABASE_URL` must be that Postgres.
- **VPN/tor egress + the tunnel kill-switch** live with the pool-manager (host iptables), so a
  worker still fails closed on a tunnel drop regardless of the ingress — once `AUTHENTICODE_EXIT`
  names an exit driver. The pool-manager REFUSES to start with it unset; `AUTHENTICODE_EXIT=none` is the
  explicit opt-out that gives workers the libvirt network's plain NAT on purpose. Set a driver before exposing the ingress.
  Without an exit driver nothing governs a worker's traffic to the host either: the ingress publishes 8099 on
  all interfaces with no authentication, so a worker can read `/jobs` or fill the spool (Postgres is bound to
  127.0.0.1). With `AUTHENTICODE_EXIT` set, blastbox installs a per-worker INPUT chain on the host that drops
  host-destined traffic except established, DHCP and gated DNS, and `AUTHENTICODE_BLOCK_INTERNAL=1` drops the
  docker-published 8099 in FORWARD. Worker-to-worker traffic on the bridge is switched, not routed: it meets the
  FORWARD rules only with `net.bridge.bridge-nf-call-iptables=1` on the host (`modprobe br_netfilter`), and is
  dropped only by `AUTHENTICODE_BLOCK_INTERNAL=1` or a port allowlist. With more than one worker the pool-manager
  refuses to start unless both are in place (block_internal or a port allowlist, AND the sysctl at 1). The golden's
  own rule for the agent port admits the pool-manager's address alone (learned from the libvirt network at bake
  time; `AUTHENTICODE_AGENT_CALLER` overrides it, `AUTHENTICODE_LIBVIRT_NETWORK` names another network) — a golden
  baked before this version opens the port to any source until it is rebaked.
- **`/cert/{tbs}` on the ingress** searches the newest 2000 scans of its store and says so in the answer's
  `scanned` / `truncated` fields (the orchestrator's `/cert` has no such bound).

## Rolling golden (freshness re-bake + rollback backups)

`golden_rotate.py` keeps the golden FRESH and keeps the last N as rollback backups. It is NOT a
temporal-trust ladder (workers sync real time + do live CRL on restore, so they always validate
against *now*); the point is fail-safe rebakes:

```
build_candidate()  private copy of the promoted golden --overlay clone--> refresh trust state (myatg --refresh: disallowed
                   kill-list + CRL cache + roots/CTL) --> flatten --> candidate.qcow2
                   EVERY GOLDEN_MAX_CHAIN cycles (and always with GOLDEN_REBAKE_FROM=master) the cycle is instead the FULL
                   golden_build bake from the packer master: it stages and COMPILES the agent from MYATG_SRC (/opt/myatg —
                   whatever that checkout holds ships to every worker), installs the task and ACLs, refreshes, gates, promotes
validate_golden()  boot a worker off the candidate --> gate: benign==Valid AND revoked==Revoked
rotate()           backup current golden (keep last N) --> promote candidate --> restart pool-manager
                   (EVERY pool-manager start, this one included, fails each authenticode row still RUNNING
                   as "orphaned by a pool-manager restart" and deletes its spooled sample: a validation in
                   flight at the restart is lost and the client resubmits; the ingress answers the row's error)

```

Run both scripts AS ROOT and with the venv's interpreter (`sudo /opt/win-validator/.venv/bin/python
golden_rotate.py …` — the system python3 has no blastbox). They read `/etc/winval/winval.env` themselves
(`WINVAL_ENV_FILE` to point elsewhere) for any GOLDEN_*/AUTHENTICODE_* value not already in the
environment, so a hand-run rotation uses the same paths as the timer's even though sudo strips exported
variables. The rotation lock lives in /run and every publish
step is privileged — a preflight refuses before the build otherwise. Promotion keeps a full
temporary copy beside EACH base until the rename, so size `/dev/shm` for the golden plus one
more image plus the worker overlays; the preflight checks that space too. A rotation that could
not start (lock held, no space, a failed backup) keeps its gated candidate and logs the exact retry command;
stale candidates are reclaimed after GOLDEN_CANDIDATE_KEEP_DAYS (7).


A candidate is promoted **only if it passes the gate**; a broken/regressed bake (the WU-wedge /
corruption scenarios) is rejected and the current golden is kept. Schedule it weekly:

```sh
sudo cp deploy/winval-golden-rotate.service deploy/winval-golden-rotate.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now winval-golden-rotate.timer
```

Set `GOLDEN_REVOKED_SAMPLE` to a known-revoked file so the gate also catches a disallowed-list /
revocation regression, not just a dead worker.

