# win-validator deployment — the privilege split

Two tiers, separated so the thing handling untrusted HTTP never holds `root`/libvirt/iptables:

```
   client ──HTTP──> [ ingress container ]                         [ host pool-manager ]
                     unprivileged, read-only                       libvirt + iptables + the VM pool
                     no libvirt / no socket                        (egress + tunnel kill-switch)
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
#  samples are copied and validated there, never inside the ingress-owned job_root)

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
if ! sudo grep -q '^BLASTBOX_DATABASE_URL=' /etc/winval/winval.env; then
  PW=$(openssl rand -hex 16)
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" | sudo tee -a /etc/winval/winval.env >/dev/null
fi
# compose.env carries the SAME password (the URL in winval.env is the source of truth — also when
# you wrote that line yourself); written 0600 from the first byte, never tee-then-chmod
# compose.env is DERIVED from winval.env's URL every time it disagrees (missing, written before the
# encoded form existed, or the URL was edited). Postgres keeps whatever password its volume was
# initialised with: to change the password for real, `down -v` first, then edit the URL.
WANT_URLENC=$(sudo grep '^BLASTBOX_DATABASE_URL=' /etc/winval/winval.env | tail -1 | cut -d= -f2- | python3 -c 'import sys; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); print(quote(unquote(u.password), safe="")) if u.password else None')
if ! sudo test -f /etc/winval/compose.env || [ "$(sudo sed -n 's/^WINVAL_PG_PASSWORD_URLENC=//p' /etc/winval/compose.env)" != "$WANT_URLENC" ]; then   # a MISSING compose.env is derived too (an undecodable URL compares empty to empty otherwise, and the guidance below never prints)
  # the password is URL-DECODED (a percent-encoded '@' or '#' in the URL is the literal char
  # Postgres must be initialised with; both clients decode it the same way)
  # two forms: the literal password (Postgres initialises with it; written as a JSON/double-quoted
  # string — compose's env file understands \" and \\ inside double quotes — with '$' as '$$',
  # because compose interpolates its env file and a bare '$' would truncate the secret) and the
  # percent-encoded one (the ingress embeds it in a URL)
  PWLINE=$(sudo grep '^BLASTBOX_DATABASE_URL=' /etc/winval/winval.env | tail -1 | cut -d= -f2- | python3 -c 'import sys, json; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); pw = unquote(u.password) if u.scheme.startswith("postgres") and u.username == "winval" and u.password else None; (sys.exit("the password contains control characters, which compose'"'"'s env file cannot carry; choose another") if pw and any(ord(c) < 32 or ord(c) == 127 for c in pw) else None); print("WINVAL_PG_PASSWORD=" + json.dumps(pw, ensure_ascii=False).replace("$", "$$") + "\nWINVAL_PG_PASSWORD_URLENC=" + quote(pw, safe="")) if pw else None')
  if [ -n "$PWLINE" ]; then
    printf '%s\n' "$PWLINE" | sudo install -m 0600 /dev/stdin /etc/winval/compose.env   # printf, not echo: dash's echo would eat the backslashes
  else   # never an EMPTY compose.env (the fallback password would lock the ingress out)
    echo "winval.env's BLASTBOX_DATABASE_URL is not postgresql://winval:<password>@host...; write BOTH lines to /etc/winval/compose.env by hand before the compose up: WINVAL_PG_PASSWORD=<the password, double-quoted, \$ as \$\$> and WINVAL_PG_PASSWORD_URLENC=<the same, percent-encoded>" >&2
  fi
fi
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
`ExecStartPre` when it is MISSING, or present but not owned by the unit — `/dev/shm` empties on reboot, so a rebooted host comes
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

## Why each piece is shaped this way

- **ingress** runs `read_only`, `cap_drop: ALL`, `no-new-privileges`, as uid 10001, with only the
  `job_root` volume + a tmpfs `/tmp` writable. It imports `winval_blastbox.ingress` only — the lazy
  package `__init__` keeps the libvirt/engine modules out of its import graph.
- **pool-manager** runs on the host (systemd) because it drives `virsh` + `iptables`. It is never
  bound to a client-facing socket; its inputs are the Postgres queue + the spooled files. Restart it
  to pick up a rebaked golden.
- **Postgres** (not sqlite) is the cross-boundary store — a real broker beats a sqlite file shared
  over a container/host bind-mount. Redis also works (`BLASTBOX_DATABASE_URL=redis://…`).
- **VPN/tor egress + the tunnel kill-switch** live with the pool-manager (host iptables), so a
  worker still fails closed on a tunnel drop regardless of the ingress.

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
sudo cp deploy/winval-golden-rotate.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now winval-golden-rotate.timer
```

Set `GOLDEN_REVOKED_SAMPLE` to a known-revoked file so the gate also catches a disallowed-list /
revocation regression, not just a dead worker.

