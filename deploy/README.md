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

# secrets, root-only: the env file BOTH units read, and the golden's ssh key
sudo install -d -m 0700 /etc/winval
[ -e /etc/winval/winval.env ] || sudo install -m 0600 deploy/winval.env.example /etc/winval/winval.env   # first time only; then edit
sudo install -m 0600 ~/.ssh/win_golden /etc/winval/win_golden               # the key the golden was built with

# unprivileged tiers: ingress + Postgres. The password is minted ONCE and written into the env
# file the pool-manager reads — it is baked into the Postgres volume at first start and cannot
# be recovered later. Re-running this block is safe: an existing password is kept (a fresh one
# would lock both tiers out of the `pgdata` volume that holds the first). To start over:
# `sudo docker compose --env-file /etc/winval/compose.env -f deploy/docker-compose.yml down -v`
# and delete the BLASTBOX_DATABASE_URL line from winval.env.
if ! sudo grep -q '^BLASTBOX_DATABASE_URL=' /etc/winval/winval.env; then
  PW=$(openssl rand -hex 16)
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" | sudo tee -a /etc/winval/winval.env >/dev/null
  echo "WINVAL_PG_PASSWORD=$PW" | sudo tee /etc/winval/compose.env >/dev/null && sudo chmod 0600 /etc/winval/compose.env
fi
# every compose invocation from now on carries the env file, or a later `up` would recreate the
# ingress with the 'winval' fallback password against a volume that holds the real one
sudo docker compose --env-file /etc/winval/compose.env -f deploy/docker-compose.yml up --build -d

# the smoke gates (boot/recycle for the pool, benign==Valid for the rotation) validate a benign
# SIGNED sample — any small Microsoft-signed binary. winval.env.example points both gates at
# this path. Set the two variables in winval.env ONLY once the sample is in place: a set path that
# does not exist fails the pool-manager at start, by name. Without them, readiness is port-open only.
sudo install -d /var/lib/winval/samples && sudo install -m 0644 /path/to/whoami.exe /var/lib/winval/samples/whoami.exe

# privileged tier on the host (libvirt)
sudo cp deploy/winval-pool-manager.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now winval-pool-manager
```

The unit materialises the RAM base (`AUTHENTICODE_GOLDEN_BASE`, on `/dev/shm`) in
`ExecStartPre` only when it is MISSING — `/dev/shm` empties on reboot, so a rebooted host comes
back on its own (an 18 GB copy takes ~20–30 s; the unit allows 20 min for slow stores). Fast
failures — Postgres not up yet, a bad `winval.env` — are retried every 30 s for eight starts, then the
unit latches `failed`: fix the cause and `sudo systemctl reset-failed winval-pool-manager && sudo
systemctl start winval-pool-manager`. A base that is present is never touched. The
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
build_candidate()  master --overlay clone--> refresh trust state (myatg --refresh: disallowed
                   kill-list + CRL cache + roots/CTL) --> flatten --> candidate.qcow2
validate_golden()  boot a worker off the candidate --> gate: benign==Valid AND revoked==Revoked
rotate()           backup current golden (keep last N) --> promote candidate --> restart pool-manager
```

A candidate is promoted **only if it passes the gate**; a broken/regressed bake (the WU-wedge /
corruption scenarios) is rejected and the current golden is kept. Schedule it weekly:

```sh
sudo cp deploy/winval-golden-rotate.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now winval-golden-rotate.timer
```

Set `GOLDEN_REVOKED_SAMPLE` to a known-revoked file so the gate also catches a disallowed-list /
revocation regression, not just a dead worker.

