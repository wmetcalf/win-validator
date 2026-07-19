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
# shared job_root (writable by the ingress container's uid + readable by the host pool-manager)
sudo mkdir -p /var/lib/winval/jobs && sudo chown 10001:10001 /var/lib/winval/jobs

# unprivileged tiers: ingress + Postgres
WINVAL_PG_PASSWORD=$(openssl rand -hex 16) \
  docker compose -f deploy/docker-compose.yml up --build -d

# privileged tier on the host (libvirt). Edit the unit's BLASTBOX_DATABASE_URL password to match.
sudo cp deploy/winval-pool-manager.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now winval-pool-manager
```

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

