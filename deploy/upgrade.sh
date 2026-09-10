#!/bin/sh
# In-place upgrade of a deployed host: `sudo sh deploy/upgrade.sh <branch> [--restart]`.
# A SCRIPT, not a paste: `set -e` and every refusal stay in this process, never in the operator's shell.
# Stops on a dirty tree, on a checkout that cannot fast-forward, and on a HEAD that is not origin/<branch>
# (local commits AHEAD of origin fast-forward "successfully" and would build the untrusted-facing ingress
# and install root units from an unreviewed tree). Without --restart it stops before anything restarts and
# prints what --restart does: restarting both tiers drops in-flight uploads and fails every RUNNING job as
# orphaned (clients resubmit) — drain first if that matters.
set -eu
ROOT="${WINVAL_ROOT:-/opt/win-validator}"; ETC="${WINVAL_ETC:-/etc/winval}"
branch="${1:-}"; [ -n "$branch" ] || { echo "usage: upgrade.sh <branch> [--restart]" >&2; exit 2; }
restart=no; [ "${2:-}" = "--restart" ] && restart=yes
if [ "$(id -u)" != 0 ] && [ -z "${WINVAL_ETC:-}" ]; then echo "upgrade.sh: run as root (sudo): it writes $ETC and /etc/systemd/system" >&2; exit 1; fi
cd "$ROOT"
[ -z "$(git status --porcelain)" ] || { echo "upgrade.sh: local changes in $ROOT — stash or discard them first:" >&2; git status --short >&2; exit 1; }
git fetch --all --tags
git checkout "$branch"
git merge --ff-only "origin/$branch"
if [ "$(git rev-parse HEAD)" != "$(git rev-parse "origin/$branch")" ]; then
  echo "upgrade.sh: HEAD $(git rev-parse --short HEAD) is not origin/$branch $(git rev-parse --short "origin/$branch") (local commits ahead of origin?): refusing to build the ingress and install units from a tree that is not the reviewed one" >&2
  exit 1
fi
"$ROOT/.venv/bin/pip" install --upgrade "blastbox>=0.1.33" "psycopg[binary,pool]" redis fastapi "uvicorn[standard]" python-multipart prometheus_client
diff "$ETC/winval.env" deploy/winval.env.example || true   # every knob the README's upgrade section names; new knobs have defaults
sh deploy/compose-env.sh   # this version's compose REQUIRES WINVAL_PG_PASSWORD_URLENC, which a compose.env written before it does not carry
if [ "$restart" != yes ]; then
  cat <<MSG
upgrade.sh: code, venv and compose.env are current. Nothing was restarted. To finish:
  sudo sh deploy/upgrade.sh $branch --restart
That rebuilds the ingress container (in-flight uploads are dropped) and restarts the pool-manager (every RUNNING
job is failed as 'orphaned by a pool-manager restart' and its sample removed; clients resubmit) — drain first if
that matters. The pool-manager's first start may wait up to 30 min behind a rotation's lock, then re-copy the RAM base.
MSG
  exit 0
fi
docker compose --env-file "$ETC/compose.env" -f deploy/docker-compose.yml up --build -d   # rebuilds the ingress from this checkout
install -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/ && systemctl daemon-reload
systemctl restart winval-pool-manager
echo "upgrade.sh: both tiers restarted on $(git rev-parse --short HEAD)"
