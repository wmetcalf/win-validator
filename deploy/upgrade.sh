#!/bin/sh
# In-place upgrade of a deployed host: `sudo sh deploy/upgrade.sh <branch> [--restart]`.
# A SCRIPT, not a paste: `set -e` and every refusal stay in this process, never in the operator's shell.
# Every refusal happens BEFORE the deployed tree moves: the tree is live (the units run from it, the weekly
# rotation imports from it), so a refused upgrade must leave HEAD where it was. The five refusals: a dirty tree;
# a compose.env that could not be derived (compose-env.sh --check, every rule of it, nothing written); an argument
# that is not a branch on origin (tags are not supported: deploy a branch); a detached HEAD on no origin branch
# (the checkout would orphan it); a local branch that is not an ancestor of origin's tip (local commits AHEAD of
# origin fast-forward "successfully" and would build the untrusted-facing ingress and install root units from an
# unreviewed tree). It never mints a database password: that is the bring-up's, and a fresh one would lock both
# tiers out of the initialised volume.
# Without --restart it stops before anything restarts and prints what --restart does: restarting both tiers
# drops in-flight uploads and fails every RUNNING job as orphaned (clients resubmit) — drain first if that matters.
set -eu
ROOT="${WINVAL_ROOT:-/opt/win-validator}"; ETC="${WINVAL_ETC:-/etc/winval}"
branch="${1:-}"; [ -n "$branch" ] || { echo "usage: upgrade.sh <branch> [--restart]" >&2; exit 2; }
restart=no; [ "${2:-}" = "--restart" ] && restart=yes
if [ "$(id -u)" != 0 ] && [ "${WINVAL_SKIP_ROOT_CHECK:-}" != 1 ]; then echo "upgrade.sh: run as root (sudo): it writes $ETC and /etc/systemd/system" >&2; exit 1; fi
cd "$ROOT"
[ -z "$(git status --porcelain)" ] || { echo "upgrade.sh: local changes in $ROOT — stash or discard them first:" >&2; git status --short >&2; exit 1; }
git fetch --prune origin   # branches only (--tags fails for good once an upstream tag moves; nothing here uses a tag), and PRUNED: a branch deleted upstream left a stale origin/<branch> that passed every guard and shipped its pre-merge tip
if ! git rev-parse --verify -q "refs/remotes/origin/$branch" >/dev/null; then
  echo "upgrade.sh: '$branch' is not a branch on origin now (deleted upstream after a merge? then deploy the branch it was merged into; a tag? tags are not supported); the tree was not moved" >&2; exit 1
fi
# compose-env's OWN rules, all of them, before the checkout — and the TARGET version's copy of them, read from origin without
# touching the tree: a host still on a version that has no deploy/compose-env.sh (this script arrived with it) can bootstrap
# with `git show origin/<branch>:deploy/upgrade.sh | sudo sh -s -- <branch>`, and a duplicated first gate here once let a
# present-but-unusable URL move the tree
rules=$(git show "refs/remotes/origin/$branch:deploy/compose-env.sh" 2>/dev/null) || rules=""   # captured first: a pipe into sh -s reads an empty script as success when the path does not exist at that ref
[ -n "$rules" ] || { echo "upgrade.sh: origin/$branch has no deploy/compose-env.sh (a version older than this script?): this upgrade path deploys versions that carry it; the tree was not moved" >&2; exit 1; }
printf '%s\n' "$rules" | sh -s -- --check || { echo "upgrade.sh: compose.env could not be derived (above); the tree was not moved" >&2; exit 1; }
if [ "$(git rev-parse --abbrev-ref HEAD)" = HEAD ] && [ -z "$(git branch -r --contains HEAD 2>/dev/null)" ]; then
  echo "upgrade.sh: the tree is detached at $(git rev-parse --short HEAD), a commit on no origin branch; the checkout would orphan it — re-attach (git checkout <its branch>) or discard it first; the tree was not moved" >&2; exit 1
fi
if git rev-parse --verify -q "refs/heads/$branch" >/dev/null && ! git merge-base --is-ancestor "refs/heads/$branch" "refs/remotes/origin/$branch"; then
  echo "upgrade.sh: local branch $branch ($(git rev-parse --short "refs/heads/$branch")) carries commits that are not on origin/$branch ($(git rev-parse --short "refs/remotes/origin/$branch")): refusing to build the ingress and install units from a tree that is not the reviewed one; the tree was not moved" >&2; exit 1
fi
git checkout -B "$branch" "refs/remotes/origin/$branch"   # by the remote ref, never the bare name: a tag named like the branch resolved first and detached the live tree at it; -B is a fast-forward here (the guard above proved the local branch an ancestor)
[ "$(git rev-parse HEAD)" = "$(git rev-parse "refs/remotes/origin/$branch")" ] || { echo "upgrade.sh: HEAD is not origin/$branch after the checkout; stopping" >&2; exit 1; }
"$ROOT/.venv/bin/pip" install --upgrade "blastbox>=0.1.33" "psycopg[binary,pool]" redis fastapi "uvicorn[standard]" python-multipart prometheus_client
# every knob the README's upgrade section names; new knobs have defaults. REDACTED on both sides: the live URL line carries the
# database password, and this diff is stdout — of an invocation the README pipes, that lands in tee/script/CI logs
# ...as LOGICAL lines: systemd joins a line ending in an odd number of backslashes with the next, so a URL continued onto the
# next line is one assignment to the service and two physical lines to a line-oriented sed, the second of them unredacted
redacted() {
  python3 - "$1" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read().splitlines()
def continues(raw):
    if raw.lstrip().startswith("#"): return False
    return (len(raw) - len(raw.rstrip("\\"))) % 2 == 1
joined = []
for line in lines:
    if joined and continues(joined[-1]): joined[-1] = joined[-1][:-1] + line
    else: joined.append(line)
pat = re.compile(r"(BLASTBOX_DATABASE_URL\s*=\s*|[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|LICENSE)[A-Za-z_]*\s*=\s*).*$")   # blanks around '=' honoured (KEY = value); _KEY alone hid AUTHENTICODE_SSH_KEY; UNANCHORED: a secret assignment joined onto another value by a continuation is redacted where it lands
for line in joined:
    sys.stdout.buffer.write((pat.sub(lambda m: m.group(1) + "<redacted>", line, count=1) + "\n").encode("utf-8", "surrogateescape"))   # bytes out as bytes in: a stray non-UTF-8 byte must not end the diff in a traceback
PY
}
example=$(mktemp) && redacted deploy/winval.env.example > "$example" && { redacted "$ETC/winval.env" | diff - "$example" || true; }; rm -f "$example"
sh deploy/compose-env.sh   # this version's compose REQUIRES WINVAL_PG_PASSWORD_URLENC, which a compose.env written before it does not carry (no --mint: an upgrade never invents a password)
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
install -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/   # its own line: in an AND-list a failed install was exempt from set -e and the restart ran under the OLD unit
systemctl daemon-reload
systemctl restart winval-pool-manager
echo "upgrade.sh: both tiers restarted on $(git rev-parse --short HEAD)"
