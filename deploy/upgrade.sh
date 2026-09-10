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
redacted() {   # the file's ASSIGNMENTS as systemd reads them (the same parser compose-env.sh and golden_rotate.py carry), one KEY=value
  # line per knob sorted by name, a secret's value replaced: a redaction over physical lines printed the second line of a quoted
  # multi-line secret and a URL landed mid-line by a continuation
  python3 - "$1" <<'PY'
import re, sys
# --- envfile parser (systemd src/basic/env-file.c parse_env_file_internal, verified against systemd-run over 77 files) ---
import re as _re
def parse_env_file(data: bytes):
    """winval.env as systemd's EnvironmentFile reads it: a state machine, not lines. Quoted values run across newlines until
    their closing quote (an open one swallows the rest of the file); a closing quote returns to the value (\"a\" \"b\" is ab);
    backslash escapes \\ \" $ ` inside double quotes and any character unquoted, backslash-newline continues; # and ; start
    a comment only where a key would; the LAST assignment wins; a key that is not a valid name is dropped. Returns
    (assignments, unterminated) — unterminated says the file ended inside a quote. Raises ValueError when systemd would
    refuse the whole file (an assignment that is not valid UTF-8 or carries a NUL)."""
    if b"\x00" in data:   # a NUL anywhere, a comment included: systemd refuses the whole file (the UTF-8 rule below is per assignment)
        raise ValueError("the file carries a NUL byte: systemd rejects the whole file")
    text = data.decode("utf-8", "surrogateescape")
    WS = " \t"; NL = "\n\r"; COMMENTS = "#;"; ESC = "\"\\`$"
    PRE_KEY, KEY, PRE_VALUE, VALUE, VALUE_ESCAPE, SQ, DQ, DQ_ESCAPE, COMMENT = range(9)
    st = PRE_KEY; key = []; val = []; key_ws = None; val_ws = None; out = {}
    def push():
        k = "".join(key[:key_ws] if key_ws is not None else key); v = "".join(val)
        if any("\udc80" <= c <= "\udcff" for c in k + v):
            raise ValueError(f"the assignment of {k!r} is not valid UTF-8: systemd rejects the whole file")
        if _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k): out[k] = v
    for c in text:
        if st == PRE_KEY:
            if c in COMMENTS: st = COMMENT
            elif c not in WS and c not in NL: st = KEY; key = [c]; key_ws = None
        elif st == KEY:
            if c in NL: st = PRE_KEY; key = []
            elif c == "=": st = PRE_VALUE; val = []; val_ws = None
            else:
                if c not in WS: key_ws = None
                elif key_ws is None: key_ws = len(key)
                key.append(c)
        elif st == PRE_VALUE:
            if c in NL: st = PRE_KEY; push(); key = []; val = []
            elif c == "'": st = SQ
            elif c == '"': st = DQ
            elif c == "\\": st = VALUE_ESCAPE; val_ws = None
            elif c not in WS: st = VALUE; val_ws = None; val.append(c)
        elif st == VALUE:
            if c in NL:
                st = PRE_KEY
                if val_ws is not None: del val[val_ws:]
                push(); key = []; val = []
            elif c == "\\": st = VALUE_ESCAPE; val_ws = None
            else:
                if c not in WS: val_ws = None
                elif val_ws is None: val_ws = len(val)
                val.append(c)
        elif st == VALUE_ESCAPE:
            st = VALUE
            if c not in NL: val.append(c)
        elif st == SQ:
            if c == "'": st = PRE_VALUE
            else: val.append(c)
        elif st == DQ:
            if c == '"': st = PRE_VALUE
            elif c == "\\": st = DQ_ESCAPE
            else: val.append(c)
        elif st == DQ_ESCAPE:
            st = DQ
            if c in ESC: val.append(c)
            elif c != "\n": val.append("\\"); val.append(c)   # only a LINE FEED continues here (env-file.c tests '\n', not the newline set): a CR keeps its backslash
        elif st == COMMENT:
            if c in NL: st = PRE_KEY
    unterminated = st in (SQ, DQ, DQ_ESCAPE)
    if st in (PRE_VALUE, VALUE, VALUE_ESCAPE, SQ, DQ, DQ_ESCAPE):
        if st == VALUE and val_ws is not None: del val[val_ws:]
        push()
    return out, unterminated
# --- end envfile parser ---

try:
    env, _ = parse_env_file(open(sys.argv[1], "rb").read())
except ValueError as exc:
    env = {"(unreadable)": str(exc)}
secret = re.compile(r"^(BLASTBOX_DATABASE_URL|[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|LICENSE)[A-Za-z_]*)$")
assignment = re.compile(r"(BLASTBOX_DATABASE_URL\s*=\s*|[A-Za-z_]*(?:PASSWORD|SECRET|TOKEN|API_KEY|LICENSE)[A-Za-z_]*\s*=\s*)")   # a secret assignment a continuation landed INSIDE another knob's value: cut there, whatever follows (newlines included)
userinfo = re.compile(r"://[^/@\s]*@")   # any URL userinfo, the whole of it (user AND password), wherever it sits in a value
def shown(v):
    m = assignment.search(v)
    if m: v = v[:m.end()] + "<redacted>"
    return userinfo.sub("://<redacted>@", v).replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
for k in sorted(env):
    v = "<redacted>" if secret.match(k) else shown(env[k])
    sys.stdout.buffer.write(f"{k}={v}\n".encode("utf-8", "surrogateescape"))
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
