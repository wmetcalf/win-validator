#!/bin/sh
# In-place upgrade of a deployed host: `sudo sh deploy/upgrade.sh <branch> [--restart]`.
# A SCRIPT, not a paste: `set -e` and every refusal stay in this process, never in the operator's shell.
# Every refusal happens BEFORE the deployed tree moves: the tree is live (the units run from it, the weekly
# rotation imports from it), so a refused upgrade must leave HEAD where it was. The refusals, all before the move:
# not root; a dirty tree; a compose.env that could not be derived (compose-env.sh --check, every rule of it, nothing
# written); an argument that is not a branch on origin (tags are not supported: deploy a branch); a target whose tree
# has no deploy/compose-env.sh (a version without these rules); a detached HEAD on no origin branch (the checkout
# would orphan it); a local branch that is not an ancestor of origin's tip (local commits AHEAD of origin fast-forward
# "successfully" and would build the untrusted-facing ingress and install root units from an unreviewed tree); and,
# with --restart, an egress posture this version's pool-manager refuses at start (without --restart, a WARNING); and, in BOTH halves
# (both install the timer), a winval.env whose old GOLDEN_BASE names a path the weekly rotation would not promote to.
# It never mints a database password: that is the bring-up's, and a fresh one would lock both tiers out of the
# initialised volume.
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
envfile_py() {   # $1 = mode, $2 = file [, $3 = key]. 'redacted': the file's ASSIGNMENTS as systemd reads them (the same parser
  # compose-env.sh and golden_rotate.py carry), one KEY=value line per knob sorted by name, a secret's value replaced (a redaction
  # over physical lines printed the second line of a quoted multi-line secret and a URL landed mid-line by a continuation).
  # 'get': one knob's value as the units read it (empty when unset)
  python3 -I - "$1" "$2" "${3:-}" <<'PY'   # -I: the caller's cwd is not on sys.path (a planted json.py never imports as root)
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
    env, _ = parse_env_file(open(sys.argv[2], "rb").read())
except ValueError as exc:
    env = {"(unreadable)": str(exc)}
if sys.argv[1] == "get":
    print(env.get(sys.argv[3], "")); sys.exit(0)
if sys.argv[1] == "rotation":   # the ROTATION's own refusal (golden_rotate.rotation_preflight, right after its root check): its own pass, so
    # no start-time knob's verdict can mask it — the egress mode below prints ONE verdict, the pool-manager's first
    legacy = (env.get("GOLDEN_BASE") or "").strip(" \t")   # the rotator's OLD name for the RAM base (golden_rotate.LEGACY_GOLDEN_BASE): read by
    # nothing else, refused by the preflight whenever it names a path other than the one the rotation would promote to — the weekly timer included
    effective = (env.get("AUTHENTICODE_GOLDEN_BASE") or "").strip(" \t") or "/dev/shm/golden-base.qcow2"
    if legacy and legacy != effective: print(f"rotation: GOLDEN_BASE={legacy[:200]!r} is the rotator's OLD name for the RAM base and nothing else reads it (the pool and the unit boot from AUTHENTICODE_GOLDEN_BASE, {effective}); the weekly rotation refuses that posture — rename the knob"); sys.exit(0)
    print("ok"); sys.exit(0)
if sys.argv[1] == "egress":
    import os
    # the pool-manager's START, judged in ITS order, read the way it reads the env: _refuse_open_egress first (LOCK_PARAMS, then the
    # network posture: workers live in a private network namespace each, with no egress — so AUTHENTICODE_EXIT must be unset or none and
    # no rooter-era egress knob may be set — and the namespace's host address must parse), then WarmVmPool.__init__'s knob guards (the
    # smoke sample, its status, the warm dir), then the golden base. A posture refused after checkout, pip and restart is what this gate
    # exists to refuse BEFORE
    lp = (env.get("AUTHENTICODE_LOCK_PARAMS") or "").strip().lower()   # _refuse_open_egress's first guard (engine.params_locked); the value is not echoed
    if lp and lp not in ("1", "true", "yes", "on", "0", "false", "no", "off"): print("malformed: AUTHENTICODE_LOCK_PARAMS is not a boolean (true/false): the pool-manager refuses that posture at start"); sys.exit(0)
    ex = (env.get("AUTHENTICODE_EXIT") or "").strip()   # stripped, as the manager strips it: a quoted blank is unset, which is none
    if ex and ex.lower() != "none":
        print(f"refuse: AUTHENTICODE_EXIT={ex[:40]!r} names a host-side egress exit; those were removed (they installed iptables chains on the host) — workers are isolated in a private network namespace with no egress: set AUTHENTICODE_EXIT=none or unset it"); sys.exit(0)
    OBSOLETE = ("AUTHENTICODE_EGRESS_PORTS", "AUTHENTICODE_VPN_TABLE", "AUTHENTICODE_VPN_TUN", "AUTHENTICODE_FAKENET_ADDR", "AUTHENTICODE_GATEWAY", "AUTHENTICODE_LEG", "AUTHENTICODE_IP_POOL")   # vm_pool.OBSOLETE_EGRESS_KNOBS, inlined: this runs before the checkout
    stale = [k for k in OBSOLETE if (env.get(k) or "").strip()]
    if stale: print(f"refuse: {', '.join(stale)} configured host-firewall egress or a shared libvirt network, both removed: remove the knob(s); the pool-manager refuses that posture at start"); sys.exit(0)
    caller = (env.get("AUTHENTICODE_AGENT_CALLER") or "").strip()
    if caller:
        import ipaddress
        try:
            a = ipaddress.IPv4Address(caller)
            if int(a) & 0xff in (0, 255): raise ValueError("network or broadcast address of its /24")   # netns_isolation.host_addr
        except ValueError: print("malformed: AUTHENTICODE_AGENT_CALLER is not one IPv4 address (the host side of every worker's private namespace); the pool-manager refuses that posture at start"); sys.exit(0)
    import shutil
    missing = [t for t in ("ip", "dnsmasq") if not shutil.which(t, path=os.environ.get("PATH", "") + ":/usr/sbin:/sbin")]   # pool_manager.HOST_TOOLS
    if missing: print(f"refuse: {', '.join(missing)} not found: namespace isolation needs iproute2 (ip) and dnsmasq on the host; the pool-manager refuses to start without them"); sys.exit(0)
    def golden_guard():   # vm_pool.golden_base and the unit's pre-start, mirrored: space and tab trimmed at the ends, any other byte outside
        # printable ASCII refused — read where the manager builds its spec, after the smoke and warm-dir guards
        gb = (env.get("AUTHENTICODE_GOLDEN_BASE") or "").strip(" \t") or "/dev/shm/golden-base.qcow2"
        if not all(32 <= ord(c) < 127 for c in gb): print(f"malformed: AUTHENTICODE_GOLDEN_BASE={gb[:200]!r} carries a character outside printable ASCII (a pasted U+00A0, a stray newline?); the pool-manager's pre-start refuses that posture"); sys.exit(0)
    def pool_guards():   # WarmVmPool.__init__'s own refusals (after _refuse_open_egress, as the manager orders them): the smoke sample, its
        # expected status, the warm dir — each refused by name at start, so refused HERE before the move
        AGENT = {"valid", "revoked", "distrusted", "untrustedroot", "hashmismatch", "expired", "notyetvalid", "unknownerror", "notsigned"}
        smp = (env.get("AUTHENTICODE_SMOKE_SAMPLE") or "").strip()
        if smp and not os.path.isfile(smp): print(f"malformed: AUTHENTICODE_SMOKE_SAMPLE={smp!r} is not a file; the pool-manager refuses that posture at start"); sys.exit(0)
        if smp:
            exp = (env.get("AUTHENTICODE_SMOKE_EXPECT") or "").strip() or "Valid"
            if exp.lower() not in AGENT: print(f"malformed: AUTHENTICODE_SMOKE_EXPECT={exp!r} is not a status the agent maps; the pool-manager refuses that posture at start"); sys.exit(0)
        wd = (env.get("AUTHENTICODE_WARM_DIR") or "").strip()
        if wd and not os.path.isdir(wd): print(f"malformed: AUTHENTICODE_WARM_DIR={wd!r} is not a directory; the pool-manager refuses that posture at start"); sys.exit(0)
    pool_guards()
    golden_guard()   # __init__ builds the spec after the smoke and warm-dir guards
    print("ok"); sys.exit(0)
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

# design change #8, the half an env file decides, read the way the pool-manager reads it (the helper mirrors its rules): with --restart
# a posture the manager would refuse is refused HERE, before the move; without it, said loudly (the sysctl half as the unit's ExecStartPre will leave it)
rverdict=$(envfile_py rotation "$ETC/winval.env")   # the weekly rotation's own refusal, its own pass (never masked by a start-time knob's
case "$rverdict" in ok) ;; *)   # verdict): BOTH halves install the units and the timer, so it is refused in both, before the move
  printf '%s\n' "upgrade.sh: $ETC/winval.env: $rverdict, then rerun; the tree was not moved (both halves install the timer that would refuse)" >&2; exit 1 ;;   # printf: dash's echo would re-expand the repr's \n \t
esac
verdict=$(envfile_py egress "$ETC/winval.env")
case "$verdict" in ok) ;;
  *)   # unset: / malformed: / refuse: — each names its remedy; they bite only when the pool-manager STARTS, so without --restart a warning
  if [ "$restart" = yes ]; then printf '%s\n' "upgrade.sh: $ETC/winval.env: $verdict, then rerun; the tree was not moved" >&2; exit 1; fi
  printf '%s\n' "upgrade.sh: WARNING: $ETC/winval.env: $verdict" >&2 ;;
esac
if [ "$(git rev-parse --abbrev-ref HEAD)" = HEAD ] && [ -z "$(git branch -r --contains HEAD 2>/dev/null)" ]; then
  echo "upgrade.sh: the tree is detached at $(git rev-parse --short HEAD), a commit on no origin branch; the checkout would orphan it — re-attach (git checkout <its branch>) or discard it first; the tree was not moved" >&2; exit 1
fi
if git rev-parse --verify -q "refs/heads/$branch" >/dev/null && ! git merge-base --is-ancestor "refs/heads/$branch" "refs/remotes/origin/$branch"; then
  echo "upgrade.sh: local branch $branch ($(git rev-parse --short "refs/heads/$branch")) carries commits that are not on origin/$branch ($(git rev-parse --short "refs/remotes/origin/$branch")): refusing to build the ingress and install units from a tree that is not the reviewed one; the tree was not moved" >&2; exit 1
fi
git checkout -B "$branch" "refs/remotes/origin/$branch"   # by the remote ref, never the bare name: a tag named like the branch resolved first and detached the live tree at it; -B is a fast-forward here (the guard above proved the local branch an ancestor)
[ "$(git rev-parse HEAD)" = "$(git rev-parse "refs/remotes/origin/$branch")" ] || { echo "upgrade.sh: HEAD is not origin/$branch after the checkout; stopping" >&2; exit 1; }
# the unit files go in RIGHT AFTER the checkout, before pip and the restart gate: installing a unit restarts nothing, and the code
# just checked out depends on what its unit does at start (the RAM base it materialises) — a pip failure,
# a crash or a reboot from here on would otherwise leave or start the new code under the old unit and latch the pool-manager failed
install -m 0644 deploy/*.service deploy/*.timer /etc/systemd/system/   # its own line: in an AND-list a failed install was exempt from set -e and the restart ran under the OLD unit
systemctl daemon-reload
"$ROOT/.venv/bin/pip" install --upgrade "blastbox>=0.1.33" "psycopg[binary,pool]" redis fastapi "uvicorn[standard]" python-multipart prometheus_client
# every knob the README's upgrade section names; new knobs have defaults. REDACTED on both sides: the live URL line carries the
# database password, and this diff is stdout — of an invocation the README pipes, that lands in tee/script/CI logs
# ...as LOGICAL lines: systemd joins a line ending in an odd number of backslashes with the next, so a URL continued onto the
# next line is one assignment to the service and two physical lines to a line-oriented sed, the second of them unredacted
example=$(mktemp) && envfile_py redacted deploy/winval.env.example > "$example" && { envfile_py redacted "$ETC/winval.env" | diff - "$example" || true; }; rm -f "$example"
sh deploy/compose-env.sh   # this version's compose REQUIRES WINVAL_PG_PASSWORD_URLENC, which a compose.env written before it does not carry (no --mint: an upgrade never invents a password)
if [ "$restart" != yes ]; then
  cat <<MSG
upgrade.sh: code, venv, compose.env and the unit files are current. Nothing was restarted. To finish:
  sudo sh deploy/upgrade.sh $branch --restart
That rebuilds the ingress container (in-flight uploads are dropped) and restarts the pool-manager (every RUNNING
job is failed as 'orphaned by a pool-manager restart' and its sample removed; clients resubmit) — drain first if
that matters. The pool-manager's first start may wait up to 30 min behind a rotation's lock, then re-copy the RAM base.
MSG
  exit 0
fi
docker compose --env-file "$ETC/compose.env" -f deploy/docker-compose.yml up --build -d   # rebuilds the ingress from this checkout
ready="${WINVAL_READY_FILE:-$(envfile_py get "$ETC/winval.env" WINVAL_READY_FILE)}"; ready="${ready:-/run/winval-pool-manager.ready}"   # the marker the pool-manager writes once warm
settle="${GOLDEN_RESTART_SETTLE_S:-$(envfile_py get "$ETC/winval.env" GOLDEN_RESTART_SETTLE_S)}"; case "$settle" in ''|*[!0-9]*) settle=3600;; esac
t0=$(date +%s)   # the marker's freshness counts from the restart's ISSUE (a fast warm lands before systemctl returns)
systemctl restart winval-pool-manager
returned=$(date +%s)   # the ceiling, and the number the operator reads, count from its RETURN (the stop, up to TimeoutStopSec, is not warm time)
if [ "$settle" -eq 0 ]; then echo "upgrade.sh: both tiers restarted on $(git rev-parse --short HEAD); GOLDEN_RESTART_SETTLE_S=0: the pool-manager was NOT waited for (it reports the pool warm at $ready)"; exit 0; fi   # 0 skips the wait, as in the rotation
# a Type=simple unit is 'active' the instant systemctl returns: wait for the manager to SAY the pool is warm (the marker, newer than the
# restart), fail on the unit's failure signals meanwhile, give up by name at the ceiling — the rotation's restart_pool, in sh
while :; do
  if [ -f "$ready" ] && [ "$(stat -c %Y "$ready" 2>/dev/null || echo 0)" -ge "$((t0 - 2))" ]; then break; fi
  if [ "$(systemctl is-failed winval-pool-manager 2>/dev/null)" = failed ]; then echo "upgrade.sh: winval-pool-manager went 'failed' after the restart: its start is failing (journalctl -u winval-pool-manager); the code is upgraded, the pool is DOWN" >&2; exit 1; fi
  case "$(systemctl is-active winval-pool-manager 2>/dev/null)" in active|activating) ;; *) echo "upgrade.sh: winval-pool-manager is not active after the restart (journalctl -u winval-pool-manager); the code is upgraded, the pool is DOWN" >&2; exit 1;; esac
  if [ "$(( $(date +%s) - returned ))" -ge "$settle" ]; then echo "upgrade.sh: winval-pool-manager did not report the pool warm within ${settle}s ($ready not written; journalctl -u winval-pool-manager): the code is upgraded, the pool is not in service; GOLDEN_RESTART_SETTLE_S raises the wait" >&2; exit 1; fi
  sleep 1
done
echo "upgrade.sh: both tiers restarted on $(git rev-parse --short HEAD); the pool-manager reported the pool warm $(( $(date +%s) - returned ))s after the restart returned"
