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
# with --restart, an egress posture this version's pool-manager refuses at start (without --restart, a WARNING).
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
if sys.argv[1] == "egress":
    import os   # the pool-manager's START, read the way it reads the env: _refuse_open_egress (#7/#8) AND the posture the warm-up
    # validates (validate_egress_posture: the IP pool, a supported exit name, inetsim's sink, gateway-and-leg together, a well-formed boolean) — a
    # posture refused after checkout, pip and restart is what this gate exists to refuse BEFORE
    SUPPORTED = ['direct', 'drop', 'inetsim', 'none', 'openvpn', 'tor', 'wireguard']   # blastbox.host.runtime.libvirt_egress._SUPPORTED_EXITS, inlined: this runs before the checkout and cannot import the target version (a harness scenario keeps the two equal)
    ex = (env.get("AUTHENTICODE_EXIT") or "").strip()   # stripped, as the manager strips it: a quoted blank is unset
    if not ex: print("unset: AUTHENTICODE_EXIT is not set (this version's pool-manager refuses to start without one): name an exit driver (direct is the minimum) or write AUTHENTICODE_EXIT=none to run with no egress policy on purpose"); sys.exit(0)
    # AUTHENTICODE_IP_POOL is parsed by the posture check whatever the exit (validate_egress_posture, blastbox's _parse_ip_pool):
    # 'START-END', both IPv4, END >= START, one /16 — so even AUTHENTICODE_EXIT=none refuses a bad pool. Judged AFTER the unset-exit
    # refusal, the manager's own order (_refuse_open_egress at start, the posture in the warm-up); the four knobs the posture reads
    # (pool, sink, gateway, leg) are stripped on both sides, so a whitespace-only value is unset to both
    pool_spec = (env.get("AUTHENTICODE_IP_POOL") or "").strip()
    if pool_spec:
        import ipaddress
        start, _, end = pool_spec.partition("-")
        try:
            if not end: raise ValueError("must be 'START-END'")
            lo, hi = int(ipaddress.IPv4Address(start.strip())), int(ipaddress.IPv4Address(end.strip()))
            if hi < lo: raise ValueError("END < START")
            if start.strip().split(".")[:2] != end.strip().split(".")[:2]: raise ValueError("must fit in one /16")
        except (ValueError, ipaddress.AddressValueError) as exc:
            print(f"malformed: AUTHENTICODE_IP_POOL is not a usable range ({exc}); the pool-manager refuses that posture at start"); sys.exit(0)
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
    if ex.lower() == "none": pool_guards(); print("ok"); sys.exit(0)
    if ex not in SUPPORTED:
        print(f"malformed: AUTHENTICODE_EXIT names an exit the VM rooter does not support (one of {', '.join(SUPPORTED)}); the pool-manager refuses that posture at start"); sys.exit(0)
    # the rest of validate_egress_posture: inetsim needs its sink; a shared-router VPN needs BOTH gateway and leg or neither
    if ex == "inetsim" and not (env.get("AUTHENTICODE_FAKENET_ADDR") or "").strip():
        print("malformed: AUTHENTICODE_EXIT=inetsim needs AUTHENTICODE_FAKENET_ADDR (the FakeNet sink); the pool-manager refuses that posture at start"); sys.exit(0)
    if ex in ("openvpn", "wireguard") and bool((env.get("AUTHENTICODE_GATEWAY") or "").strip()) != bool((env.get("AUTHENTICODE_LEG") or "").strip()):
        print(f"malformed: AUTHENTICODE_EXIT={ex} shared-router mode needs BOTH AUTHENTICODE_GATEWAY and AUTHENTICODE_LEG (or neither); the pool-manager refuses that posture at start"); sys.exit(0)
    bi = (env.get("AUTHENTICODE_BLOCK_INTERNAL") or "").strip().lower()   # BEFORE the worker-count short-circuit: the spec parses the boolean whatever the count
    if bi and bi not in ("1", "true", "yes", "on", "0", "false", "no", "off"):
        print(f"malformed: AUTHENTICODE_BLOCK_INTERNAL={bi!r} is not a boolean (true/false): the pool-manager refuses that posture"); sys.exit(0)
    try: workers = max(1, int((env.get("AUTHENTICODE_POOL_SIZE") or "2").strip()))
    except ValueError: workers = 2
    if workers < 2: pool_guards(); print("ok"); sys.exit(0)
    if "AUTHENTICODE_EGRESS_PORTS" in env and ex != "drop" and bi not in ("1", "true", "yes", "on"):   # an allowlist admitting the AGENT port opens the siblings' agent to a compromised worker
        try: agent = max(1, int((env.get("AUTHENTICODE_AGENT_PORT") or "8765").strip()))   # knobs.env_int: int() of the stripped value, floored at 1, the default on a non-integer
        except ValueError: agent = 8765
        listed = set()   # blastbox's parse_egress_ports, mirrored: split on commas AND whitespace, int() (so +8765 and 8_765 count, as there), 1..65535, the rest dropped
        for tok in re.split(r"[,\s]+", (env.get("AUTHENTICODE_EGRESS_PORTS") or "").strip()):
            if not tok: continue
            try: n = int(tok)
            except ValueError: continue
            if 1 <= n <= 65535: listed.add(n)
        if agent in listed:
            print(f"refuse: AUTHENTICODE_EGRESS_PORTS admits the agent port {agent} with AUTHENTICODE_BLOCK_INTERNAL off and {workers} workers: the pool-manager refuses to start (a compromised worker reaches its siblings' agent through the allowlist); set AUTHENTICODE_BLOCK_INTERNAL=1 or drop the port"); sys.exit(0)
    if ex == "drop" or "AUTHENTICODE_EGRESS_PORTS" in env or bi in ("1", "true", "yes", "on"):   # a SET allowlist (not admitting the agent port), even a closed one, drops siblings; the drop exit ends in DROP
        # the kernel half, as the restart will find it: the unit's ExecStartPre loads br_netfilter and sets the sysctl (both with `-`, so a host
        # that cannot load the module reaches the manager, which refuses by name); refuse that host HERE, before the move
        import os, subprocess
        if os.path.exists(os.environ.get("WINVAL_BRIDGE_NF_SYSCTL") or "/proc/sys/net/bridge/bridge-nf-call-iptables"): pool_guards(); print("ok"); sys.exit(0)
        # the VERBOSE dry run (the exit code says nothing: with an `install br_netfilter /bin/false` directive `-n` exits 0 for a module it
        # would not insert) is the plan, and `modprobe -c` names whose install directive a plan line is (the plan does not): loadable = rc 0
        # and EITHER br_netfilter's own directive is the documented `modprobe --ignore-install br_netfilter` self-load (the command's words
        # up to a comment), OR it has none, the plan inserts br_netfilter.ko and carries no install line (a dependency's directive is refused:
        # whether the load survives it cannot be told from the plan) — winval_blastbox.pool_manager._bridge_nf_loadable, inlined
        def mp(*a):
            r = subprocess.run(["modprobe", *a], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
            return r.returncode, [ln.strip() for ln in r.stdout.decode("utf-8", "replace").splitlines() if ln.strip()]
        try:
            rc, plan = mp("-n", "-v", "br_netfilter"); conf = mp("-c")[1] if rc == 0 else []
            why = "" if rc == 0 else f"modprobe -n -v br_netfilter failed (rc {rc}: {' | '.join(plan)[:200]})"
            own = [ln for ln in conf if ln.split()[:2] == ["install", "br_netfilter"]]
            if not why and own:
                words = []
                for w in own[0].split()[2:]:
                    if w.startswith("#"): break
                    words.append(w)
                first = []   # the idiom, EXACTLY (pool_manager._is_self_load): the first simple command the system's modprobe, flags from the insertion-preserving set, the module its one argument
                for w in words:
                    if w in ("&&", "||", ";", "|"): break
                    first.append(w)
                import shutil
                prog = first[0] if first else ""; flags = [w for w in first[1:] if w.startswith("-")]; args = [w for w in first[1:] if not w.startswith("-")]
                system = shutil.which("modprobe") or ""
                prog_ok = os.path.basename(prog) == "modprobe" and ("/" not in prog or (bool(system) and os.access(prog, os.X_OK) and os.path.realpath(prog) == os.path.realpath(system)))
                OKFLAGS = {"--ignore-install", "-i", "--quiet", "-q", "--verbose", "-v", "--all", "-a", "--use-blacklist", "-b", "--syslog", "-s"}
                name = os.path.basename(args[0]) if len(args) == 1 else ""
                for suf in (".zst", ".xz", ".gz", ".ko"):
                    if name.endswith(suf): name = name[:-len(suf)]
                idiom = prog_ok and all(f in OKFLAGS for f in flags) and any(f in ("--ignore-install", "-i") for f in flags) and name.replace("-", "_") == "br_netfilter"
                if not idiom: why = f"a modprobe.d install directive replaces the insertion ({own[0][:120]}); only the plain self-load idiom is read as loadable"
                else:   # the idiom's own command, dry-run: the directive's text does not say the module EXISTS
                    rc2, plan2 = mp("-n", "-v", *[w for w in first[1:] if w not in ("-q", "--quiet", "-s", "--syslog")])   # the idiom's OWN words, dry-run (quiet/syslog would hide the plan)
                    if rc2 != 0 or not any(ln.startswith("insmod ") and "/br_netfilter.ko" in ln for ln in plan2): why = f"the self-load directive's own modprobe --ignore-install br_netfilter would insert nothing (rc {rc2}: {' | '.join(plan2)[:200] or 'no output'})"
                    elif any(ln.startswith("install ") for ln in plan2): why = "a dependency in the self-load's plan carries an install directive: whether the load survives it cannot be told from the plan"
            elif not why:
                installs = [ln for ln in plan if ln.startswith("install ")]
                if not any(ln.startswith("insmod ") and "/br_netfilter.ko" in ln for ln in plan): why = f"the dry run names no br_netfilter.ko to insert ({' | '.join(plan)[:200] or 'no output'})"
                elif installs: why = f"a dependency in the plan carries an install directive ({installs[0][:120]}): whether the load survives it cannot be told from the plan"
        except (OSError, subprocess.SubprocessError) as exc: why = f"modprobe could not run ({exc})"
        if not why: pool_guards(); print("ok"); sys.exit(0)
        print(f"refuse: br_netfilter is not loaded and cannot be ({why}): with {workers} workers on one bridge the pool-manager refuses to start (the FORWARD rules never see worker-to-worker frames); install the module or run one worker"); sys.exit(0)
    print(f"refuse: an AUTHENTICODE_EXIT driver with {workers} workers and neither AUTHENTICODE_BLOCK_INTERNAL=1 nor an AUTHENTICODE_EGRESS_PORTS that does not admit the agent port (nor the drop exit): the pool-manager refuses to start (a worker could reach its siblings' agent port); set one"); sys.exit(0)
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
verdict=$(envfile_py egress "$ETC/winval.env")
case "$verdict" in ok) ;; *)   # unset: / malformed: / refuse: — each names its remedy
  if [ "$restart" = yes ]; then echo "upgrade.sh: $ETC/winval.env: $verdict, then rerun; the tree was not moved" >&2; exit 1; fi
  echo "upgrade.sh: WARNING: $ETC/winval.env: $verdict" >&2 ;;
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
# just checked out depends on what its unit does at start (the RAM base it materialises, the br_netfilter it loads) — a pip failure,
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
t0=$(date +%s)
systemctl restart winval-pool-manager
# a Type=simple unit is 'active' the instant systemctl returns: wait for the manager to SAY the pool is warm (the marker, newer than the
# restart), fail on the unit's failure signals meanwhile, give up by name at the ceiling — the rotation's restart_pool, in sh
while :; do
  if [ -f "$ready" ] && [ "$(stat -c %Y "$ready" 2>/dev/null || echo 0)" -ge "$((t0 - 2))" ]; then break; fi
  if [ "$(systemctl is-failed winval-pool-manager 2>/dev/null)" = failed ]; then echo "upgrade.sh: winval-pool-manager went 'failed' after the restart: its start is failing (journalctl -u winval-pool-manager); the code is upgraded, the pool is DOWN" >&2; exit 1; fi
  case "$(systemctl is-active winval-pool-manager 2>/dev/null)" in active|activating) ;; *) echo "upgrade.sh: winval-pool-manager is not active after the restart (journalctl -u winval-pool-manager); the code is upgraded, the pool is DOWN" >&2; exit 1;; esac
  if [ "$(( $(date +%s) - t0 ))" -ge "$settle" ]; then echo "upgrade.sh: winval-pool-manager did not report the pool warm within ${settle}s ($ready not written; journalctl -u winval-pool-manager): the code is upgraded, the pool is not in service; GOLDEN_RESTART_SETTLE_S raises the wait" >&2; exit 1; fi
  sleep 1
done
echo "upgrade.sh: both tiers restarted on $(git rev-parse --short HEAD); the pool-manager reported the pool warm $(( $(date +%s) - t0 ))s after the restart"
