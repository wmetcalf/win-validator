#!/bin/sh
# Derive /etc/winval/compose.env from winval.env's BLASTBOX_DATABASE_URL — run as root (the bring-up calls it
# with --mint, deploy/upgrade.sh without). --mint writes a fresh random password INTO winval.env when it has no
# URL line: greenfield only — on an initialised volume a fresh password locks both tiers out of pgdata, so
# without --mint a missing URL line is a refusal that touches nothing. compose.env carries the SAME password in the two forms compose needs
# (the URL in winval.env is the source of truth — also when you wrote that line yourself); written 0600
# from the first byte, never tee-then-chmod; DERIVED every time it disagrees (missing, written before the
# encoded form existed, or the URL was edited). Postgres keeps whatever password its volume was initialised
# with: to change the password for real, `down -v` first, then edit the URL.
# --check: every refusal this script can make, with NOTHING written — deploy/upgrade.sh runs it before the deployed tree
# moves, so the ONE set of rules lives here (a duplicated first-gate in the upgrade script let a present-but-unusable URL
# through, and the refusal then came after the tree and the venv had moved).
set -eu
ETC="${WINVAL_ETC:-/etc/winval}"; mint=no; check=no
# the deployed venv (it carries psycopg, the ingress's own URL parser), found from THIS script's location — never the caller's
# cwd: root ran <cwd>/.venv/bin/python, a shim planted in any directory an operator happened to be in. Read from a pipe
# (upgrade.sh's `sh -s`, run from the tree it cd'd into) the cwd IS the tree
case "$0" in */*) TREE=$(cd "$(dirname "$(readlink -f "$0")")/.." && pwd) ;; *) TREE=$PWD ;; esac   # readlink -f: a symlink to the script from $HOME/bin resolved to $HOME and found a planted ~/.venv
PY=python3; [ -x "$TREE/.venv/bin/python" ] && [ "$(stat -c %u "$TREE/.venv/bin/python" 2>/dev/null)" = "$(id -u)" ] && PY="$TREE/.venv/bin/python"   # and only a venv the invoking user owns: piped in (`sh -s`) from a stranger's writable cwd, a planted ./.venv ran as root
case "${1:-}" in --mint) mint=yes ;; --check) check=yes ;; "") ;; *) echo "usage: compose-env.sh [--mint|--check]" >&2; exit 2 ;; esac
[ -f "$ETC/winval.env" ] || { echo "compose-env: $ETC/winval.env does not exist" >&2; exit 1; }
if [ -e "$ETC/compose.env" ] && [ ! -f "$ETC/compose.env" ]; then echo "compose-env: $ETC/compose.env is not a regular file (a directory? install would write INTO it and report success)" >&2; exit 1; fi
# the candidate file and compose's scratch dir hold the password: removed on EVERY exit, a failed install (read-only /etc,
# ENOSPC) aborting under set -e included — the rm after the install never ran then, and the plaintext survived in TMPDIR
cand=""; trap '[ -z "$cand" ] || rm -f "$cand"' EXIT; trap 'exit 1' INT TERM HUP   # a signal runs no EXIT trap by itself: exit from it, and the trap runs
# compose lets the PROCESS environment beat the env file, even a set-but-empty variable: a WINVAL_PG_PASSWORD exported into
# root's shell would make the `up` (run in that same shell) resolve it over compose.env, and the checks below would judge
# the file while compose used the variable. Refused up front, by name, in every mode
# compose itself reads the env file below; a docker without the compose plugin (or none at all) is named here, not blamed on the file
docker compose version >/dev/null 2>&1 || { echo "compose-env: 'docker compose' is not usable here ($(docker compose version 2>&1 | head -1)); the compose up needs it and so does reading $ETC/compose.env the way compose does" >&2; exit 1; }
for v in WINVAL_PG_PASSWORD WINVAL_PG_PASSWORD_URLENC; do
  if eval "[ -n \"\${$v+x}\" ]"; then echo "compose-env: $v is set in the environment; compose would use it instead of $ETC/compose.env (a set-but-empty one resolves to empty): unset it and rerun" >&2; exit 1; fi
done
envfile_py() {   # $1 = file, $2 = mode: 'url' prints BLASTBOX_DATABASE_URL as the SERVICE reads it (systemd's parser, verified against
  # systemd-run: quoted values run across lines, an open quote swallows the rest of the file, a closing quote returns to the value, the
  # last assignment wins); 'unterminated' exits 3 when the file ends inside an open quote. A file systemd would reject (an assignment
  # that is not UTF-8) is a refusal here — grep '^KEY=' | tail -1 chose another line than systemd, and the pool-manager was locked out
  "$PY" - "$1" "$2" <<'PY'
import sys
# --- envfile parser (systemd src/basic/env-file.c parse_env_file_internal, verified against systemd-run over 77 files) ---
import re as _re
def parse_env_file(data: bytes):
    """winval.env as systemd's EnvironmentFile reads it: a state machine, not lines. Quoted values run across newlines until
    their closing quote (an open one swallows the rest of the file); a closing quote returns to the value (\"a\" \"b\" is ab);
    backslash escapes \\ \" $ ` inside double quotes and any character unquoted, backslash-newline continues; # and ; start
    a comment only where a key would; the LAST assignment wins; a key that is not a valid name is dropped. Returns
    (assignments, unterminated) — unterminated says the file ended inside a quote. Raises ValueError when systemd would
    refuse the whole file (an assignment that is not valid UTF-8 or carries a NUL)."""
    text = data.decode("utf-8", "surrogateescape")
    WS = " \t"; NL = "\n\r"; COMMENTS = "#;"; ESC = "\"\\`$"
    PRE_KEY, KEY, PRE_VALUE, VALUE, VALUE_ESCAPE, SQ, DQ, DQ_ESCAPE, COMMENT = range(9)
    st = PRE_KEY; key = []; val = []; key_ws = None; val_ws = None; out = {}
    def push():
        k = "".join(key[:key_ws] if key_ws is not None else key); v = "".join(val)
        if any("\udc80" <= c <= "\udcff" or c == "\x00" for c in k + v):
            raise ValueError(f"the assignment of {k!r} is not valid UTF-8 (or carries a NUL): systemd rejects the whole file")
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
            elif c not in NL: val.append("\\"); val.append(c)
        elif st == COMMENT:
            if c in NL: st = PRE_KEY
    unterminated = st in (SQ, DQ, DQ_ESCAPE)
    if st in (PRE_VALUE, VALUE, VALUE_ESCAPE, SQ, DQ, DQ_ESCAPE):
        if st == VALUE and val_ws is not None: del val[val_ws:]
        push()
    return out, unterminated
# --- end envfile parser ---

try:
    env, unterminated = parse_env_file(open(sys.argv[1], "rb").read())
except ValueError as exc:
    sys.exit(f"compose-env: {sys.argv[1]}: {exc} (the unit would start with none of its knobs) — fix that line first")
if sys.argv[2] == "unterminated":
    sys.exit(3 if unterminated else 0)
print(env.get("BLASTBOX_DATABASE_URL", ""))
PY
}
db_url() { envfile_py "$ETC/winval.env" url; }
URL=$(db_url) || exit 1   # read ONCE, as the service reads it (an indented line counts, a commented one does not); a file systemd would reject is a refusal, not 'no URL line' (a crash here read as one, and --mint then wrote a SECOND password)
if [ -z "$URL" ]; then
  if [ "$mint" != yes ]; then
    echo "compose-env: $ETC/winval.env has no BLASTBOX_DATABASE_URL line; nothing written. The bring-up mints one (compose-env.sh --mint); an upgrade never does — a fresh password would lock both tiers out of the initialised database volume" >&2; exit 1
  fi
  PW=$(openssl rand -hex 16)
  [ -z "$(tail -c1 "$ETC/winval.env")" ] || echo >> "$ETC/winval.env"   # a last line without its newline: the URL was glued onto that knob, and the SECOND --mint then succeeded over the corrupted knob
  if [ -s "$ETC/winval.env" ] && tail -1 "$ETC/winval.env" | "$PY" -c 'import sys; raw = sys.stdin.read().rstrip("\n"); sys.exit(0 if not raw.lstrip().startswith("#") and (len(raw) - len(raw.rstrip("\\"))) % 2 == 1 else 1)'; then
    echo "compose-env: the last line of $ETC/winval.env ends in a backslash, a continuation to every reader: the minted URL would be swallowed into that knob (and a second --mint would then mint a second password); end that line first" >&2; exit 1
  fi
  uq=0; envfile_py "$ETC/winval.env" unterminated || uq=$?; case $uq in 3) echo "compose-env: $ETC/winval.env ends inside an open quote: systemd reads everything after it as that value, the minted URL included (and the pool-manager would fall back to an in-memory job store, never claiming the ingress's rows); close that quote first" >&2; exit 1 ;; 0) ;; *) exit 1 ;; esac
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" >> "$ETC/winval.env"
  echo "compose-env: minted a database password into $ETC/winval.env (greenfield)"
fi
# the two lines compose needs, derived from the URL. The password is URL-DECODED (a percent-encoded '@' or '#' in the URL
# is the literal char Postgres must be initialised with; both clients decode it the same way). Two forms: the literal
# password (written as a JSON/double-quoted string — compose's env file understands \" and \\ inside double quotes — with
# '$' as '$$', because compose interpolates its env file and a bare '$' would truncate the secret) and the percent-encoded
# one (the ingress embeds it in a URL)
[ "$mint" = yes ] && [ -z "$URL" ] && URL=$(db_url)   # the line --mint just wrote
PWLINE=$(printf '%s' "$URL" | python3 -c 'import sys, json; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); pw = unquote(u.password) if u.scheme.startswith("postgres") and u.username == "winval" and u.password else None; (sys.exit("the password contains control characters, which compose'"'"'s env file cannot carry; choose another") if pw and any(ord(c) < 32 or ord(c) == 127 for c in pw) else None); print("WINVAL_PG_PASSWORD=" + json.dumps(pw, ensure_ascii=False).replace("$", "$$") + "\nWINVAL_PG_PASSWORD_URLENC=" + quote(pw, safe="")) if pw else None')
# What compose READS from an env file is decided by compose, not by a re-implementation of its parser here: a hand-rolled
# reading passed "" (quoted empty), then `"" # comment`, a trailing space, a whitespace-only value and an uninterpolated
# $VAR as non-empty — each of which compose resolves to its 'winval' fallback, splitting the password between the tiers.
# So the two values are read back through compose's own interpolation (a throwaway one-service file), and a file compose
# cannot parse (an unterminated quote) is a refusal HERE, before anything moves — not at the `up` afterwards.
# Prints "plain=<set|empty> urlenc=<set|empty> agree=<yes|no>" — agree: the URL the ingress builds from the URLENC value
# (postgresql://winval:<it>@postgres:5432/winval) parses back to user winval, host postgres, db winval and the plain password
# BY LIBPQ'S RULES (psycopg, the ingress's own parser, when the venv carries it; else the strict fallback: every byte either
# unreserved or a %XX escape — python's lenient unquote let a raw '%' or '@' through that libpq then refused or split at the
# FIRST '@'). Compose's config output spells a '$' in a value as '$$', undone before the comparison. A non-zero rc means
# compose refused the file (its message on stderr).
compose_reads() {
  d=$(mktemp -d) || return 1
  trap 'rm -rf "$d"' EXIT INT TERM HUP   # this function runs in a command substitution (its own subshell): the parent's trap never sees $d
  printf 'services:\n  p:\n    image: scratch\n    environment:\n      A: ${WINVAL_PG_PASSWORD:-}\n      B: ${WINVAL_PG_PASSWORD_URLENC:-}\n' > "$d/probe.yml"
  if cfg=$(docker compose --env-file "$1" -f "$d/probe.yml" config --format json 2>"$d/err"); then
    rm -rf "$d"
    CFG="$cfg" "$PY" - <<'PY'
import json, os, re, sys
from urllib.parse import unquote
e = json.loads(os.environ["CFG"])["services"]["p"].get("environment") or {}
a = (e.get("A") or "").replace("$$", "$"); b = e.get("B") or ""
url = "postgresql://winval:" + b + "@postgres:5432/winval"
try:
    from psycopg.conninfo import conninfo_to_dict
    try:
        d = conninfo_to_dict(url)
        ok = bool(a and b) and d.get("user") == "winval" and d.get("host") == "postgres" and str(d.get("port")) == "5432" and d.get("dbname") == "winval" and d.get("password") == a
    except Exception:
        ok = False
except ImportError:
    ok = bool(a and b) and re.fullmatch(r"(?:(?![@/%])[\x21-\x7e]|%[0-9A-Fa-f]{2})*", b) is not None and unquote(b) == a   # what libpq takes raw in the password: printable ASCII but '@' (ends the userinfo), '/' and a bare '%' (verified per char at round 110); a space is over-strict here
print("plain=" + ("set" if a else "empty"), "urlenc=" + ("set" if b else "empty"), "agree=" + ("yes" if ok else "no"))
PY
  else
    # compose quotes the token it choked on (Go-quoted: the password, once a survivor's open quote swallowed the password
    # line, or the operator's own hand-written one): every quoted segment is elided before the message leaves this script
    MSG="$(cat "$d/err")" "$PY" - <<'PY'
import os, re, sys
# compose echoes the token it choked on in the OPERATOR'S quote character (a single quote too), or after 'in variable name':
# everything from the first quote of either kind, backtick or colon past the line number is dropped, whatever the shape
for line in os.environ["MSG"].splitlines():
    m = re.match(r"^(.*?line \d+: [A-Za-z ]*?)(?=[\"'`:]|$)", line)
    sys.stderr.write((m.group(1).rstrip() + " <elided>" if m else re.sub(r"[\"'`].*$", "<elided>", line)) + "\n")
PY
    rm -rf "$d"; return 1
  fi
}
# both lines present with NON-EMPTY values that AGREE, as compose reads them: what a hand-written compose.env must carry (an
# empty value resolves to compose's 'winval' fallback and locks the ingress out; a plain line the operator forgot to
# percent-encode into the other initialised pgdata with the password the ingress URL then could not even parse — a permanent
# lockout, down -v the only way back). A file compose cannot parse is neither hand-written nor usable: refused below with
# compose's own message (a derived file replaces only the two password lines, so its OTHER lines are checked the same way
# before the write)
hand_written=no; unparseable=""; disagree=no
if [ -f "$ETC/compose.env" ]; then
  # compose's parse error quotes the offending value verbatim (a password with an unbalanced quote): captured in a variable,
  # never a file — a predictable name under /tmp, created 0644 by root's umask, held the secret for the length of the call
  if reads=$(compose_reads "$ETC/compose.env" 2>&1); then
    case "$reads" in "plain=set urlenc=set agree=yes") hand_written=yes ;; "plain=set urlenc=set agree=no") disagree=yes ;; esac
  else
    unparseable=$reads
  fi
fi
if [ -n "$PWLINE" ]; then
    # The file as it SHOULD be: every line that is not an assignment of the two password names as compose would read one
    # (compose's dotenv is last-wins and honours `export ` and leading blanks, so a trailing `export WINVAL_PG_PASSWORD=bogus`
    # would beat the derived line — dropped, not kept), then the two derived lines. That candidate is read by compose BEFORE
    # anything is written (or, with --check, instead of being written): a broken survivor line (WINVAL_SPOOL_SIZE="4g) would
    # otherwise surface at the `up`, after the tree moved. 'already matches' is the file being byte-for-byte that candidate —
    # a textual match of the two lines alone let an unparseable survivor and a later redefinition through as 'matches'.
    # Line-oriented: compose's dotenv also allows a MULTI-LINE quoted value, and a line inside one spelled like an assignment
    # of the two names would be dropped from that value — compose.env carries single-line knobs (README); not supported
    OTHER=$(grep -v '^[[:space:]]*\(export[[:space:]][[:space:]]*\)\{0,1\}WINVAL_PG_PASSWORD\(_URLENC\)\{0,1\}[[:space:]]*=' "$ETC/compose.env" 2>/dev/null || true)   # READ before the write: a grep in the same pipeline as install raced the recreated (empty) file
    cand=$(mktemp) || exit 1
    { [ -n "$OTHER" ] && printf '%s\n' "$OTHER"; printf '%s\n' "$PWLINE"; } > "$cand"   # printf, not echo: dash's echo would eat the backslashes
    if ! reads=$(compose_reads "$cand" 2>&1) || [ "$reads" != "plain=set urlenc=set agree=yes" ]; then
      # attributed WITHOUT the password: the other lines are probed on their own (a message about them cannot contain it);
      # when they parse alone, one of them leaves a quote open that swallows the derived lines — said in words, no message
      rm -f "$cand"; others=$(mktemp) || exit 1; { [ -n "$OTHER" ] && printf '%s\n' "$OTHER"; } > "$others"
      if [ -n "$OTHER" ] && ! omsg=$(compose_reads "$others" 2>&1 >/dev/null); then
        echo "compose-env: compose could not read the derived $ETC/compose.env: a line other than the two password lines is broken — compose said: $omsg; nothing written" >&2
      else
        echo "compose-env: compose could not read the derived $ETC/compose.env: the other lines leave a quote open that swallows the derived password lines (compose's message is withheld: it would quote the password), or compose cannot run; nothing written" >&2
      fi
      rm -f "$others"; exit 1
    fi
    if cmp -s "$cand" "$ETC/compose.env" 2>/dev/null; then
      rm -f "$cand"; echo "compose-env: $ETC/compose.env already matches winval.env"
    elif [ "$check" = yes ]; then rm -f "$cand"; echo "compose-env: --check ok ($ETC/compose.env would be derived from winval.env's URL)"; exit 0
    else
      install -m 0600 "$cand" "$ETC/compose.env"; rm -f "$cand"   # the other lines (WINVAL_UPLOAD_MB, WINVAL_SPOOL_SIZE) survive a password change
      echo "compose-env: $ETC/compose.env derived from winval.env's BLASTBOX_DATABASE_URL"
    fi
  elif [ "$hand_written" = yes ]; then
    # winval.env's URL is not the compose's Postgres (another scheme, user or no password) and the operator wrote both lines
    # by hand, as told: theirs, left alone. NOTE the shipped compose wires its ingress to ITS Postgres service and nothing else:
    # a pool-manager on a different store never sees the ingress's rows (pool_manager.py: the store must match the ingress)
    echo "compose-env: winval.env's URL is not the compose's Postgres; $ETC/compose.env is hand-written and left alone — the shipped compose's ingress queues into ITS Postgres service, so the pool-manager's store must be that Postgres or the ingress must be yours"
  else   # never an EMPTY compose.env or one with an empty value (the 'winval' fallback password would lock the ingress out)
    [ -z "$unparseable" ] || echo "compose-env: compose cannot read $ETC/compose.env: $unparseable" >&2
    [ "$disagree" = no ] || echo "compose-env: the two lines in $ETC/compose.env do not carry the same password: WINVAL_PG_PASSWORD_URLENC must be the percent-encoding of WINVAL_PG_PASSWORD (as compose reads them)" >&2
    echo "winval.env's BLASTBOX_DATABASE_URL is not postgresql://winval:<password>@host...; write BOTH lines to $ETC/compose.env by hand (non-empty, as compose reads them: no trailing comment on the line, \$ as \$\$) before the compose up: WINVAL_PG_PASSWORD=<the password, double-quoted> and WINVAL_PG_PASSWORD_URLENC=<the same, percent-encoded>" >&2
    exit 1
fi
