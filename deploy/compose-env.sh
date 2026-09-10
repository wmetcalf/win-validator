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
case "$0" in */*) TREE=$(cd "$(dirname "$0")/.." && pwd) ;; *) TREE=$PWD ;; esac
PY=python3; [ -x "$TREE/.venv/bin/python" ] && PY="$TREE/.venv/bin/python"
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
db_url() {   # the value as the SERVICE reads it: the units' EnvironmentFile, read with the rules golden_rotate._load_env_file emulates
  # (systemd.exec): backslash continuation lines, indented keys, # comments, the LAST assignment wins, matching quotes stripped,
  # \\ and \" unescaped inside double quotes, any \x unescaped unquoted — grep '^KEY=' | tail -1 with the quotes stripped chose
  # another line than systemd on an indented or continued file, and the pool-manager was locked out of the ingress's queue
  "$PY" - "$ETC/winval.env" <<'PY'
import re, sys
lines = open(sys.argv[1], encoding="utf-8", errors="surrogateescape").read().splitlines()
def continues(raw):
    if raw.lstrip().startswith("#"): return False
    return (len(raw) - len(raw.rstrip("\\"))) % 2 == 1
joined = []
for line in lines:
    if joined and continues(joined[-1]): joined[-1] = joined[-1][:-1] + line
    else: joined.append(line)
seen = {}
for line in joined:
    line = line.strip()
    if not line or line.startswith("#") or "=" not in line: continue
    k, v = line.split("=", 1); k = k.strip(); v = v.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        quote = v[0]; v = v[1:-1]
        if quote == '"': v = re.sub(r'\\([\\"])', r'\1', v)
    else:
        v = re.sub(r"\\(.)", r"\1", v)
    if k: seen[k] = v
print(seen.get("BLASTBOX_DATABASE_URL", ""))
PY
}
if [ -z "$(db_url)" ]; then   # as the service reads it (an indented line counts, a commented one does not)
  if [ "$mint" != yes ]; then
    echo "compose-env: $ETC/winval.env has no BLASTBOX_DATABASE_URL line; nothing written. The bring-up mints one (compose-env.sh --mint); an upgrade never does — a fresh password would lock both tiers out of the initialised database volume" >&2; exit 1
  fi
  PW=$(openssl rand -hex 16)
  [ -z "$(tail -c1 "$ETC/winval.env")" ] || echo >> "$ETC/winval.env"   # a last line without its newline: the URL was glued onto that knob, and the SECOND --mint then succeeded over the corrupted knob
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" >> "$ETC/winval.env"
  echo "compose-env: minted a database password into $ETC/winval.env (greenfield)"
fi
# the two lines compose needs, derived from the URL. The password is URL-DECODED (a percent-encoded '@' or '#' in the URL
# is the literal char Postgres must be initialised with; both clients decode it the same way). Two forms: the literal
# password (written as a JSON/double-quoted string — compose's env file understands \" and \\ inside double quotes — with
# '$' as '$$', because compose interpolates its env file and a bare '$' would truncate the secret) and the percent-encoded
# one (the ingress embeds it in a URL)
PWLINE=$(db_url | python3 -c 'import sys, json; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); pw = unquote(u.password) if u.scheme.startswith("postgres") and u.username == "winval" and u.password else None; (sys.exit("the password contains control characters, which compose'"'"'s env file cannot carry; choose another") if pw and any(ord(c) < 32 or ord(c) == 127 for c in pw) else None); print("WINVAL_PG_PASSWORD=" + json.dumps(pw, ensure_ascii=False).replace("$", "$$") + "\nWINVAL_PG_PASSWORD_URLENC=" + quote(pw, safe="")) if pw else None')
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
    ok = bool(a and b) and re.fullmatch(r"(?:[A-Za-z0-9._~!$&'()*+,;=:-]|%[0-9A-Fa-f]{2})*", b) is not None and unquote(b) == a   # what libpq takes raw in userinfo: unreserved, sub-delims and ':'; never @ / ? # [ ] or a bare %
print("plain=" + ("set" if a else "empty"), "urlenc=" + ("set" if b else "empty"), "agree=" + ("yes" if ok else "no"))
PY
  else
    cat "$d/err" >&2; rm -rf "$d"; return 1
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
      # compose's message quotes the token it choked on, and a survivor's unbalanced quote swallows the derived password line
      # into that token: the password, in both forms and its JSON spelling, is redacted before the message is shown
      rm -f "$cand"; MSG="$reads" PWLINE="$PWLINE" ETC_FILE="$ETC/compose.env" "$PY" - >&2 <<'PY'
import json, os
msg, pwline = os.environ["MSG"], os.environ["PWLINE"]
plain_json = pwline.splitlines()[0].split("=", 1)[1]; enc = pwline.splitlines()[1].split("=", 1)[1]
plain = json.loads(plain_json.replace("$$", "$"))
for needle in sorted({plain_json, plain_json.replace("$$", "$"), plain, enc}, key=len, reverse=True):
    if needle: msg = msg.replace(needle, "<password>")
print("compose-env: compose could not read the derived " + os.environ.get("ETC_FILE", "compose.env") + " (a broken line among the other lines, or a compose that cannot run); nothing written. compose said: " + msg)
PY
      exit 1
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
