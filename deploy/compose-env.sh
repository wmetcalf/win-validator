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
case "${1:-}" in --mint) mint=yes ;; --check) check=yes ;; "") ;; *) echo "usage: compose-env.sh [--mint|--check]" >&2; exit 2 ;; esac
[ -f "$ETC/winval.env" ] || { echo "compose-env: $ETC/winval.env does not exist" >&2; exit 1; }
if [ -e "$ETC/compose.env" ] && [ ! -f "$ETC/compose.env" ]; then echo "compose-env: $ETC/compose.env is not a regular file (a directory? install would write INTO it and report success)" >&2; exit 1; fi
# the candidate file and compose's scratch dir hold the password: removed on EVERY exit, a failed install (read-only /etc,
# ENOSPC) aborting under set -e included — the rm after the install never ran then, and the plaintext survived in TMPDIR
cand=""; d=""; trap '[ -z "$cand" ] || rm -f "$cand"; [ -z "$d" ] || rm -rf "$d"' EXIT
# compose lets the PROCESS environment beat the env file, even a set-but-empty variable: a WINVAL_PG_PASSWORD exported into
# root's shell would make the `up` (run in that same shell) resolve it over compose.env, and the checks below would judge
# the file while compose used the variable. Refused up front, by name, in every mode
# compose itself reads the env file below; a docker without the compose plugin (or none at all) is named here, not blamed on the file
docker compose version >/dev/null 2>&1 || { echo "compose-env: 'docker compose' is not usable here ($(docker compose version 2>&1 | head -1)); the compose up needs it and so does reading $ETC/compose.env the way compose does" >&2; exit 1; }
for v in WINVAL_PG_PASSWORD WINVAL_PG_PASSWORD_URLENC; do
  if eval "[ -n \"\${$v+x}\" ]"; then echo "compose-env: $v is set in the environment; compose would use it instead of $ETC/compose.env (a set-but-empty one resolves to empty): unset it and rerun" >&2; exit 1; fi
done
if ! grep -q '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env"; then
  if [ "$mint" != yes ]; then
    echo "compose-env: $ETC/winval.env has no BLASTBOX_DATABASE_URL line; nothing written. The bring-up mints one (compose-env.sh --mint); an upgrade never does — a fresh password would lock both tiers out of the initialised database volume" >&2; exit 1
  fi
  PW=$(openssl rand -hex 16)
  [ -z "$(tail -c1 "$ETC/winval.env")" ] || echo >> "$ETC/winval.env"   # a last line without its newline: the URL was glued onto that knob, and the SECOND --mint then succeeded over the corrupted knob
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" >> "$ETC/winval.env"
  echo "compose-env: minted a database password into $ETC/winval.env (greenfield)"
fi
db_url() {   # the value as the service reads it: systemd's EnvironmentFile (and golden_rotate's loader) accept a value in matching double or single quotes — urlsplit does not, and a quoted URL derived the wrong password
  grep '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env" | tail -1 | cut -d= -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
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
# (a raw '@' or '#' in it makes the ingress see another host or a fragment; compose's config output spells a '$' in a value as
# '$$', undone before the comparison); a non-zero rc means compose refused the file (its message on stderr).
compose_reads() {
  d=$(mktemp -d) || return 1
  printf 'services:\n  p:\n    image: scratch\n    environment:\n      A: ${WINVAL_PG_PASSWORD:-}\n      B: ${WINVAL_PG_PASSWORD_URLENC:-}\n' > "$d/probe.yml"
  if cfg=$(docker compose --env-file "$1" -f "$d/probe.yml" config --format json 2>"$d/err"); then
    rm -rf "$d"
    printf '%s' "$cfg" | python3 -c 'import json, sys; e = json.load(sys.stdin)["services"]["p"].get("environment") or {}; from urllib.parse import unquote, urlsplit; a = e.get("A") or ""; b = e.get("B") or ""; u = urlsplit("postgresql://winval:" + b + "@postgres:5432/winval"); ok = bool(a and b) and u.username == "winval" and u.hostname == "postgres" and u.port == 5432 and u.path == "/winval" and unquote(u.password or "") == a.replace("$$", "$"); print("plain=" + ("set" if a else "empty"), "urlenc=" + ("set" if b else "empty"), "agree=" + ("yes" if ok else "no"))'
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
    if ! reads=$(compose_reads "$cand") || [ "$reads" != "plain=set urlenc=set agree=yes" ]; then
      rm -f "$cand"; echo "compose-env: compose could not read the derived $ETC/compose.env (its message above: a broken line among the other lines, or a compose that cannot run); nothing written" >&2; exit 1
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
