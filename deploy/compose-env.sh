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
if ! grep -q '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env"; then
  if [ "$mint" != yes ]; then
    echo "compose-env: $ETC/winval.env has no BLASTBOX_DATABASE_URL line; nothing written. The bring-up mints one (compose-env.sh --mint); an upgrade never does — a fresh password would lock both tiers out of the initialised database volume" >&2; exit 1
  fi
  PW=$(openssl rand -hex 16)
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" >> "$ETC/winval.env"
  echo "compose-env: minted a database password into $ETC/winval.env (greenfield)"
fi
db_url() {   # the value as the service reads it: systemd's EnvironmentFile (and golden_rotate's loader) accept a value in matching double or single quotes — urlsplit does not, and a quoted URL derived the wrong password
  grep '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env" | tail -1 | cut -d= -f2- | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}
WANT_URLENC=$(db_url | python3 -c 'import sys; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); print(quote(unquote(u.password), safe="")) if u.password else None')
HAVE_URLENC=$(sed -n 's/^WINVAL_PG_PASSWORD_URLENC=//p' "$ETC/compose.env" 2>/dev/null | tail -1)
# both lines present with NON-EMPTY values: what a hand-written compose.env must carry (an empty value resolves to compose's
# 'winval' fallback and locks the ingress out; and an empty WANT_URLENC from a password-less URL used to compare equal to a
# MISSING line, so a pre-URLENC compose.env was reported as 'already matches' and compose then hard-failed after the upgrade)
hand_written=no; grep -q '^WINVAL_PG_PASSWORD=..*' "$ETC/compose.env" 2>/dev/null && grep -q '^WINVAL_PG_PASSWORD_URLENC=..*' "$ETC/compose.env" 2>/dev/null && hand_written=yes
if [ -n "$WANT_URLENC" ] && [ "$HAVE_URLENC" = "$WANT_URLENC" ]; then
  echo "compose-env: $ETC/compose.env already matches winval.env"
else
  # the password is URL-DECODED (a percent-encoded '@' or '#' in the URL is the literal char Postgres must be initialised
  # with; both clients decode it the same way). Two forms: the literal password (written as a JSON/double-quoted string —
  # compose's env file understands \" and \\ inside double quotes — with '$' as '$$', because compose interpolates its env
  # file and a bare '$' would truncate the secret) and the percent-encoded one (the ingress embeds it in a URL)
  PWLINE=$(db_url | python3 -c 'import sys, json; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); pw = unquote(u.password) if u.scheme.startswith("postgres") and u.username == "winval" and u.password else None; (sys.exit("the password contains control characters, which compose'"'"'s env file cannot carry; choose another") if pw and any(ord(c) < 32 or ord(c) == 127 for c in pw) else None); print("WINVAL_PG_PASSWORD=" + json.dumps(pw, ensure_ascii=False).replace("$", "$$") + "\nWINVAL_PG_PASSWORD_URLENC=" + quote(pw, safe="")) if pw else None')
  if [ -n "$PWLINE" ]; then
    if [ "$check" = yes ]; then echo "compose-env: --check ok ($ETC/compose.env would be derived from winval.env's URL)"; exit 0; fi
    OTHER=$(grep -v '^WINVAL_PG_PASSWORD' "$ETC/compose.env" 2>/dev/null || true)   # READ before the write: a grep in the same pipeline as install raced the recreated (empty) file
    { [ -n "$OTHER" ] && printf '%s\n' "$OTHER"; printf '%s\n' "$PWLINE"; } | install -m 0600 /dev/stdin "$ETC/compose.env"   # the other lines (WINVAL_UPLOAD_MB, WINVAL_SPOOL_SIZE) survive a password change; printf, not echo: dash's echo would eat the backslashes
    echo "compose-env: $ETC/compose.env derived from winval.env's BLASTBOX_DATABASE_URL"
  elif [ "$hand_written" = yes ]; then
    # winval.env's URL is not the compose's Postgres (another scheme, user or no password) and the operator wrote both lines
    # by hand, as told: theirs, left alone. NOTE the shipped compose wires its ingress to ITS Postgres service and nothing else:
    # a pool-manager on a different store never sees the ingress's rows (pool_manager.py: the store must match the ingress)
    echo "compose-env: winval.env's URL is not the compose's Postgres; $ETC/compose.env is hand-written and left alone — the shipped compose's ingress queues into ITS Postgres service, so the pool-manager's store must be that Postgres or the ingress must be yours"
  else   # never an EMPTY compose.env or one with an empty value (the 'winval' fallback password would lock the ingress out)
    echo "winval.env's BLASTBOX_DATABASE_URL is not postgresql://winval:<password>@host...; write BOTH lines to $ETC/compose.env by hand (non-empty) before the compose up: WINVAL_PG_PASSWORD=<the password, double-quoted, \$ as \$\$> and WINVAL_PG_PASSWORD_URLENC=<the same, percent-encoded>" >&2
    exit 1
  fi
fi
