#!/bin/sh
# Derive /etc/winval/compose.env from winval.env's BLASTBOX_DATABASE_URL — run as root (the bring-up and
# deploy/upgrade.sh both call it). compose.env carries the SAME password in the two forms compose needs
# (the URL in winval.env is the source of truth — also when you wrote that line yourself); written 0600
# from the first byte, never tee-then-chmod; DERIVED every time it disagrees (missing, written before the
# encoded form existed, or the URL was edited). Postgres keeps whatever password its volume was initialised
# with: to change the password for real, `down -v` first, then edit the URL.
set -eu
ETC="${WINVAL_ETC:-/etc/winval}"
[ -f "$ETC/winval.env" ] || { echo "compose-env: $ETC/winval.env does not exist" >&2; exit 1; }
if ! grep -q '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env"; then
  PW=$(openssl rand -hex 16)
  echo "BLASTBOX_DATABASE_URL=postgresql://winval:$PW@127.0.0.1:5433/winval" >> "$ETC/winval.env"
fi
WANT_URLENC=$(grep '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env" | tail -1 | cut -d= -f2- | python3 -c 'import sys; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); print(quote(unquote(u.password), safe="")) if u.password else None')
if ! test -f "$ETC/compose.env" || [ "$(sed -n 's/^WINVAL_PG_PASSWORD_URLENC=//p' "$ETC/compose.env")" != "$WANT_URLENC" ]; then   # a MISSING compose.env is derived too
  # the password is URL-DECODED (a percent-encoded '@' or '#' in the URL is the literal char Postgres must be initialised
  # with; both clients decode it the same way). Two forms: the literal password (written as a JSON/double-quoted string —
  # compose's env file understands \" and \\ inside double quotes — with '$' as '$$', because compose interpolates its env
  # file and a bare '$' would truncate the secret) and the percent-encoded one (the ingress embeds it in a URL)
  PWLINE=$(grep '^BLASTBOX_DATABASE_URL=' "$ETC/winval.env" | tail -1 | cut -d= -f2- | python3 -c 'import sys, json; from urllib.parse import urlsplit, unquote, quote; u = urlsplit(sys.stdin.read().strip()); pw = unquote(u.password) if u.scheme.startswith("postgres") and u.username == "winval" and u.password else None; (sys.exit("the password contains control characters, which compose'"'"'s env file cannot carry; choose another") if pw and any(ord(c) < 32 or ord(c) == 127 for c in pw) else None); print("WINVAL_PG_PASSWORD=" + json.dumps(pw, ensure_ascii=False).replace("$", "$$") + "\nWINVAL_PG_PASSWORD_URLENC=" + quote(pw, safe="")) if pw else None')
  if [ -n "$PWLINE" ]; then
    OTHER=$(grep -v '^WINVAL_PG_PASSWORD' "$ETC/compose.env" 2>/dev/null || true)   # READ before the write: a grep in the same pipeline as install raced the recreated (empty) file
    { [ -n "$OTHER" ] && printf '%s\n' "$OTHER"; printf '%s\n' "$PWLINE"; } | install -m 0600 /dev/stdin "$ETC/compose.env"   # the other lines (WINVAL_UPLOAD_MB, WINVAL_SPOOL_SIZE) survive a password change; printf, not echo: dash's echo would eat the backslashes
    echo "compose-env: $ETC/compose.env derived from winval.env's BLASTBOX_DATABASE_URL"
  else   # never an EMPTY compose.env (the fallback password would lock the ingress out)
    echo "winval.env's BLASTBOX_DATABASE_URL is not postgresql://winval:<password>@host...; write BOTH lines to $ETC/compose.env by hand before the compose up: WINVAL_PG_PASSWORD=<the password, double-quoted, \$ as \$\$> and WINVAL_PG_PASSWORD_URLENC=<the same, percent-encoded>" >&2
    exit 1
  fi
else
  echo "compose-env: $ETC/compose.env already matches winval.env"
fi
