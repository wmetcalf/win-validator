#!/usr/bin/env bash
# Portable WS2025 golden build: drop an ISO in iso/, run this. No toolz-specific setup.
#
#   ISO_PATH=/path/to/win2025.iso ./build.sh          # or drop it at iso/windows.iso
#   ADMIN_PASSWORD='Secret#123' ./build.sh            # override the default password
#   ./build.sh -var 'memory_mb=8192' -var 'cpus=4'    # extra args pass straight to `packer build`
#
# Produces: output/winserver2025-core.qcow2
set -euo pipefail
cd "$(dirname "$0")"

say() { printf '\033[1;36m>>> %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# ---- prerequisites --------------------------------------------------------------------------------
command -v packer            >/dev/null || die "packer not installed — https://developer.hashicorp.com/packer/install"
command -v ssh-keygen        >/dev/null || die "ssh-keygen not found (openssh-client)"
command -v python3           >/dev/null || die "python3 not found (used to render the answer file safely)"
command -v xorriso >/dev/null || command -v genisoimage >/dev/null || command -v mkisofs >/dev/null \
    || die "need one of xorriso / genisoimage / mkisofs (for the answer CD)"

# Resolve the qemu binary. Override with QEMU_BINARY=/path if your system qemu lacks slirp.
QEMU="${QEMU_BINARY:-qemu-system-x86_64}"
command -v "$QEMU" >/dev/null 2>&1 || [ -x "$QEMU" ] || die "qemu not found: '$QEMU' (install qemu-kvm, or set QEMU_BINARY=/path)"

# The gotcha that bites people: a qemu compiled WITHOUT slirp (libslirp) can't do Packer's user-mode
# networking. Crucially, `-netdev help` LISTS 'user' even when it's compiled OUT — so test it FOR REAL.
# a slirp-enabled qemu ACCEPTS the netdev and then sits in its main loop forever — nothing asks it to
# quit — so the probe feeds it `quit` on a stdio monitor (a qemu without slirp rejects the option
# before the monitor exists) and is bounded by a timeout either way
# (captured first, then grepped: under `set -o pipefail` a slirp-less qemu's exit 1 made the whole
# pipeline non-zero even when grep matched, so the check could never fire)
slirp_probe="$(printf 'quit\n' | timeout 30 "$QEMU" -machine none -display none -monitor stdio -netdev user,id=slirptest 2>&1 || true)"
if printf '%s' "$slirp_probe" | grep -qi "not compiled"; then
    die "'$QEMU' has no slirp (user-mode networking) compiled in — Packer's qemu builder can't reach
       the guest. Install a slirp-enabled qemu, or point QEMU_BINARY at one (e.g. a stock Ubuntu qemu)."
fi
[ -w /dev/kvm ] || { echo "ERROR: /dev/kvm is not writable. The template needs KVM (accelerator = \"kvm\", -cpu host; there is no TCG fallback): run on a KVM-capable host, or add this user to the kvm group." >&2; exit 1; }

# ---- inputs ---------------------------------------------------------------------------------------
ISO="${ISO_PATH:-iso/windows.iso}"
[ -f "$ISO" ] || die "no Windows Server 2025 ISO at '$ISO'. Drop one at iso/windows.iso or set ISO_PATH=/path/to.iso"
mkdir -p keys

# ---- Administrator password: use ADMIN_PASSWORD if set, else generate a strong random one ----------
if [ -n "${ADMIN_PASSWORD:-}" ]; then
    ADMIN_PW="$ADMIN_PASSWORD"
else
    # 20 chars, cryptographically random, guaranteed to meet Windows complexity (upper/lower/digit/
    # special), from an XML- and shell-safe charset (no < > & " ' $ ` \ | / that would break the
    # answer file or the shell).
    ADMIN_PW="$(python3 - <<'PY'
import secrets, string
special = "!@#%^*-_=+"
alphabet = string.ascii_letters + string.digits + special
while True:
    pw = "".join(secrets.choice(alphabet) for _ in range(20))
    if (any(c.isupper() for c in pw) and any(c.islower() for c in pw)
            and any(c.isdigit() for c in pw) and any(c in special for c in pw)):
        print(pw); break
PY
)"
    ( umask 077; printf '%s\n' "$ADMIN_PW" > keys/admin_password.txt )
    say "generated random Administrator password -> keys/admin_password.txt"
fi

# ---- throwaway per-build SSH keypair --------------------------------------------------------------
if [ ! -f keys/build_key ]; then
    ssh-keygen -t ed25519 -N '' -C 'win-golden-build' -f keys/build_key >/dev/null
    say "generated throwaway build key: keys/build_key(.pub)"
fi
PUBKEY="$(cat keys/build_key.pub)"

# ---- render the answer file (XML-escaped substitution, then parsed back: an operator ADMIN_PASSWORD with
#      & < or > used to land raw in two <Value> elements, and Windows Setup silently ignores an unparseable
#      Autounattend — the failure surfaced only as packer waiting out ssh_timeout) ---------------------
PUBKEY="$PUBKEY" ADMIN_PW="$ADMIN_PW" python3 - <<'PY'
import os, sys, xml.etree.ElementTree as ET
from xml.sax.saxutils import escape
t = open("answer/Autounattend.xml.tmpl", encoding="utf-8").read()
pubkey = os.environ["PUBKEY"].replace("'", "''")   # the key lands inside a PowerShell single-quoted string: an apostrophe in a supplied key's comment doubles
if '"' in pubkey:   # the key lands inside a -Command "..." in the answer file, and Windows Setup decodes any XML entity back to the quote before
    # the command runs: no escape survives, so a quote (a key comment) is refused by name rather than ending the command early (no authorized
    # key, the ssh_timeout burned). The password lands in a plain <Value> element and needs no such care
    sys.exit("the SSH public key contains a double quote (in its comment?): the answer file's -Command cannot carry it; strip it from the key")
t = t.replace("@@SSH_PUBKEY@@", escape(pubkey)).replace("@@ADMIN_PASSWORD@@", escape(os.environ["ADMIN_PW"]))
try:
    ET.fromstring(t)
    data = t.encode("utf-8")   # a value the environment could not decode (not UTF-8) is refused here, not as a traceback
except (ET.ParseError, UnicodeError) as exc:
    sys.exit(f"rendered Autounattend.xml is not well-formed UTF-8 XML ({exc}); refusing to build with it")
fd = os.open("answer/Autounattend.xml", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)   # it carries the Administrator password: 0600, like keys/admin_password.txt
os.chmod(fd, 0o600)   # an existing file from an earlier render keeps its old mode otherwise
os.write(fd, data); os.close(fd)
PY
say "rendered answer/Autounattend.xml"

# ---- build ----------------------------------------------------------------------------------------
say "packer init"
packer init winserver2025-core.pkr.hcl
say "built image creds:  Administrator / ${ADMIN_PW}   (also in keys/admin_password.txt; ssh key keys/build_key)"
say "packer build  (ISO=$ISO)  — unattended install + provisioners, ~30-60 min"
exec packer build \
    -var "iso_path=${ISO}" \
    -var "admin_password=${ADMIN_PW}" \
    -var "ssh_key_file=keys/build_key" \
    -var "qemu_binary=${QEMU}" \
    "$@" \
    winserver2025-core.pkr.hcl
