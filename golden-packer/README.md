# win-golden-packer

A **portable, reproducible** builder for a hardened **Windows Server 2025 (Core)** golden image
(`qcow2`) — for KVM/libvirt hosts. Clone, drop in an ISO, run one script. No host-specific setup.

The image installs unattended, enables in-box **OpenSSH** (key-only), and bakes a hardened feature
set via ordered PowerShell provisioners (cert-store sync, Windows Update, WDAC/AppLocker, Defender,
CIS-ish hardening, eval-rearm). It's the *OS base*; layering an application/agent on top is a separate
downstream step.

## Prerequisites

- **Packer** ≥ 1.10 — <https://developer.hashicorp.com/packer/install>
- **qemu-kvm** with **slirp** (user-mode networking). Packer's qemu builder reaches the guest over an
  SSH port-forward through slirp — no bridge/tap/root needed. Verify:
  ```sh
  qemu-system-x86_64 -netdev help | grep -w user     # must print "user"
  ```
  If it doesn't, your qemu was compiled without `libslirp`; install a slirp-enabled qemu. `build.sh`
  checks this and fails early with a clear message.
- **xorriso** (or `genisoimage`/`mkisofs`) — for the answer CD.
- **openssh-client** + **python3** — key generation + answer-file rendering.
- Read/write **`/dev/kvm`** (for acceleration; the build works without it but is very slow).

On Debian/Ubuntu: `apt-get install qemu-system-x86 qemu-utils xorriso openssh-client python3` (+ Packer).

## Use it

```sh
git clone <this-repo> win-golden-packer && cd win-golden-packer

# 1. Drop your Windows Server 2025 ISO here (eval or retail):
cp /path/to/Windows_Server_2025.iso iso/windows.iso     # or: export ISO_PATH=/path/to.iso

# 2. Build (unattended install + provisioners, ~30–60 min):
./build.sh
```

Output: **`output/winserver2025-core.qcow2`**.

Overrides (all optional):
```sh
ADMIN_PASSWORD='Secret#2026!' ./build.sh          # force a specific Administrator password (default: auto-generated random)
ISO_PATH=/mnt/iso/w2025.iso   ./build.sh          # ISO location
./build.sh -var 'memory_mb=8192' -var 'cpus=4'    # any extra arg is passed straight to `packer build`
./build.sh -var 'headless=false'                  # watch the install in a QEMU window
```

## What's in the box

```
winserver2025-core.pkr.hcl      Packer template (qemu builder + SSH + provisioners), fully var-driven
build.sh                        one-shot: prereq checks (incl. slirp) → keygen → render answer → build
answer/Autounattend.xml.tmpl    unattended-install template; build.sh injects the build pubkey + password
variables.pkrvars.hcl.example   optional var file (copy to variables.auto.pkvars.hcl to persist settings)
scripts/                        ordered PowerShell provisioners (10-openssh … 90-defender)
iso/                            drop your Windows + (optional) virtio ISOs here  (gitignored)
keys/                           throwaway per-build ed25519 keypair, auto-generated  (gitignored)
output/                         build output qcow2  (gitignored)
```

## How it works

1. `build.sh` verifies prerequisites (the **slirp** check is the one that trips people up), generates a
   **throwaway ed25519 keypair** + a **strong random Administrator password** (unless `ADMIN_PASSWORD`
   is set), both saved under `keys/` (gitignored), and renders `answer/Autounattend.xml` from the template,
   substituting that build pubkey + the Administrator password.
2. Packer boots the ISO with the answer file on an **OEMDRV** CD → unattended WS2025-Core install →
   first-boot enables OpenSSH and installs the build pubkey.
3. Packer connects over SSH (via slirp port-forward, **key-only**) and runs the provisioners: OpenSSH
   hardening, then **Windows Update in an install→reboot loop** (so cumulative/servicing-stack updates
   fully apply), then the feature-bake steps, ending with **95-freeze-windows-update** which disables WU
   in the image.
4. Clean shutdown → `output/winserver2025-core.qcow2`.

The keypair is **per-build and disposable** — nothing is hardcoded. Rotate the golden's real access
key downstream if you deploy it.

## Notes / gotchas

- **Image index**: `answer/Autounattend.xml.tmpl` installs `/IMAGE/INDEX = 1` (Server Standard Core).
  Change it for Desktop Experience / Datacenter.
- **Eval ISO**: the WS2025 eval ISO works; `80-eval-rearm.ps1` re-arms the 180-day eval. For retail,
  add a product key in the autounattend `<UserData>`.
- **`x86_64` template**: this builds an x86_64 golden. (For an ARM64 golden — e.g. targeting managed
  microVM runtimes — the machine type / ISO / arch would need adjusting.)
- **Windows Update**: applied at build time in an **install→reboot loop** (`20-windows-update.ps1` ×3
  with `windows-restart` between), so the golden ships fully patched. The **deployed image then has WU
  frozen** (`95-freeze-windows-update.ps1`: `NoAutoUpdate=1`, WU/UsoSvc/WaaSMedic disabled, update tasks
  off) — a disposable analysis VM stays deterministic and won't self-patch or phone home mid-job.
  Re-patch by **rebuilding** the golden, not at runtime.
- **SSH is key-only**: `10-openssh-harden.ps1` forces `PasswordAuthentication no`; the Packer build
  itself authenticates with the generated key (no `ssh_password`).
- **Not portable, by design**: the large ISOs (`iso/`) and the build output are gitignored — you supply
  the ISO; the repo supplies everything else.
