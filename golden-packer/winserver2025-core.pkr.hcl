# Portable Windows Server 2025 (Core) golden builder.
#
# Boots the WS2025 ISO with an attached autounattend CD (OEMDRV), does an unattended Core install,
# connects over in-box OpenSSH using a throwaway per-build keypair, runs the ordered PowerShell
# provisioners, powers off -> output/winserver2025-core.qcow2.
#
# Networking: Packer's qemu builder uses slirp (user-mode NAT) + an SSH port-forward to reach the
# guest. No bridge/tap/root needed. If your qemu is compiled WITHOUT slirp, the build can't reach
# the guest -- build.sh checks for this up front. See README.md.
#
# Drive everything through ./build.sh (generates the key, renders the answer file, runs this).

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = ">= 1.0.0"
    }
  }
}

variable "iso_path" { type = string }                          # your WS2025 ISO (build.sh passes it)

variable "iso_checksum" {                                      # "none" skips; or "sha256:<hex>"
  type    = string
  default = "none"
}
variable "admin_password" {                                    # required — build.sh generates a random
  type      = string                                          # one per build (or set ADMIN_PASSWORD)
  sensitive = true
}
variable "ssh_key_file" {                                      # throwaway per-build private key
  type    = string
  default = "keys/build_key"
}
variable "disk_size_mb" {                                      # 80 GB — WS2025 + large cumulative + WinSxS
  type    = number
  default = 81920
}
variable "memory_mb" {                                         # WS2025 update *finalization* (TrustedInstaller)
  type    = number                                            # is slow on little RAM; a fat cumulative needs headroom
  default = 8192
}
variable "cpus" {                                             # more cores = TiWorker finalizes the giant
  type    = number                                           # cumulative fast enough to fit the WU plugin's window
  default = 4
}
variable "headless" {
  type    = bool
  default = true
}
variable "output_dir" {
  type    = string
  default = "output"
}
variable "qemu_binary" {                                       # override for hosts whose system qemu
  type    = string                                             # lacks slirp (build.sh passes QEMU_BINARY)
  default = "qemu-system-x86_64"
}
variable "cpu_model" {                                         # modern WS2025 WinPE hangs on qemu's
  type    = string                                             # default qemu64 CPU under recent qemu;
  default = "host"                                             # pass the real host CPU (needs KVM)
}

source "qemu" "w2025core" {
  iso_url              = var.iso_path
  iso_checksum         = var.iso_checksum
  output_directory     = var.output_dir
  vm_name              = "winserver2025-core.qcow2"
  format               = "qcow2"
  qemu_binary          = var.qemu_binary
  accelerator          = "kvm"
  qemuargs             = [["-cpu", var.cpu_model]]                 # WS2025 WinPE needs real CPU features
  machine_type         = "pc"
  disk_interface       = "ide"
  disk_size            = "${var.disk_size_mb}M"
  memory               = var.memory_mb
  cpus                 = var.cpus
  net_device           = "e1000"
  headless             = var.headless
  boot_wait            = "3s"
  boot_command         = ["<enter><wait2><enter><wait2><enter>"]   # dismiss "press any key to boot from CD"
  cd_files             = ["answer/Autounattend.xml"]               # Packer builds the OEMDRV answer CD
  cd_label             = "OEMDRV"
  communicator         = "ssh"
  ssh_username         = "Administrator"
  ssh_private_key_file = var.ssh_key_file                          # KEY-ONLY: no ssh_password. The
  ssh_timeout          = "120m"                                    # autounattend installs this pubkey at
                                                                   # first boot; 10-openssh-harden then
                                                                   # disables password auth in the image.
  shutdown_command     = "shutdown /s /t 10 /f /d p:4:1 /c packer"
}

build {
  sources = ["source.qemu.w2025core"]

  provisioner "powershell" { scripts = ["scripts/10-openssh-harden.ps1"] }

  # Windows Update via PSWindowsUpdate's Invoke-WUJob (install as a local SYSTEM task; Packer owns the
  # reboot). SINGLE best-effort pass + one reboot. KB5094125 (the ~22GB checkpoint cumulative) is
  # excluded inside the script via -NotTitle: PROVEN that including it fails the build -- its
  # finalization forces an uncontrolled reboot mid-provisioner that kills the SSH session (exit
  # 2300218). For a fully-patched golden, build from a pre-integrated VLSC/MSDN base ISO instead.
  provisioner "powershell"      { scripts = ["scripts/20-windows-update.ps1"] }
  provisioner "windows-restart" { restart_timeout = "120m" }

  # Feature-bake provisioners. 95-freeze-windows-update MUST be last — it freezes WU in the deployed
  # image AFTER all patching + the rest of the golden is baked (disposable VMs stay deterministic).
  provisioner "powershell" {
    scripts = [
      "scripts/30-cert-store-sync.ps1",
      "scripts/40-authenticode-selftest.ps1",
      "scripts/50-graveyard-task.ps1",
      "scripts/60-wdac-applocker.ps1",
      "scripts/70-hardening.ps1",
      "scripts/80-eval-rearm.ps1",
      "scripts/90-defender.ps1",
      "scripts/95-freeze-windows-update.ps1",
    ]
  }
}
