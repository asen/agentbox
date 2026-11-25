# The canonical Agentbox QEMU image recipe (../README.md). Boots the
# verified Ubuntu cloud disk once under KVM with a build-only NoCloud seed,
# uploads the staged context over the build's inbound SSH/SFTP, upgrades the
# system with stock APT over the build network, assembles the worker from
# source inside the guest, then removes every build trace and publishes a
# standalone qcow2 plus metadata. Inputs come only from stage.py's output
# (agentbox.pkrvars.hcl). The build network (`build_network`, below) is this
# recipe's alone: the runtime's NIC stays restricted, and a custom recipe
# has whatever its own qemuargs say. No HTTP server, no host share, no host
# secret, no agent forwarding.
#
#   python3 -I images/worker/stage.py qemu --repo . --inputs INPUTS --out STAGE
#   packer build -var-file STAGE/agentbox.pkrvars.hcl images/qemu/default/agentbox.pkr.hcl
#   python3 -I images/worker/stage.py publish --stage STAGE --output STAGE/output

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1.1"
    }
  }
}

variable "base_image" {
  type        = string
  description = "Absolute path of the verified base cloud disk (stage.py)."
}

variable "base_sha256" {
  type = string
}

variable "context" {
  type        = string
  description = "stage.py's context directory: uploaded, never secrets."
}

variable "seed" {
  type        = string
  description = "stage.py's build-only NoCloud seed (user-data, meta-data)."
}

variable "build_key" {
  type        = string
  description = "stage.py's build-only private key; host-only, never uploaded."
  sensitive   = true
}

variable "output" {
  type = string
}

# The build's network, apart from the provisioning commands. `nat`: QEMU
# user-mode networking without `restrict`: the guest reaches whatever this
# host can (the internet, its LAN and VPN) and, through the gateway
# 10.0.2.2, the host's own loopback services. Plus the one inbound forward
# from host loopback to the guest's sshd.
variable "build_network" {
  type    = string
  default = "nat"
  validation {
    condition     = contains(["nat"], var.build_network)
    error_message = "The build network: nat."
  }
}

locals {
  netdev = {
    nat = "user,id=agentbox0,ipv4=on,ipv6=off,hostfwd=tcp:127.0.0.1:{{ .SSHHostPort }}-:22"
  }
}

source "qemu" "agentbox" {
  iso_url          = "file://${var.base_image}"
  iso_checksum     = "sha256:${var.base_sha256}"
  disk_image       = true
  use_backing_file = false
  format           = "qcow2"
  disk_size        = "8192M"
  disk_interface   = "virtio"
  accelerator      = "kvm"
  cpus             = 2
  memory           = 4096
  headless         = true
  vnc_bind_address = "127.0.0.1"
  output_directory = var.output
  vm_name          = "agentbox.qcow2"

  cd_files = ["${var.seed}/user-data", "${var.seed}/meta-data"]
  cd_label = "cidata"

  host_port_min = 22000
  host_port_max = 22999
  # The runtime's CPU model (the provider's qemu_argv: -cpu host), not
  # QEMU's qemu64: the agents' start check runs their native builds here
  # (Claude Code's needs SSE4.2).
  qemuargs = [
    ["-cpu", "host"],
    ["-netdev", local.netdev[var.build_network]],
    ["-device", "virtio-net,netdev=agentbox0"],
  ]

  communicator                 = "ssh"
  ssh_host                     = "127.0.0.1"
  ssh_username                 = "agentbox-build"
  ssh_private_key_file         = var.build_key
  ssh_file_transfer_method     = "sftp"
  ssh_timeout                  = "15m"
  ssh_agent_auth               = false
  ssh_disable_agent_forwarding = true

  shutdown_command = "sudo -n /bin/sh /var/tmp/agentbox-build/qemu/finalize.sh"
  shutdown_timeout = "10m"
}

build {
  sources = ["source.qemu.agentbox"]

  provisioner "shell" {
    inline = ["install -d -m 0700 /var/tmp/agentbox-build"]
  }

  provisioner "file" {
    source      = "${var.context}/"
    destination = "/var/tmp/agentbox-build"
  }

  provisioner "shell" {
    inline = ["sudo -n /usr/bin/python3 -I -B /var/tmp/agentbox-build/qemu/guest-install.py"]
  }

  # The built bundle, its metadata and the system record, for the host,
  # each to its exact path beside the disk (stage.py publish): the metadata
  # lets the host verify the baked worker without a payload copy; the
  # bundle is the same bytes for a supplied SSH jail's upload. Packer picks a directory download by
  # the source's syntax (a trailing '/'), not the remote file type; the
  # recursive SCP lands worker/ at output/worker.
  provisioner "file" {
    direction   = "download"
    source      = "/var/tmp/agentbox-build/out/worker/"
    destination = "${var.output}/"
  }

  provisioner "file" {
    direction   = "download"
    source      = "/var/tmp/agentbox-build/out/worker-metadata.json"
    destination = "${var.output}/worker-metadata.json"
  }

  provisioner "file" {
    direction   = "download"
    source      = "/var/tmp/agentbox-build/out/image-manifest.json"
    destination = "${var.output}/image-manifest.json"
  }

  post-processor "manifest" {
    output     = "${var.output}/packer-manifest.json"
    strip_path = true
  }
}
