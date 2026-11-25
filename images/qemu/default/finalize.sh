#!/bin/sh
# The QEMU build's last command (Packer's shutdown_command), as root in the
# builder guest (../README.md): applies the static management profile,
# removes every build trace and instance identity, then powers off. The
# profile is applied only now so the build's own SSH session is never
# reconfigured. Nothing here contacts the network.
set -eu

context=/var/tmp/agentbox-build
profile="$context/qemu/profile"

# The build boot's SSH host private keys in $1, each overwritten in place
# with zeros before its removal (../README.md), so that their deleted
# blocks are not left holding them; the published disk is scanned natively.
# Only a regular file with one link; anything else refuses and fails the
# build.
scrub_host_keys() {
  for key in "$1"/ssh_host_*_key; do
    test -e "$key" || test -L "$key" || continue
    if test -L "$key" || ! test -f "$key" || test "$(stat -c %h "$key")" != 1; then
      echo "agentbox-finalize refused: host_key" >&2
      exit 1
    fi
    shred -n 0 -z "$key"
  done
}

test "$(id -u)" = 0

# Static root-managed NoCloud profile: per-boot identities come from each
# execution's seed (QEMU provider, plan step 3), never from this image.
install -D -m 0644 -o 0 -g 0 "$profile/99-agentbox.cfg" /etc/cloud/cloud.cfg.d/99-agentbox.cfg
install -D -m 0644 -o 0 -g 0 "$profile/00-agentbox.conf" /etc/ssh/sshd_config.d/00-agentbox.conf
install -D -m 0644 -o 0 -g 0 "$profile/10-agentbox-identity.conf" \
  /etc/systemd/system/ssh.service.d/10-agentbox-identity.conf
# The socket must not listen before the initialized service starts; Ubuntu's
# strong ssh.service -> ssh.socket dependency goes with it.
ln -sfn /dev/null /etc/systemd/system/ssh.socket
for dep in /etc/systemd/system/ssh.service.requires/ssh.socket \
           /etc/systemd/system/sockets.target.wants/ssh.socket; do
  if test -L "$dep"; then
    case "$(readlink "$dep")" in
      /lib/systemd/system/ssh.socket|/usr/lib/systemd/system/ssh.socket) rm -f "$dep" ;;
      *) echo "agentbox-finalize refused: socket_dependency" >&2; exit 1 ;;
    esac
  fi
done
mkdir -p /etc/systemd/system/multi-user.target.wants
ln -sfn /usr/lib/systemd/system/ssh.service /etc/systemd/system/multi-user.target.wants/ssh.service

# Build state, the build account and its credentials.
rm -rf "$context"
userdel --force --remove agentbox-build
rm -f /etc/sudoers.d/90-cloud-init-users
rm -rf /root/.ssh /root/.cache /root/.npm /root/.bash_history

# Instance identity of the build boot.
cloud-init clean --logs --seed
rm -rf /var/lib/cloud
scrub_host_keys /etc/ssh
rm -f /etc/ssh/ssh_host_* /var/lib/dbus/machine-id /var/lib/systemd/random-seed
: > /etc/machine-id
rm -rf /var/lib/dhcp/* /var/lib/systemd/network/* 2>/dev/null || true

# Logs and temporary files.
find /var/log -type f -exec truncate -s 0 {} +
rm -rf /var/log/journal/* /tmp/* /tmp/.[!.]* /var/tmp/* /var/tmp/.[!.]* 2>/dev/null || true
sync
exec /usr/bin/systemctl poweroff
