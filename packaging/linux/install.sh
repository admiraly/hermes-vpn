#!/usr/bin/env bash
# Install (or remove) the Hermes daemon + CLI as a systemd service.
#
#   sudo ./install.sh [BIN_DIR]     install from BIN_DIR (default: the
#                                   directory holding this script, else
#                                   target/release)
#   sudo ./install.sh --uninstall   stop and remove the service
#
# The invoking user (via sudo) is added to the `hermes` group, which is
# what grants access to the daemon. Log out and back in for that to apply.
set -euo pipefail

[ "$(id -u)" = 0 ] || { echo "run with sudo" >&2; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
UNIT=/etc/systemd/system/hermes-daemon.service

if [ "${1:-}" = --uninstall ]; then
  systemctl disable --now hermes-daemon 2>/dev/null || true
  rm -f "$UNIT" /usr/local/bin/hermes-daemon /usr/local/bin/hermes /etc/modules-load.d/hermes.conf
  systemctl daemon-reload
  echo "Hermes removed. State in /var/lib/hermes and the 'hermes' user/group were kept;"
  echo "delete them with: sudo rm -rf /var/lib/hermes && sudo userdel hermes"
  exit 0
fi

BIN_DIR=${1:-}
if [ -z "$BIN_DIR" ]; then
  if [ -x "$HERE/hermes-daemon" ]; then BIN_DIR=$HERE; else BIN_DIR=$HERE/../../target/release; fi
fi
for b in hermes-daemon hermes; do
  [ -x "$BIN_DIR/$b" ] || { echo "missing $BIN_DIR/$b (build with: cargo build --release -p hermes-daemon -p hermes-cli)" >&2; exit 1; }
done

# Service account and access group.
getent group hermes >/dev/null || groupadd --system hermes
id -u hermes >/dev/null 2>&1 ||
  useradd --system --gid hermes --no-create-home --home-dir /var/lib/hermes \
          --shell /usr/sbin/nologin hermes

# TUN/TAP support, now and at boot.
modprobe tun || true
echo tun > /etc/modules-load.d/hermes.conf
# The service runs unprivileged: CAP_NET_ADMIN alone can't open a device
# node it has no permission on. Distros ship /dev/net/tun as 0666 via
# udev; make sure that holds here (some minimal images use 0600).
if [ -c /dev/net/tun ] && [ "$(stat -c %a /dev/net/tun)" != 666 ]; then
  echo "Setting /dev/net/tun to mode 0666 (was $(stat -c %a /dev/net/tun))"
  chmod 0666 /dev/net/tun
  echo 'KERNEL=="tun", GROUP="root", MODE="0666"' > /etc/udev/rules.d/70-hermes-tun.rules
fi

install -m 0755 "$BIN_DIR/hermes-daemon" "$BIN_DIR/hermes" /usr/local/bin/
install -m 0644 "$HERE/hermes-daemon.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now hermes-daemon
systemctl restart hermes-daemon # pick up a new binary on upgrade

if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
  usermod -aG hermes "$SUDO_USER"
  echo "Added $SUDO_USER to the 'hermes' group — log out and back in, then run: hermes status"
else
  echo "Add users who may use Hermes to the 'hermes' group: sudo usermod -aG hermes <user>"
fi
systemctl --no-pager --lines=3 status hermes-daemon || true
