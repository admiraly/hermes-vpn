#!/usr/bin/env bash
# End-to-end smoke test on one Linux box: two network namespaces play two
# machines, each running a real hermes-daemon with a real TAP adapter; the
# root namespace runs hermes-signaling + hermes-relay and routes between
# them. Exercises everything the unit/e2e tests can't: kernel adapters,
# daemon lifecycle, the CLI, ARP across the virtual LAN, and MTU.
#
# Usage (as root, after `cargo build --workspace --exclude hermes-ui`):
#   scripts/netns-smoke.sh relayed     # all traffic via the relay
#   scripts/netns-smoke.sh p2p         # direct path
#   scripts/netns-smoke.sh fallback    # direct path firewalled → relay fallback
#   scripts/netns-smoke.sh restart     # p2p room survives a signaling restart
#   scripts/netns-smoke.sh service     # node A runs like the systemd unit: as the
#                                      # unprivileged `hermes` user with only
#                                      # CAP_NET_ADMIN, driven by another user
#                                      # through the group-shared system socket
#   scripts/netns-smoke.sh clean       # tear everything down
#
# Needs: iproute2, iputils-ping, iptables (fallback mode).
set -u
MODE=${1:-relayed}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
BIN=${BIN:-$ROOT/target/debug}
WORK=${WORK:-/tmp/hermes-smoke}
RELAY=10.200.1.1:8788

cleanup() {
  pkill -x hermes-daemon 2>/dev/null
  pkill -x hermes-relay 2>/dev/null
  pkill -x hermes-signalin 2>/dev/null # comm is truncated to 15 chars
  iptables -D FORWARD -s 10.200.1.0/24 -d 10.200.2.0/24 -j DROP 2>/dev/null
  iptables -D FORWARD -s 10.200.2.0/24 -d 10.200.1.0/24 -j DROP 2>/dev/null
  while iptables -D FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT 2>/dev/null; do :; done
  rm -rf /run/hermes
  for n in a b; do
    ip link del veth-$n 2>/dev/null
    ip netns del hermes-$n 2>/dev/null
  done
  # Namespace teardown is asynchronous; wait for the veths to disappear
  # so an immediate re-run can recreate them.
  for _ in $(seq 1 20); do
    ip link show veth-a >/dev/null 2>&1 || ip link show veth-b >/dev/null 2>&1 || break
    sleep 0.1
  done
}
cleanup
[ "$MODE" = clean ] && exit 0

# --- topology -------------------------------------------------------------
sysctl -qw net.ipv4.ip_forward=1
# Hosts with Docker (e.g. GitHub's runners) default FORWARD to DROP; allow
# our own A<->B traffic explicitly (fallback mode inserts DROPs above this).
iptables -I FORWARD -s 10.200.0.0/16 -d 10.200.0.0/16 -j ACCEPT 2>/dev/null || true
i=1
for n in a b; do
  ip netns add hermes-$n
  ip link add veth-$n type veth peer name eth0 netns hermes-$n
  ip addr add 10.200.$i.1/24 dev veth-$n
  ip link set veth-$n up
  ip -n hermes-$n addr add 10.200.$i.2/24 dev eth0
  ip -n hermes-$n link set eth0 up
  ip -n hermes-$n link set lo up
  ip -n hermes-$n route add default via 10.200.$i.1
  i=$((i + 1))
done
if [ "$MODE" = fallback ]; then
  # Block direct A<->B so only the relay path works (symmetric-NAT stand-in).
  iptables -I FORWARD -s 10.200.1.0/24 -d 10.200.2.0/24 -j DROP
  iptables -I FORWARD -s 10.200.2.0/24 -d 10.200.1.0/24 -j DROP
fi

# --- servers + daemons ------------------------------------------------------
rm -rf "$WORK"; mkdir -p "$WORK/a" "$WORK/b" /run/hermes-smoke-a /run/hermes-smoke-b
if [ "$MODE" = service ]; then
  # Unprivileged users must be able to execute the binaries; the checkout
  # may sit under a private home directory (GitHub's runners: 0750). Stage
  # them like install.sh does with /usr/local/bin.
  install -d -m 0755 "$WORK/bin"
  install -m 0755 "$BIN"/hermes "$BIN"/hermes-daemon "$BIN"/hermes-relay "$BIN"/hermes-signaling "$WORK/bin/"
  chmod 0755 "$WORK"
  BIN=$WORK/bin
fi
export RUST_LOG=${RUST_LOG:-info}
start_signaling() {
  HERMES_SIGNALING_BIND=0.0.0.0:8787 "$BIN/hermes-signaling" >>"$WORK/signaling.log" 2>&1 &
}
start_signaling
# Wildcard bind on purpose: the root namespace is multi-homed (one address
# per veth), and B reaches the relay via A's side address — the relay must
# still answer B from the address B sent to.
HERMES_RELAY_BIND=${RELAY_BIND:-0.0.0.0:8788} "$BIN/hermes-relay" >"$WORK/relay.log" 2>&1 &
sleep 0.5
run() { local n=$1; shift; ip netns exec hermes-$n env HOME="$WORK/$n" XDG_RUNTIME_DIR=/run/hermes-smoke-$n "$@"; }
if [ "$MODE" = service ]; then
  # Mirror packaging/linux/hermes-daemon.service: system user `hermes`,
  # RuntimeDirectory=/run/hermes (0750), StateDirectory, ambient
  # CAP_NET_ADMIN only. The CLI runs as `hermes-smoke-user`, a plain user
  # whose only privilege is membership in the `hermes` group.
  getent group hermes >/dev/null || groupadd --system hermes
  id -u hermes >/dev/null 2>&1 || useradd --system --gid hermes --no-create-home --shell /usr/sbin/nologin hermes
  id -u hermes-smoke-user >/dev/null 2>&1 || useradd --no-create-home --shell /bin/sh hermes-smoke-user
  usermod -aG hermes hermes-smoke-user
  install -d -o hermes -g hermes -m 0750 /run/hermes
  # Distros ship /dev/net/tun as 0666 (udev); some containers make it 0600,
  # which only root could open.
  chmod 0666 /dev/net/tun
  install -d -o hermes -g hermes -m 0700 "$WORK/a-state"
  ip netns exec hermes-a env STATE_DIRECTORY="$WORK/a-state" \
    setpriv --reuid hermes --regid hermes --init-groups \
      --inh-caps +net_admin --ambient-caps +net_admin --bounding-set -all,+net_admin \
      "$BIN/hermes-daemon" --system >"$WORK/daemon-a.log" 2>&1 &
  # Node A's CLI: an ordinary group member, no env overrides — it must
  # find the system socket on its own.
  run() {
    local n=$1; shift
    if [ "$n" = a ]; then
      ip netns exec hermes-a setpriv --reuid hermes-smoke-user --regid hermes-smoke-user --init-groups \
        env -i PATH=/usr/bin:/bin HOME=/nonexistent "$@"
    else
      ip netns exec hermes-$n env HOME="$WORK/$n" XDG_RUNTIME_DIR=/run/hermes-smoke-$n "$@"
    fi
  }
else
  run a "$BIN/hermes-daemon" >"$WORK/daemon-a.log" 2>&1 &
fi
run b "$BIN/hermes-daemon" >"$WORK/daemon-b.log" 2>&1 &
sleep 1

run a "$BIN/hermes" add-server signaling main ws://10.200.1.1:8787/v1 >/dev/null
run b "$BIN/hermes" add-server signaling main ws://10.200.2.1:8787/v1 >/dev/null
for n in a b; do run $n "$BIN/hermes" use-signaling main >/dev/null; run $n "$BIN/hermes" connect || exit 1; done

case $MODE in
  relayed) ARGS=(--mode relayed --relay $RELAY); WANT=relayed ;;
  p2p | restart | service) ARGS=(--mode p2p); WANT=direct ;;
  fallback) ARGS=(--mode p2p --relay $RELAY); WANT=relayed ;;
  *) echo "unknown mode $MODE"; exit 2 ;;
esac
OUT=$(run a timeout 15 "$BIN/hermes" create smoke "${ARGS[@]}") || { echo "$OUT"; exit 1; }
CODE=$(echo "$OUT" | grep -oE '[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}' | head -1)
run b timeout 15 "$BIN/hermes" join "$CODE" >/dev/null || exit 1

# --- wait for the path, then prove it carries traffic -----------------------
# Both sides decide their path independently; wait until both agree.
for _ in $(seq 1 30); do
  run a "$BIN/hermes" status | grep -q " $WANT " &&
    run b "$BIN/hermes" status | grep -q " $WANT " && break
  sleep 1
done
run a "$BIN/hermes" status
PEER_IP=$(run a "$BIN/hermes" status | grep -oE '10\.42\.[0-9]+\.[0-9]+' | head -1)
FAIL=0
ip netns exec hermes-a ping -c 3 -W 2 "$PEER_IP" >/dev/null || FAIL=1
ip netns exec hermes-a ping -c 2 -W 2 -s 1300 -M do "$PEER_IP" >/dev/null || FAIL=1
run a "$BIN/hermes" status | grep -q " $WANT " || FAIL=1
if [ "$MODE" = service ] && [ $FAIL = 0 ]; then
  # The service's socket admits the group, and nobody else.
  [ "$(stat -c '%a %G' /run/hermes/daemon.sock)" = "660 hermes" ] || { echo "socket perms: $(stat -c '%a %G' /run/hermes/daemon.sock)"; FAIL=1; }
  id -u hermes-smoke-outsider >/dev/null 2>&1 || useradd --no-create-home --shell /bin/sh hermes-smoke-outsider
  if setpriv --reuid hermes-smoke-outsider --regid hermes-smoke-outsider --init-groups \
      env -i HOME=/nonexistent "$BIN/hermes" status >/dev/null 2>&1; then
    echo "a user outside the hermes group could drive the daemon"; FAIL=1
  fi
  # State went to the service's state directory, owned by the service user.
  [ "$(stat -c %U "$WORK/a-state/identity.key" 2>/dev/null)" = hermes ] || { echo "identity not in StateDirectory"; FAIL=1; }
fi
if [ "$MODE" = restart ] && [ $FAIL = 0 ]; then
  # Kill signaling: rooms vanish from its memory. Both daemons must
  # reconnect, restore the same room, and keep their live tunnel.
  ROOM_BEFORE=$(run b "$BIN/hermes" status | grep '^room')
  pkill -x hermes-signalin
  sleep 2
  start_signaling
  for _ in $(seq 1 40); do
    run a "$BIN/hermes" status | grep -q '^connected  true' &&
      run b "$BIN/hermes" status | grep -q '^connected  true' && break
    sleep 1
  done
  sleep 2 # let the re-joins land
  run b "$BIN/hermes" status
  run a "$BIN/hermes" status | grep -q '^connected  true' || { echo "A did not reconnect"; FAIL=1; }
  run b "$BIN/hermes" status | grep -q '^connected  true' || { echo "B did not reconnect"; FAIL=1; }
  [ "$(run b "$BIN/hermes" status | grep '^room')" = "$ROOM_BEFORE" ] || { echo "B is in a different room"; FAIL=1; }
  run a "$BIN/hermes" status | grep -q " $WANT " || { echo "A lost its peer"; FAIL=1; }
  ip netns exec hermes-a ping -c 3 -W 2 "$PEER_IP" >/dev/null || { echo "no traffic after restart"; FAIL=1; }
  grep -q "room restored" "$WORK/signaling.log" || echo "(note: restore not logged)"
fi
if [ $FAIL = 0 ]; then
  # Latency: the in-tunnel ping (every 5 s) must produce an RTT.
  for _ in $(seq 1 12); do
    run a "$BIN/hermes" status | grep -qE '[0-9]+ ms' && break
    sleep 1
  done
  run a "$BIN/hermes" status | grep -qE '[0-9]+ ms' || { echo "no RTT measured"; FAIL=1; }
  # Graceful shutdown: SIGTERM makes B leave the room, so A sees it go
  # right away (not after a 45 s idle timeout).
  for pid in $(ip netns pids hermes-b); do
    [ "$(cat /proc/$pid/comm 2>/dev/null)" = hermes-daemon ] && kill -TERM "$pid"
  done
  for _ in $(seq 1 10); do
    run a "$BIN/hermes" status | grep -q '^peers      (none)' && break
    sleep 0.5
  done
  run a "$BIN/hermes" status | grep -q '^peers      (none)' || { echo "A still sees B after B's graceful shutdown"; FAIL=1; }
fi
if [ $FAIL = 0 ]; then
  echo "PASS ($MODE): A reached B at $PEER_IP over a $WANT path (1300-byte DF packets, RTT measured, clean shutdown)"
else
  echo "FAIL ($MODE) — logs in $WORK"
fi
[ "${KEEP:-0}" = 1 ] || cleanup
exit $FAIL
