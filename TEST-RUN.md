# Hermes — first real two-machine test

A concrete, copy-paste runbook for the exact setup you asked for:

- **one Linux server** running both the **signaling** and **relay** servers,
- **one Linux client**,
- **one Windows client**,

driven entirely by the `hermes` command-line tool (no GUI needed).

> **Build the binaries first** (see [BUILDING.md](BUILDING.md)) and stage
> them like this — the rest of this guide refers to these folders:
>
> ```sh
> # On Linux:
> cargo build --release -p hermes-signaling -p hermes-relay -p hermes-daemon -p hermes-cli
> mkdir -p dist/linux && cp target/release/hermes{-signaling,-relay,-daemon,} dist/linux/
> ```
> ```powershell
> # On Windows (wintun.dll from https://www.wintun.net, amd64 build):
> cargo build --release -p hermes-signaling -p hermes-relay -p hermes-daemon -p hermes-cli
> mkdir dist\windows; copy target\release\hermes*.exe dist\windows\; copy wintun.dll dist\windows\
> ```
>
> ```
> dist/linux/    hermes-relay  hermes-signaling  hermes-daemon  hermes
> dist/windows/  hermes-relay.exe  hermes-signaling.exe  hermes-daemon.exe  hermes.exe  wintun.dll
> ```
>
> Before involving real machines you can rehearse the whole flow on one
> Linux box: `sudo scripts/netns-smoke.sh relayed|p2p|fallback` runs two
> daemons with real TAP adapters in separate network namespaces.

Throughout, replace **`SERVER_IP`** with your Linux server's address
(reachable from both clients).

---

## Part 1 — Linux server (signaling + relay)

Copy `dist/linux/hermes-signaling` and `dist/linux/hermes-relay` to the server.

```sh
chmod +x hermes-signaling hermes-relay

# Open the ports (adjust for your firewall / cloud security group)
sudo ufw allow 8787/tcp     # signaling (WebSocket)
sudo ufw allow 8788/udp     # relay

# Run both. For a quick test, two terminals (or tmux); for a lasting
# setup use the systemd units in docs/SERVER-OPERATIONS.md.
RUST_LOG=info ./hermes-signaling      # terminal 1 → listens on 0.0.0.0:8787
HERMES_RELAY_BIND=SERVER_IP:8788 RUST_LOG=info ./hermes-relay   # terminal 2
```

Sanity check from your laptop:

```sh
curl http://SERVER_IP:8787/health      # → ok
```

If that prints `ok`, signaling is reachable. (The relay is UDP and has no
health endpoint — you'll confirm it works in Part 4.)

> Cloud VMs: also open `8787/tcp` and `8788/udp` in the provider's
> security group, not just `ufw`.

---

## Part 2 — Linux client

Copy `dist/linux/hermes-daemon` and `dist/linux/hermes` to the Linux client.

```sh
chmod +x hermes-daemon hermes

# 1. Make sure the TUN module is available, and grant the daemon the one
#    capability it needs. Use setcap (NOT sudo) so the daemon runs as YOU
#    and the `hermes` CLI (also you) can find its socket.
sudo modprobe tun
sudo setcap cap_net_admin=+ep ./hermes-daemon

# 2. Start the daemon (as your user) and leave it running.
RUST_LOG=info ./hermes-daemon &
#    (or in its own terminal without the &)

# 3. Point this node at your servers and connect.
./hermes add-server signaling main ws://SERVER_IP:8787/v1
./hermes add-server relay     main SERVER_IP:8788
./hermes use-signaling main
./hermes connect                      # → "connected to signaling server"
```

Leave this client connected. You'll create the room from the Windows side
in Part 4 (or here — either machine can be the creator).

---

## Part 3 — Windows client

Copy the whole `dist/windows/` folder to the Windows machine. **Keep
`wintun.dll` in the same folder as `hermes-daemon.exe`.**

1. **Start the daemon as Administrator** (it must create the virtual
   adapter). Right-click `hermes-daemon.exe` → **Run as administrator**,
   or from an **elevated** PowerShell:
   ```powershell
   cd path\to\dist\windows
   $env:RUST_LOG="info"; .\hermes-daemon.exe
   ```

2. Open a **second elevated** PowerShell (also Administrator — a
   non-elevated shell may not be able to talk to the elevated daemon's
   pipe), and point this node at your servers:
   ```powershell
   cd path\to\dist\windows
   .\hermes.exe add-server signaling main ws://SERVER_IP:8787/v1
   .\hermes.exe add-server relay     main SERVER_IP:8788
   .\hermes.exe use-signaling main
   .\hermes.exe connect
   ```

---

## Part 4 — Create a room and join it

Start with a **relayed** room — it's the path most likely to work first
(it needs only outbound UDP to the relay, no NAT traversal).

**On the Linux client (the creator):**

```sh
./hermes create gametest --mode relayed --relay SERVER_IP:8788
```

It prints something like:

```
in room — mode Relayed, relay SERVER_IP:8788
INVITE CODE: WLFK-7X4K-QR2S
(share this with the other machine, then run: hermes join WLFK-7X4K-QR2S)
```

**On the Windows client:**

```powershell
.\hermes.exe join WLFK-7X4K-QR2S
```

Both should now be in the room.

---

## Part 5 — Confirm it actually carries traffic

On **either** client:

```sh
./hermes status
```

You'll see the other peer with a virtual IP in `10.42.x.x`, e.g.:

```
node        9f3a…
connected  true
room       room-WLFK [Relayed] relay=SERVER_IP:8788
ALIAS            VIRTUAL IP      PATH     TRAFFIC tx/rx       HANDSHAKE
hermes-user      10.42.183.20    relayed  1.2K/0.9K          3s ago
```

Now **ping the peer's virtual IP** to prove the tunnel passes real OS
traffic:

```sh
# Linux client — ping the Windows peer's 10.42.x.x from `status`
ping 10.42.183.20
```
```powershell
# Windows client — ping the Linux peer's 10.42.x.x
ping 10.42.183.20
```

Re-run `hermes status` and watch **TRAFFIC** climb and **HANDSHAKE** stay
recent. Successful pings + rising counters = a working encrypted virtual
LAN. 🎉

Anything that works over IP now works between the machines: file shares,
game LAN discovery, etc.

---

## Part 6 — Try pure peer-to-peer (optional)

Once relayed mode works, test direct P2P. Leave the room first on both:

```sh
./hermes leave
```

Recreate **without** forcing the relay, but keep it as a safety net:

```sh
# P2P, with automatic relay fallback if a direct path can't be made
./hermes create gametest --relay SERVER_IP:8788
# (omit --relay entirely for pure P2P with no fallback)
```

Join from Windows as before, then `hermes status`:

- **PATH = direct** → the two machines hole-punched a direct tunnel. 
- **PATH = relayed** → direct failed (likely both behind strict NAT) and
  it fell back to the relay. Still works, just not direct.

This is the real-world NAT-traversal test — the least-proven path, so it's
the most interesting result to report back.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `could not reach hermes-daemon` | Daemon not running, or (Linux) you started it with `sudo` instead of `setcap` so the socket is under root — restart it as your user. (Windows) run the `hermes.exe` shell **as Administrator** too. |
| Windows daemon won't start | `wintun.dll` must be in the same folder; must run **as Administrator**. |
| Linux daemon: "operation not permitted" | `sudo setcap cap_net_admin=+ep ./hermes-daemon` and `sudo modprobe tun`. |
| `connect` fails | `curl http://SERVER_IP:8787/health` — if that fails, signaling isn't reachable (firewall / not running). Check the `ws://SERVER_IP:8787/v1` address. |
| In a relayed room but ping fails | Relay UDP blocked: open `8788/udp` on the server **and** the cloud security group. Run the relay with `RUST_LOG=debug` to see registrations/forwards. |
| `join` says invalid code | Codes are case-insensitive but must match exactly (e.g. `WLFK-7X4K-QR2S`); both clients must be connected to the **same** signaling server. |
| Pings drop / large transfers stall | MTU — the adapter is pinned to 1340; if you changed it, recheck the budget. |

Useful: run any server or the daemon with `RUST_LOG=debug` for a play-by-play.

---

## What this proves (and doesn't)

A green run here is the **first real end-to-end validation**: real virtual
adapters on real machines, real WireGuard encryption, traffic crossing the
internet via your relay (and, in Part 6, possibly a direct hole-punched
path). It exercises the parts no automated test can: the TAP/wintun
adapter, the daemon process lifecycle, and (Part 6) live NAT traversal.

It does **not** test scale, long-run stability, reconnect-after-drop, or
mobile/macOS — those remain on [CHECKLIST.md](CHECKLIST.md).
