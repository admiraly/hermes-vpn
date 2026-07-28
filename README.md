# Hermes

> A virtual LAN for the modern era. Like Hamachi, but open, self-hostable,
> and with first-class broadcast/multicast support — everything that used
> to Just Work™ on a real LAN works again.

Hermes creates a virtual Ethernet network ("room") shared by a group of
peers. Every peer gets a virtual network adapter; every application that
talks to that adapter reaches all other room members over encrypted
WireGuard tunnels. Because the virtual link behaves like real Ethernet,
ARP, mDNS/Bonjour, SSDP, NetBIOS, and game discovery all work natively.

**Platforms:** Windows (wintun) and Linux (`/dev/net/tun`).

## Two room modes

Every room is created in one of two modes — pick at creation time, and
every member automatically follows:

| | **Pure P2P** | **Via central server** |
|---|---|---|
| Data path | Direct UDP between peers (UPnP → STUN → hole punch) | Everything forwarded by a relay server |
| Server sees | Nothing after rendezvous | Ciphertext + metadata only |
| Works behind strict NAT / firewalls | Usually | Always (needs only outbound UDP) |
| Latency | Best possible | Adds one hop via the relay |

In **both** modes traffic is end-to-end encrypted with WireGuard
(ChaCha20-Poly1305, X25519, Noise IK). The relay server can never read
room traffic — it forwards opaque ciphertext between registered room
members.

A pure-P2P room can also be given an **optional fallback relay**: peers
connect directly when they can, and only the pairs that can't (e.g. both
behind symmetric NAT) fail over to the relay — so you get best-case
latency without a room becoming unusable on hard networks.

## Server fleet & directory

Hermes uses two kinds of self-hostable servers:

- **Signaling server** (`hermes-signaling`) — WebSocket rendezvous. Peers
  authenticate with a signed challenge, create/join rooms, and exchange
  connection candidates. Never touches room traffic.
- **Relay server** (`hermes-relay`) — the "central server" backing relayed
  rooms. A single UDP socket; forwards end-to-end-encrypted datagrams
  between room members.

Clients discover servers from three merged sources:

1. Built-in defaults (localhost, for development),
2. an **operator manifest** — a JSON file you host anywhere; adding a new
   public server to the fleet is a one-line edit (see
   [docs/SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md)),
3. servers the user added by hand in the UI's *Servers* panel.

## Repository layout

```
hermes/
├── hermes-core/       # Engine library — identity, tunnels, NAT, mesh, relay client
├── hermes-daemon/     # Privileged background service (owns the TAP adapter, IPC server)
├── hermes-signaling/  # WebSocket rendezvous server (self-hostable)
├── hermes-relay/      # UDP relay server — the "central server" mode backend
├── hermes-ui/         # Desktop app (Tauri 2 + React)
└── docs/              # Architecture & operations guides
```

## Quick start (development, single machine)

Four terminals from the workspace root:

```sh
# 1. Signaling server (ws://127.0.0.1:8787/v1)
cargo run -p hermes-signaling

# 2. Relay server (127.0.0.1:8788) — only needed for relayed rooms
cargo run -p hermes-relay

# 3. Daemon — needs privileges for the virtual adapter
#    Linux:
sudo -E cargo run -p hermes-daemon
#    Windows: run from an elevated prompt
cargo run -p hermes-daemon

# 4. UI
cd hermes-ui && npm install && npx tauri dev
```

In the UI: *Connect to signaling server* → *Create Room* → choose
**Pure peer-to-peer** or **Via central server** → share the invite code
(e.g. `WOLF-7X4K-QR2M`).

For a full production setup — building, deploying the signaling and relay
servers on a VPS, and installing the client on Windows/Linux, step by step
— see **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**. See
[BUILDING.md](BUILDING.md) for toolchain detail (Windows needs either MSVC
Build Tools or MinGW-w64) and
[docs/SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md) for running the
public server fleet and the directory manifest.

## Project status

v2 baseline is built and tested (46 passing tests). CI
([.github/workflows/ci.yml](.github/workflows/ci.yml)) builds and tests the
engine and servers on Windows **and** Linux, type-checks the frontend, and
builds the full Tauri app — so the cross-platform code is exercised on every
push. Known bugs, remaining work, and the future roadmap are tracked in
[CHECKLIST.md](CHECKLIST.md).

## Security model

- Each install holds a permanent **Ed25519 keypair**; the private key
  never leaves the device. The WireGuard X25519 key is derived from it.
- Room access requires a 12-character checksummed invite code shared
  out-of-band.
- The signaling server authenticates every connection with a signed
  challenge; it cannot impersonate peers or forge room membership.
- Relay registrations are Ed25519-signed with strictly-increasing
  timestamps, so captured packets cannot hijack a session.
- Relays and signaling servers see metadata only — never plaintext.

## License

Dual-licensed under MIT OR Apache-2.0.
