# Hermes architecture

## Processes

```
┌─────────────┐   Tauri commands    ┌──────────────┐   IPC (named pipe /   ┌───────────────┐
│  UI (React) │ ──────────────────► │ Tauri (Rust) │ ───── unix socket) ──►│ hermes-daemon │
└─────────────┘  ◄── events ─────── └──────────────┘  ◄── events ───────── │  (privileged) │
                                                                           │  HermesEngine │
                                                                           └──────┬────────┘
                                                              WebSocket (wss)     │      UDP
                                                    ┌──────────────────────┐      │ ┌──────────────┐
                                                    │   hermes-signaling   │◄─────┤ │ hermes-relay │
                                                    │ (rendezvous, rooms)  │      └►│ (ciphertext  │
                                                    └──────────────────────┘        │  forwarder)  │
                                                                                    └──────────────┘
```

- **hermes-daemon** runs elevated (TAP adapter needs privileges), owns one
  `HermesEngine`, and serves any number of IPC clients.
- **hermes-ui** runs as the logged-in user; all engine access goes
  through daemon IPC.
- **hermes-signaling** is the control plane: auth, room membership,
  candidate exchange, room-mode distribution.
- **hermes-relay** is the optional data plane for relayed rooms.

## Room modes

The room creator chooses a `RoomMode`, stored by the signaling server and
handed to every member in `RoomCreated` / `RoomJoined`:

### `peer_to_peer`

1. On `PeerJoined`, each side gathers NAT candidates (host address, UPnP
   mapping, STUN reflexive address) — gathered once and cached.
2. Candidates are relayed through the signaling server
   (`RelayCandidates` → `PeerCandidates`).
3. Both sides probe all candidates (`HRM1` echo protocol, RFC 8445-style
   priorities); the best responding path wins.
4. A `PeerTunnel` (boringtun WireGuard) is created with
   `PeerPath::Direct(addr)`. The signaling server is now out of the loop.

**Optional relay fallback.** A P2P room may carry a fallback relay (the
room's `relay_addr`, set at creation). If step 3 fails for a peer, instead
of marking it `Stale` the engine registers with that relay on demand
(`ensure_relay_registration`) and builds a `PeerPath::Relayed` tunnel for
just that peer — the same machinery a relayed room uses, but per-peer and
lazy. This rescues symmetric-NAT pairs while keeping every other pair
direct. Fallback is asymmetry-tolerant: the inbound demux accepts both
direct and relay-framed datagrams, so one side may be direct while the
other relays.

### `relayed`

1. On room entry, the engine resolves the room's relay address, points
   the mesh at it, and starts a **registration keepalive** — a signed
   `REGISTER` datagram every 15 s (2 s during startup).
2. On `PeerJoined`, a `PeerTunnel` is created immediately with
   `PeerPath::Relayed { relay, dest }` — no NAT traversal at all.
3. Outbound WireGuard datagrams are wrapped in a `DATA` header
   (`magic, type, dest-node-id`) and sent to the relay; the relay
   rewrites them to `FORWARD` (`magic, type, src-node-id`) and delivers
   to the destination's registered address.
4. WireGuard handshake retransmission covers the window before both
   peers are registered; the room self-heals if the relay restarts.

Candidates received while in a relayed room are ignored — a confused or
malicious peer cannot pull a member off the relay path.

## Relay wire protocol

All packets start with magic `0xC8` (WireGuard's first byte is always
1–4, so the inbound demultiplexer distinguishes them statelessly).

| Type | Layout |
|---|---|
| `REGISTER` (0x01) | magic, type, room-uuid (16), node-id (32), unix-ms (8 BE), Ed25519 sig (64) |
| `REGISTER_ACK` (0x02) | magic, type, room-uuid (16) |
| `DATA` (0x03) | magic, type, dest node-id (32), WireGuard ciphertext |
| `FORWARD` (0x04) | magic, type, src node-id (32), WireGuard ciphertext |

Registration signatures cover
`"hermes-relay-register-v2" ‖ room ‖ node ‖ timestamp`. The relay
requires timestamps to be **strictly increasing** per `(room, node)`
unless re-sent from the same address — so a captured `REGISTER` is
useless to an attacker (verified by an e2e test). Sessions expire 60 s
after the last refresh.

The relay scopes every forward to the **sender's own room** (sender is
identified by source address, which only registration can bind). Nodes
in other rooms are unreachable — also covered by an e2e test.

## Data path (relayed room, Windows example)

```
app → wintun (IP packet)
    → L2/L3 shim (synthesize Ethernet)            broadcast/shim.rs
    → classify + route (unicast/flood)            broadcast/router.rs
    → PeerTunnel.send → framing (+20 B synthetic IP header)
    → boringtun encapsulate (+32 B)
    → relay DATA header (+34 B)
    → UDP to relay → FORWARD → peer
```

The virtual MTU is **1340** so a full-size frame survives all of the
above plus UDP/IP inside a standard 1500-byte path without
fragmentation.

## Server directory

`hermes-core::directory::ServerDirectory` merges three sources, by name
(later shadows earlier): built-in defaults → operator manifest (cached on
disk after every successful fetch) → user-added entries. Persisted as
`servers.toml` in the daemon's data directory. The daemon refreshes the
manifest at startup and on `RefreshServers`.

The engine itself is directory-agnostic — `connect()` takes the URL the
daemon resolved. This keeps policy in the daemon and mechanism in the
engine.

## Crate boundaries

- `hermes-core` — everything protocol- and engine-side; no binary.
- `hermes-daemon` — IPC framing (4-byte LE length + JSON), `Server`
  (engine host) and `DaemonClient` (used by the Tauri process). Both
  are generic over any duplex stream, which is how the IPC test suite
  runs the full protocol over an in-memory pipe.
- `hermes-relay`, `hermes-signaling` — thin binaries over `hermes-core`'s
  wire types; all room/auth/relay logic lives in small, testable files.

## Protocol versions

- Signaling protocol: **v2** (room modes + relay assignment).
- Daemon IPC: **v2** (room modes + server directory commands).

Both reject mismatched peers explicitly at handshake time.
