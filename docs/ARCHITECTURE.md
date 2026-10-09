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

A `DATA` packet for a room member that hasn't registered yet is held
(4 per destination, 3 s, 4096 total) and forwarded right after that
member's `REGISTER` — peers joining at the same moment no longer lose the
first handshake initiation.

The relay scopes every forward to the **sender's own room** (sender is
identified by source address, which only registration can bind). Nodes
in other rooms are unreachable — also covered by an e2e test.

## In-tunnel control messages

Inside the encrypted tunnel, a packet whose synthetic header carries the
marker `"HC"` (instead of `"HR"` for Ethernet frames) is a control
message, consumed by the tunnel itself. Currently: a latency ping every
5 s (`0x01` + sender timestamp) answered by a pong (`0x02` + the same
timestamp), giving each side the RTT shown as peer latency.

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

## Key authenticity

A peer's WireGuard public key reaches you through the signaling server, so
the server must not be able to substitute one. A node's WireGuard key is
*derived* from its Ed25519 identity seed, but nobody else can recompute
that derivation, so authenticity needs an explicit proof: in `Hello`, each
node sends `wireguard_binding` = Ed25519 signature over
`"hermes-wireguard-binding-v1" ‖ node_id ‖ wireguard_public`. The server
checks it on arrival (to keep junk out) and relays it in `PeerInfo`; **the
receiving client verifies it again** and refuses to build a tunnel for any
peer whose key its own identity doesn't vouch for (event `bad_peer_key`).
The server can pass the proof along but cannot forge it. It does *not* make
the server untrusted for admission — see
[THREAT-MODEL.md](THREAT-MODEL.md).

## Virtual addressing

A member's virtual MAC and IPv4 are derived from its node id (BLAKE3), so
every member computes everyone's addresses without a coordinator. IPv4
host parts are only 16 bits, so the signaling server breaks the rare tie:
on join it gives the newcomer an `ip_salt` — the smallest index into the
node's derivation sequence whose address no current member uses — and
hands it to everyone in `PeerInfo`. Salt 0 is the default address.

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

## Signaling liveness and reconnects

Signaling is control plane only; tunnels never depend on it once up. The
engine's supervisor reconnects with backoff whenever the WebSocket dies,
and three mechanisms make that safe:

- **Keepalive.** Clients send `ping` every 15 s. Both sides treat 45 s of
  silence as a dead connection, so a half-open TCP session (NAT timeout,
  network switch) is noticed instead of hanging forever.
- **One session per node.** Room membership is tracked per session, and
  a join replaces any older session of the same node. When the stale
  connection finally closes, the server sees it is no longer a member and
  stays quiet — peers are only told `peer_left` about sessions that were
  still current.
- **Room restore.** The automatic re-join carries `restore` (room id,
  name, mode, relay). If the server restarted and no longer knows the
  invite code, it recreates the room under the same id and code, so every
  member lands back in the same room and `enter_room` keeps the adapter
  and tunnels. Knowing the code already grants membership, so this adds
  no new power; a restore can't reuse the id of a different live room.

## Protocol versions

- Signaling protocol: **v3** (v2 added room modes + relay assignment; v3
  adds the signed WireGuard key binding below).
- Daemon IPC: **v2** (room modes + server directory commands).

Both reject mismatched peers explicitly at handshake time.
