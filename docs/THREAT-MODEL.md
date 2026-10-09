# Hermes threat model

What Hermes protects, from whom, and — just as important — what it does
**not** protect. Written against the code as of protocol v3; claims here
are backed by tests unless marked *(not enforced)*.

## Mental model

A Hermes room is one virtual Ethernet segment. **Treat every member of a
room the way you'd treat everyone plugged into the same switch**: they can
send you any Ethernet frame, run ARP spoofing, scan you, and see your
broadcast traffic. Hermes keeps *outsiders* (the network, the relay, other
rooms) out of that segment. It does not isolate members from each other.

## Parties

| Party | Trusted for | Not trusted for |
|---|---|---|
| **Room member** | Being on your LAN (see above) | Anything a LAN member shouldn't be able to do — firewall your services |
| **Signaling server** | **Admission** (who is in a room) and availability | Confidentiality of your traffic; authenticity of *existing* members' keys |
| **Relay server** | Forwarding datagrams | Reading, forging or reliably delivering them |
| **Network path** | Nothing | — |
| **Directory manifest host** | Telling your client which servers exist | — (but see "Server list" below) |
| **Release pipeline (GitHub Actions)** | Building the binaries you run | — |

## What an attacker can and cannot do

### On the network path (passive or active)
- Traffic between peers is **WireGuard** (Noise IK, ChaCha20-Poly1305,
  X25519): confidential, authenticated, replay-protected. They see
  endpoints, sizes and timing.
- The signaling channel is **plaintext `ws://` unless you use `wss://`**.
  Over `ws://` an eavesdropper reads invite codes and candidate addresses,
  and an invite code is all it takes to join a room. Clients warn loudly
  (log, CLI, app banner). *Use `wss://` for anything that crosses the
  internet.* An active attacker on a `ws://` path can also act as a hostile
  signaling server (next section).

### A malicious or compromised **signaling server**
Can:
- See node ids, aliases, which rooms exist, who is in them, invite codes
  (in the clear on its own side), client IPs, and every candidate address
  — i.e. the social graph and locations. **Metadata is not hidden from it.**
- Refuse service, drop or reorder messages, split rooms.
- **Admit anyone to any room it hosts**, including itself: it decides
  which members peers are told about, and peers build tunnels to whoever
  they're told about. *The invite code is enforced by the server, not
  cryptographically.* A hostile server can therefore join your virtual LAN
  as a member. *(not enforced — room admission is a known gap; see
  "Open problems".)*

Cannot (tested in `hermes-core/tests/key_binding_e2e.rs`):
- **Read or modify traffic between members, or impersonate an existing
  member.** Each node signs a binding of its WireGuard key to its identity
  key (`wireguard_binding`); peers verify it themselves and refuse any peer
  whose key isn't vouched for by its own identity. The server can relay the
  signature but cannot forge it. Before protocol v3 this was **not** true:
  the server could substitute its own key for a peer's and sit in the
  middle. Clients and servers from before v3 are rejected at the handshake.

### A malicious or compromised **relay**
Can:
- See node ids, room UUIDs, source IPs, packet sizes and timing.
- Drop, delay, duplicate or reorder datagrams (WireGuard tolerates all of
  these), and refuse service.

Cannot:
- Read or forge payloads (end-to-end WireGuard).
- Amplify traffic: `FORWARD` is the same size as the `DATA` that caused it,
  and `REGISTER_ACK` (18 B) is far smaller than `REGISTER` (122 B).
- Hijack a session with a captured `REGISTER` — except in the narrow window
  below.

Weak spots, by design or by choice:
- **Sender identity is the UDP source address.** Anyone who can spoof a
  member's source address (same NAT or LAN, or a network that doesn't
  filter spoofing) can make the relay deliver junk "from" that member. The
  receiver's WireGuard rejects it (authentication fails), so the cost is
  bandwidth, not integrity.
- **Replay after a relay restart.** `REGISTER` timestamps must strictly
  increase per (room, node) unless re-sent from the registered address; the
  relay keeps that in memory. After a restart, one captured `REGISTER` can
  re-point a victim's session to the attacker's address until the victim's
  next registration (≤ 15 s). The attacker still can't decrypt anything; it
  is a brief denial of service. The relay does **not** reject timestamps
  that disagree with its own clock: doing so would lock out every client
  with a wrong system clock, and the gain is this small.
- **Anyone who learns a room UUID can `REGISTER` into it** as their own
  node. Nobody tunnels to them (peers come from signaling) so they receive
  nothing; they can send junk, bounded by per-IP limits on `REGISTER`
  (not on `DATA` — there is no per-session bandwidth cap yet).

### A **malicious room member**
- Is on your LAN. Expect ARP spoofing, scanning, rogue DHCP/mDNS answers.
  Hermes verifies that frames from a peer's tunnel carry *that peer's* MAC
  (members can't forge each other's MACs), but it does not stop a member
  from putting a forged *IP* in a frame, or from poisoning ARP caches the
  way any LAN host can.
- Can learn the other members' IP addresses (candidate exchange). Rooms are
  not anonymous from their members.
- Can keep the invite code and let others in. Codes can't be revoked and
  members can't be kicked yet *(not enforced)*.

### Guessing an invite code
11 random characters from a 32-symbol alphabet = **55 bits**, drawn from the
OS CSPRNG. The server allows 60 create/join attempts per minute per client
IP. The 12th character is a checksum that catches typos (every single
mistake, and every adjacent swap except `A`↔`9`); it is not a security
feature. Codes live as long as the room has members.

### On the local machine
- The daemon's identity (`identity.key`, 32 bytes, mode 0600) *is* the
  node: whoever reads it can impersonate that node. Linux service: state is
  in `/var/lib/hermes`, owned by the `hermes` user, mode 0700.
- **Who may control the daemon:** Linux — its owner (per-user daemon) or the
  `hermes` group (service); Windows — any authenticated local user, remote
  clients refused. Controlling the daemon means joining rooms and choosing
  signaling servers, so on a shared Windows machine every logged-in user
  can use (and re-point) the service. *(Tightening this to administrators
  or a dedicated group is an open item.)*
- The Windows service runs as LocalSystem because creating the wintun
  adapter needs administrator rights. The Linux service runs unprivileged
  with `CAP_NET_ADMIN` only and a sandboxed unit.
- **Server list.** Clients can fetch an operator-hosted JSON manifest of
  servers. Whoever controls that URL controls which signaling servers a
  client is pointed at (and so inherits the "malicious signaling server"
  row above). The default manifest URL is empty unless a build sets `HERMES_DEFAULT_MANIFEST_URL`.

### Supply chain
- `Cargo.lock` is committed and CI builds with `--locked`; `cargo audit`
  runs on every lockfile change and weekly, and fails on any advisory not
  listed (with a reason) in `.cargo/audit.toml`.
- Release artifacts are built by GitHub Actions from a tag and published
  with `SHA256SUMS`. `wintun.dll` is downloaded at build time and verified
  against a pinned SHA-256.
- **Releases are not signed** and the Windows installers are not
  Authenticode-signed (SmartScreen will warn). Checksums prove the file
  matches the release page, not that the release page is genuine.

## What Hermes does not try to do
- Hide *that* you use Hermes, or hide metadata from the servers you choose.
- Protect against a compromised endpoint (malware on your machine reads
  your key and your traffic).
- Resist traffic analysis (sizes, timing, who talks to whom).
- Provide per-member isolation or ACLs inside a room.
- Protect confidentiality of anything sent over `ws://` signaling.

## Open problems (tracked in CHECKLIST.md)
1. **Cryptographic room admission.** Derive a room secret from the invite
   code so members prove they hold it to each other; then a hostile
   signaling server could no longer add itself to a room.
2. **Revocable codes, kick/ban, room passwords.**
3. Restrict who may control the Windows daemon.
4. Per-session bandwidth limits on the relay.
5. Sign releases and installers.
6. Independent cryptographic review. Everything here is the author's own
   analysis; the primitives are WireGuard (`boringtun`), Ed25519 and
   X25519 from widely used crates, but the protocol around them (relay
   registration, key binding, invite codes) has had no outside review.

## Reporting a vulnerability
See [SECURITY.md](../SECURITY.md).
