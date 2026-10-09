# Hermes — project checklist & roadmap

Status of the v2 rebuild and everything still ahead. Checked = done and
verified. Priorities: **P0** blocks real-world use, **P1** needed for a
public release, **P2+** improvements and future features.

---

## ✅ Recovery (October 2026)

The working tree was lost and partially reconstructed from a transcript
(commit `dbff5c7`, which did not compile). It has been rebuilt and is
whole again:

- [x] All missing modules re-implemented against their surviving call
      sites and docs: `broadcast/*` (MAC router, ARP, wintun shim),
      `tunnel/framing`, `room/invite_code`, `nat/stun`, `nat/upnp`, the
      `Mesh`, crate manifests, the relay server loop, `Cargo.lock`, and
      the UI build files (package.json, Vite/TS config, Tauri
      capabilities, placeholder icons)
- [x] 88 tests pass on Linux and Windows, warning-free under `-D warnings`; the
      Tauri app builds on Linux
- [x] **Real-adapter smoke test**: `scripts/netns-smoke.sh` runs two
      daemons with kernel TAP adapters in separate network namespaces.
      Relayed, direct P2P and P2P→relay fallback rooms all ping across
      the virtual LAN, including 1300-byte don't-fragment packets.
      Also runs in CI.

Bugs found and fixed while rebuilding:

- [x] ICE probes and STUN responses raced the driver's `recv_from` on the
      shared socket (replies were eaten); the probe "echo the same magic"
      scheme would also ping-pong forever. Both now go through the mesh
      demux, with distinct request/reply probe messages, and probing is
      parallel with retransmits (which is what punches holes).
- [x] Host candidate advertised `0.0.0.0:port`; now the LAN address.
- [x] The configured STUN server was ignored (and a hostname could
      never parse); now resolved and used.
- [x] Linux TAP got a random kernel MAC, so the kernel dropped every
      unicast frame peers addressed to our derived MAC. The adapter now
      takes the virtual MAC.
- [x] Candidate gathering ran STUN then UPnP serially with no overall
      deadline: ~15 s to a direct path without internet. Now concurrent
      and capped at ~3 s.

Improvements added:

- [x] **Anti-spoofing**: frames from a peer's tunnel must carry that
      peer's virtual MAC, so a member can't forge traffic as another.
- [x] **Endpoint roaming**: a datagram from an unknown address is
      attributed via WireGuard's receiver index / handshake initiator key,
      and the endpoint moves only after WireGuard authenticates it.
- [x] Unique per-tunnel WireGuard indices (they were all 0).

## ✅ Done & verified (v2 baseline)

- [x] Dual room modes: pure P2P and central-server (relayed), chosen at
      room creation, distributed to all members by the signaling server
- [x] `hermes-relay` central server: Ed25519-authenticated registration,
      replay protection, per-room ciphertext forwarding
- [x] `PeerPath` transport abstraction (Direct vs Relayed) in tunnels
- [x] Relay-aware mesh demux (magic-byte sniff, never collides with WireGuard)
- [x] Server directory: built-in + operator manifest + user-added, merged
      and persisted to `servers.toml`
- [x] Daemon IPC v2 + Tauri commands for room modes & server management
- [x] UI: P2P/central toggle with relay picker, server settings panel,
      manifest URL, room-mode badge
- [x] Fixed v1 bug: wintun adapter held a `parking_lot` guard across an
      `.await` (not `Send`) — now a tokio mutex
- [x] Reconnectable engine (needed for switching signaling servers)
- [x] e2e tests: WireGuard handshake through the real relay binary, room
      isolation, replay-hijack defense, signaling mode propagation, IPC
      directory round-trip (43 tests, all green on Windows)
- [x] Docs: README, BUILDING, ARCHITECTURE, SERVER-OPERATIONS + example manifest
- [x] `hermes-cli`: GUI-free control client (connect, server directory,
      create/join, live status) — makes headless/Linux nodes drivable
- [x] Deployment docs: DEPLOYMENT.md (full runbook) + TEST-RUN.md
      (two-machine first-test script). *(The prebuilt `dist/` binaries
      were lost with the tree; TEST-RUN.md now says how to build them.)*

---

## P0 — correctness & bugs to fix before using for real

- [x] **Windows adapter MTU is now set.** `set_mtu` in
      [tap/windows.rs](hermes-core/src/tap/windows.rs) pins the interface
      MTU via `netsh ... set subinterface mtu=` right after IP config, so
      apps do path-MTU discovery correctly instead of handing wintun
      oversized packets. (Linux already did this via `tokio-tun .mtu()`.)
- [x] **Buffer budget audited and locked down.** Per-layer overhead is now
      encoded as constants with a `mtu_budget_fits_physical_path` test
      ([tap/mod.rs](hermes-core/src/tap/mod.rs)) asserting
      `VIRTUAL_MTU + overhead ≤ 1500`. Driver, tunnel, and relay buffers
      all reference the shared `DATAGRAM_BUFFER_SIZE`, and a second test
      proves it holds the largest possible datagram. Worst-case relayed
      frame is ~1483 B on the wire — no fragmentation.
- [x] **Outbound jumbo-frame guard.** The tap→mesh loop drops any frame
      larger than `FRAME_BUFFER_SIZE` with a warning rather than emitting a
      fragmenting datagram — defense in depth if the adapter MTU isn't
      honored ([mesh/driver.rs](hermes-core/src/mesh/driver.rs)).
- [x] **Removed dead TURN stub.** `nat/turn.rs` (v1 leftover, superseded by
      the relay) is gone; `nat` module docs updated. `PathKind::Relayed`
      now correctly denotes the central-relay path.
- [x] **First relayed packet can be dropped.** The relay now holds up to
      4 `DATA` packets per not-yet-registered destination for 3 s (4096
      total, only from registered senders) and delivers them right after
      the destination's registration, so the first WireGuard handshake
      initiation no longer costs a 5 s retransmit. Unit + e2e tested.
- [~] **Real two-machine smoke test, both modes.** Covered in CI so far:
      the Linux namespace smoke test (real TAP adapters; relayed, P2P,
      fallback, signaling restart, systemd-style service) and the **Windows
      smoke test** on GitHub's Windows runners — a real wintun adapter,
      the L2/L3 shim and the relay, pinged end to end by the headless echo
      peer, both with the daemon run by hand and installed as a Windows
      service. Still needed: two separate hosts behind *real* NATs (P2P
      hole punching across the internet) and Windows↔Linux traffic over a
      direct path. Follow [TEST-RUN.md](TEST-RUN.md).
- [x] **Relay replies from the wrong address on multi-homed hosts.** A
      wildcard-bound relay answered from whichever local IP routed back,
      and clients dropped those replies (found by the netns smoke test).
      It now opens one socket per local IPv4 address, re-scanned every
      30 s, and each session replies through the socket its client uses.
      The smoke test runs the relay with a wildcard bind to guard this.

## P1 — platform & packaging (needed for a release)

- [x] **Build & test on Linux.** Whole workspace including the Tauri app
      builds on Linux, `cargo test` passes, and the netns smoke test runs
      the daemon, Unix-socket IPC and TAP adapter for real.
- [~] **Bundle `wintun.dll`** — the release workflow ships it (checksum-
      verified) next to `hermes-daemon.exe` in the Windows zip. The MSI/NSIS
      app installer doesn't include the daemon yet.
- [x] **Daemon lifecycle / service install.**
      - **Linux:** `packaging/linux/install.sh` installs a hardened systemd
        unit: the daemon runs as the unprivileged `hermes` user with only
        `CAP_NET_ADMIN`, state in `/var/lib/hermes`, socket
        `/run/hermes/daemon.sock` (0660, group `hermes` — group membership
        is the authorization). Clients try `$HERMES_SOCKET`, the per-user
        socket, then the system socket. Verified for real by the netns
        smoke test's `service` mode (also in CI), including that a user
        outside the group is refused.
      - **Windows:** `hermes-daemon service install|uninstall` registers an
        auto-start LocalSystem service (state + log in
        `%ProgramData%\Hermes`). The pipe now has an explicit ACL
        (SYSTEM/Admins full, authenticated users read/write), refuses
        remote clients, and claims its name exclusively on the first
        instance (no pipe squatting). Exercised in CI on a real Windows
        runner: install → CLI over the pipe → room traffic → uninstall.
      - Still open: a one-click installer (MSI/NSIS) wrapping this, and the
        Tauri app offering to install the service.
- [ ] **Real app icons & branding** — replace the generated placeholder
      [icons](hermes-ui/src-tauri/icons) with real artwork; add `.icns` if
      macOS is ever targeted.
- [x] **Release builds & artifacts** — `.github/workflows/release.yml`:
      push a `v*` tag to build Linux/Windows binaries, deb/AppImage and
      MSI/NSIS app bundles, and publish them with `SHA256SUMS` as a GitHub
      Release. Next: one installer per OS that bundles app + daemon and
      installs the service.
- [x] **Default manifest URL** is supported: builds read
      `HERMES_DEFAULT_MANIFEST_URL` at compile time and use it when the user
      hasn't set one. Left unset until there is an official fleet to point at.
- [x] `rust-toolchain.toml` pins the toolchain (1.97.0).

## P2 — resilience

- [x] **Auto-reconnect to signaling.** A supervisor task watches every
      signaling connection; on unexpected drop it reconnects with
      exponential backoff (1 s → 30 s cap) and re-joins the current room by
      its remembered invite code. The UDP socket/mesh/tunnels and the
      virtual adapter are owned by the engine and survive the blip — live
      tunnels keep carrying traffic throughout, and already-connected
      peers are kept (not rebuilt) on re-join. Explicit disconnect cancels
      the supervisor via a generation counter. e2e-tested against the real
      signaling binary (kill → restart → reconnected; silent after
      explicit disconnect). New events: `SignalingReconnecting{attempt}`,
      `SignalingReconnected`.
- [x] **Reconnect correctness** (found by code review, fixed with tests
      against the real server in `session_lifecycle_e2e.rs`):
      - a stale session of a reconnecting node used to be removed *by node
        id* when it finally died — kicking the live session too and
        telling every peer the node left. Membership is now per session;
        stale entries are replaced on join and leave silently.
      - half-open connections went unnoticed (client side: forever).
        Clients ping every 15 s; both sides drop 45 s of silence.
      - a signaling restart wiped all rooms, so auto re-join failed with
        `invalid_code` forever. Re-joins carry restore info and the server
        recreates the room under the same id and code.
      - joining a second room didn't leave the first.
      The netns smoke test's `restart` mode proves a live P2P room
      survives a signaling restart with its tunnel intact.
- [x] **Automatic P2P → relay fallback.** A P2P room can now carry an
      optional fallback relay (set at creation; checkbox in the UI). When a
      peer's direct path can't be established, the engine registers with
      the relay on demand and builds a relayed tunnel for that peer instead
      of marking it `Stale` ([engine_pump.rs](hermes-core/src/engine_pump.rs)
      `probe_and_tunnel`). Per-peer and lazy, so a room only touches the
      relay for the pairs that actually need it. Rescues symmetric-NAT
      pairs a pure-P2P room could never connect.
- [x] **Relay health detection + self-healing.** The relay's registration
      acks now feed a `RelayHealth` watch channel (mesh demux records
      acks; the keepalive evaluates deadlines). Three missed acks (45 s)
      → `RelayUnhealthy` event + `relay_healthy: false` in the state
      snapshot; the keepalive probes aggressively while unhealthy and
      flips back to `RelayRestored` the moment the relay answers —
      recovery needs no user action (relay sessions and WireGuard both
      re-establish on their own). Surfaced in the UI banner and `hermes
      status`. e2e-tested with a fake relay that goes silent and returns.
      Still open (folded into P6 multi-relay): switching to a *backup*
      relay mid-room — today the relay address is room-wide and fixed at
      creation.
- [~] **Re-key / endpoint roaming.** Direct tunnels now follow a peer to
      a new address once WireGuard authenticates a packet from it (tested
      with a simulated NAT rebind in `p2p_e2e`); relayed peers re-register
      from their new address. Still to verify on real Wi-Fi↔cellular.
- [x] **UPnP mapping lifecycle.** The mapping (1 h lease, or indefinite
      if the router insists) is renewed at half-lease while the engine
      runs, reused instead of re-mapped, and deleted on graceful daemon
      shutdown (`HermesEngine::shutdown`, which also leaves the room so
      peers see us go at once — verified in the netns smoke test). Not yet
      exercised against a real router.

## P3 — security hardening

- [x] **Relay DoS limits.** `REGISTER` is rate-limited per source IP
      (100/s, checked *before* the signature verification), with caps of
      256 sessions per IP and 100 000 total; all overridable by env (see
      SERVER-OPERATIONS.md). Still open: per-session bandwidth limits, and
      documenting that anyone who learns a room UUID can register and
      inject `DATA` (WireGuard rejects it; the cost is bandwidth).
- [~] **Plaintext `ws://` to a remote host** is flagged: the engine logs a
      warning, `GetState` reports `signaling_insecure`, and the CLI and UI
      warn the user prominently. Deliberately *not* refused, so LAN setups
      without TLS keep working; revisit for public builds.
- [x] **Rate-limit signaling** per client IP: 120 connections/min (HTTP 429
      before the upgrade) and 60 `create_room`/`join_room` attempts/min
      (capping invite-code guessing). Behind a TLS proxy, set
      `HERMES_SIGNALING_TRUST_PROXY=1` so the client IP comes from
      `X-Forwarded-For` (rightmost hop) instead of the proxy's address.
      A rate-limited automatic re-join retries after 5–10 s.
- [x] **Relay source-binding / threat model** documented in
      [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md): sender identity from the
      UDP source address (spoofing costs bandwidth, never integrity — the
      receiver's WireGuard rejects it), the REGISTER replay window after a
      relay restart, no amplification. Also [SECURITY.md](SECURITY.md) for
      private vulnerability reports.
- [x] **WireGuard keys are bound to node identity** (found by tracing what a
      hostile signaling server could do): the server could substitute a
      peer's WireGuard key and man-in-the-middle the "end-to-end" tunnel.
      Nodes now sign `(node_id, wireguard_public)`; peers verify it
      themselves and refuse unvouched keys (`bad_peer_key`). Protocol v3.
      Tested against a hostile in-test server — and the tests fail with the
      check disabled.
- [x] **`cargo audit`** runs in CI on lockfile changes and weekly
      (`.github/workflows/audit.yml`, `--deny warnings`). Fixed
      RUSTSEC-2026-0258 (h2, via igd-next → 0.18, which also hardens UPnP
      discovery against redirects); dropped the unmaintained `bincode`.
      Two unfixable GTK/Tauri warnings are ignored with reasons in
      `.cargo/audit.toml`. Identity key files are now created 0600 from the
      start (no chmod race).
- [~] **Independent review** of relay replay protection, key binding and
      invite codes. My own adversarial pass is in the threat model (e.g. the
      invite checksum misses exactly one adjacent swap, `A`↔`9`); outside
      eyes are still wanted.
- [x] **Cryptographic room admission** (protocol v5). The invite code (plus
      password) never reaches the server: it gets an Argon2id-derived lookup
      token, and members verify each other's MAC proofs before building
      tunnels, so a hostile server can't add itself. Rotation seals the new
      code under the old key. Tests: `crypto::admission`, `key_binding_e2e`
      (invented / replayed members), `access_e2e`, `engine_e2e`. Remaining:
      per-member credentials; crypto-enforced kick/ban.
- [ ] **Restrict who may control the Windows daemon** (today: any
      authenticated local user; remote clients are refused).
- [ ] **Sign releases** (minisign/cosign) and Authenticode-sign the Windows
      installers.

## P4 — UX / UI polish

- [x] **Editable alias** — defaults to the machine's hostname instead of
      `"hermes-user"`; change it with `hermes alias <name>` or *Settings →
      This device* in the app. Persisted in the daemon's data dir; peers see
      it from the next signaling connection.
- [x] **Copy-invite-code button** — added to the room view (clipboard).
      A shareable join link/QR is still open.
- [x] **Show which signaling server is active** — the connect screen now
      shows "via <server>" with a pointer to settings.
- [x] **Surface per-peer stats.** `Mesh::link_stats()` exposes each
      tunnel's live byte/frame counters, handshake age, and direct-vs-relayed
      path through `GetState`; the UI peer list now polls (2 s) and shows
      Path / Traffic / Handshake columns. A relay e2e assertion proves the
      counters move.
- [x] **Peer latency.** Each tunnel sends an encrypted in-tunnel ping
      every 5 s (a control message, never handed to the adapter); the RTT
      appears in `LinkStats.rtt_ms`, the peers' `latency_ms`, the CLI's RTT
      column and the UI's Latency column. Works for direct and relayed
      peers alike.
- [x] **Tray menu** — status line (not in a room / in a room · N peers /
      reconnecting), *Show Hermes*, *Quit app (network stays up)*;
      left-click shows the window and closing the window hides it to the
      tray. Builds on Linux and Windows; not yet clicked through on a real
      desktop.
- [x] **Windows 11 Fluent redesign.** Full dark theme (design tokens in
      [styles.css](hermes-ui/src/styles.css)), Segoe UI Variable, header
      with connection pill + copyable node chip, InfoBar banners for
      reconnect/relay incidents, segmented mode selector on room creation,
      status pills (direct/relayed/connecting/unreachable) per peer,
      invite-code chip, hero connect screen, restyled settings. Tauri
      window forced dark (`theme: Dark`, dark `backgroundColor` — no white
      flash). Plus a **browser demo mode** ([api.ts](hermes-ui/src/api.ts) +
      [mock.ts](hermes-ui/src/mock.ts)): `npm run dev` outside Tauri serves
      a simulated node so every screen is reviewable without a daemon or
      admin rights (`?demo=relaydown` scripts a relay incident).
      Still open: join link/QR, light theme variant.

## P5 — testing & CI

- [x] **CI matrix** (GitHub Actions): build + `cargo test` of the engine
      and servers on Windows **and** Linux, `fmt --check`, a frontend
      `npm run build`, and a full Tauri build on Windows
      ([.github/workflows/ci.yml](.github/workflows/ci.yml)). Builds use
      `--locked`; `RUSTFLAGS=-D warnings` gates the workspace (deps are
      lint-capped). The tree is fmt-clean and rustc-warning-clean.
- [x] **Driver-loop tests with a mock adapter.** `HermesEngine` takes an
      adapter factory (`with_adapter_factory`); `tap::mock::MockAdapter`
      runs in either Ethernet (Linux TAP) or IP (wintun) mode.
      `hermes-signaling/tests/engine_e2e.rs` runs two whole engines through
      the real signaling binary — one posing as Linux, one as Windows — and
      checks unicast both ways, ARP answered by the shim, and broadcast,
      without privileges, on every CI platform.
- [x] **Parser robustness** (`hermes-core/tests/parsers_proptest.rs`,
      property-based, runs on stable in CI): the relay protocol, tunnel
      framing, ARP, MAC classifier, wintun shim, STUN, ICE probes, signaling
      JSON and invite codes never panic on arbitrary or packet-shaped bytes
      and round-trip; any bit-flip of a relay REGISTER fails verification;
      and arbitrary datagrams from arbitrary addresses fed into a live mesh
      with a real tunnel never decrypt into a frame. A 150 000-cases-per-
      property run (`PROPTEST_CASES=150000`, ~2 M inputs) found nothing.
      Still open: coverage-guided fuzzing (`cargo-fuzz`, needs nightly) of
      the same parsers and of boringtun's handshake path.
- [x] **P2P ICE path test** — `hermes-core/tests/p2p_e2e.rs`: two meshes
      probe each other, build direct tunnels, carry unicast + broadcast
      frames; plus roaming, spoofing and STUN-through-demux tests.
- [x] Clippy in CI with the existing `#![warn(clippy::pedantic)]` lints
      (runs informationally — pedantic is intentionally noisy, so it
      surfaces suggestions without failing the build).
      enforced.

## P6 — future features / nice-to-have

- [ ] **macOS support** — `utun` + software Ethernet synthesis (like the
      wintun L2/L3 shim already does).
- [ ] **Mobile** (Android via Tauri 2 mobile + VpnService) — likely
      relay-only given platform NAT constraints.
- [ ] **IPv6 virtual addressing** (currently a v4 `/16` per room). The
      wintun shim also drops IPv6 *unicast* (needs neighbour-discovery
      emulation); IPv6 multicast such as mDNS is carried.
- [x] **Virtual IP collisions avoided.** Addresses are a 16-bit hash of
      the node id (~1% chance of some collision at 36 members). The
      signaling server now assigns each joiner an `ip_salt`: the smallest
      one under which its address is free among current members, so
      veterans never move and only a colliding newcomer gets the next
      address in its (deterministic) sequence. Salt 0 = the classic
      address, so old clients interoperate. Switching rooms (or a changed
      address on re-join) now tears the old adapter down first.
- [x] **Metrics endpoints** for both servers (Prometheus text format,
      off unless `HERMES_RELAY_METRICS_BIND` / `HERMES_SIGNALING_METRICS_BIND`
      is set): sessions, rooms, forwarded packets/bytes, drops by reason,
      registration outcomes, rate-limit hits, auth failures. Aggregate only —
      verified in e2e tests that no addresses, node ids, names or codes leak
      into the output. See SERVER-OPERATIONS.md.
- [ ] **Multi-relay / geo-routing** — members pick the nearest relay;
      relays mesh to each other.
- [x] **Room persistence** across restarts: the daemon remembers the last
      room (`resume.json`, mode 0600, in its data dir) and rejoins it after a
      restart, retrying for 15 minutes. `leave`, or connecting elsewhere,
      forgets it; `HERMES_RESUME=0` disables it. Tested in `resume_e2e.rs`.
- [x] **Access control beyond invite codes** — the room owner can rotate
      the invite code, kick or ban members; rooms can have a password.
      Protocol v5, IPC v4; in the CLI (`kick`,
      `rotate-invite`, `--password`) and the app. Tested in `access_e2e.rs`
      and `engine_e2e.rs`. Cryptographic enforcement of kick/ban is listed under
      open problems in THREAT-MODEL.md.
- [ ] **Bandwidth/QoS** controls and per-room MTU negotiation.

---

### Suggested order

1. P0 MTU fix + buffer audit, then the two-machine smoke test (these
   gate "does it actually work end to end").
2. Linux build/test (P1) — unblocks the cross-platform promise.
3. Auto-reconnect + P2P→relay fallback (P2) — the biggest reliability wins.
4. Packaging + CI (P1/P5) in parallel once the above is solid.
