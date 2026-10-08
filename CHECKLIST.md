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
- [x] 55 tests pass on Linux, warning-free under `-D warnings`; the
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
- [ ] **First relayed packet can be dropped.** If A sends before B has
      registered, the relay drops the `DATA` (no destination session yet).
      WireGuard retransmits so it self-heals, and the keepalive front-loads
      registration (2 s × 5 at startup), so in practice both peers register
      before tunnels form — but verify connection-setup latency on the
      two-machine test; if slow, have the relay briefly queue one packet
      per unknown dest.
- [~] **Real two-machine smoke test, both modes.** The namespace smoke
      test now proves real adapters and all three room modes on Linux. Still
      needed: two separate hosts behind *real* NATs, one of them Windows
      (wintun + shim have only been compiled and unit-tested, never run).
      Follow [TEST-RUN.md](TEST-RUN.md).
- [ ] **Relay replies from the wrong address on multi-homed hosts.** A
      relay bound to `0.0.0.0` answers from whichever local IP routes back
      to the client; clients (and their NATs) drop replies from an
      unexpected address. Documented workaround: bind to the public IP.
      Real fix: answer from the packet's destination address
      (`IP_PKTINFO`), or bind one socket per local address.

## P1 — platform & packaging (needed for a release)

- [x] **Build & test on Linux.** Whole workspace including the Tauri app
      builds on Linux, `cargo test` passes, and the netns smoke test runs
      the daemon, Unix-socket IPC and TAP adapter for real.
- [ ] **Bundle `wintun.dll`** with the Windows build/installer (must sit
      next to `hermes-daemon.exe`); document or automate the copy.
- [ ] **Daemon lifecycle / service install.** Today the daemon is launched
      by hand. Decide: Tauri sidecar that spawns it elevated, a Windows
      service + systemd unit, or a one-click installer. Wire it up. Two
      deployment gotchas to solve as part of this (documented in
      [DEPLOYMENT.md](docs/DEPLOYMENT.md) §5/§8):
      - **Linux:** running the daemon via `sudo` puts its IPC socket under
        root's `$XDG_RUNTIME_DIR`, so a UI running as the user can't find
        it. Workaround is `setcap` (run as user); a service should expose a
        well-known socket path both can agree on.
      - **Windows:** a non-elevated UI may be unable to open the elevated
        daemon's named pipe (default pipe ACL). Workaround is running the
        UI elevated too; the fix is a permissive-but-safe pipe security
        descriptor (or a proper service + client identity check).
- [ ] **Real app icons & branding** — replace the generated placeholder
      [icons](hermes-ui/src-tauri/icons) with real artwork; add `.icns` if
      macOS is ever targeted.
- [ ] **Release builds & artifacts**: `tauri build` bundles for Windows
      (MSI/NSIS) and Linux (AppImage/deb), plus standalone server binaries.
- [ ] **Set a default manifest URL** in distributed builds so the official
      fleet appears out of the box.
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
- [ ] **UPnP mappings are never renewed or removed.** We request a 1 h
      lease (falling back to indefinite) and forget about it. Renew while
      in a room; delete on leave/shutdown.

## P3 — security hardening

- [ ] **Threat-model the relay.** Anyone who learns a room UUID can
      `REGISTER` and inject `DATA` (WireGuard rejects it, so it's harmless
      beyond bandwidth) — document this, and add per-IP rate limiting /
      registration caps to blunt DoS.
- [ ] **Enforce `wss://` for non-localhost** signaling; warn loudly on
      plaintext `ws://` to a remote host.
- [ ] **Rate-limit `JoinRoom`** attempts on the signaling server to slow
      invite-code guessing (the space is large, but defense in depth).
- [ ] **Relay source-binding note.** `DATA` sender identity comes from UDP
      source address; document the E2E-encryption mitigation and consider
      binding sessions more tightly.
- [ ] Run `cargo audit` / dependency review; pin and review the crypto
      stack (`boringtun`, `ed25519-dalek`, `x25519-dalek`).
- [ ] Independent review of the relay replay-protection and the invite-code
      checksum.

## P4 — UX / UI polish

- [ ] **Editable alias** — currently hardcoded `"hermes-user"`
      ([engine.rs default config](hermes-core/src/engine.rs)); add a setting.
- [x] **Copy-invite-code button** — added to the room view (clipboard).
      A shareable join link/QR is still open.
- [x] **Show which signaling server is active** — the connect screen now
      shows "via <server>" with a pointer to settings.
- [x] **Surface per-peer stats.** `Mesh::link_stats()` exposes each
      tunnel's live byte/frame counters, handshake age, and direct-vs-relayed
      path through `GetState`; the UI peer list now polls (2 s) and shows
      Path / Traffic / Handshake columns. A relay e2e assertion proves the
      counters move.
- [ ] **Wire up peer latency.** `latency_ms` and `Room::set_latency` exist
      but are never populated ([engine_pump.rs](hermes-core/src/engine_pump.rs)) —
      add a periodic ping/RTT probe. (Handshake-age is now shown as a
      liveness proxy in the meantime.)
- [ ] **Tray menu** — `trayIcon` is configured in `tauri.conf.json` but has
      no menu/actions; add minimize-to-tray + quick room status.
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
      Still open: tray menu, join link/QR, light theme variant.

## P5 — testing & CI

- [x] **CI matrix** (GitHub Actions): build + `cargo test` of the engine
      and servers on Windows **and** Linux, `fmt --check`, a frontend
      `npm run build`, and a full Tauri build on Windows
      ([.github/workflows/ci.yml](.github/workflows/ci.yml)). Builds use
      `--locked`; `RUSTFLAGS=-D warnings` gates the workspace (deps are
      lint-capped). The tree is fmt-clean and rustc-warning-clean.
- [ ] **Driver-loop test** with a mock `VirtualAdapter` (no real TAP) to
      cover the full TAP↔mesh path without privileges.
- [ ] **Frame-parser fuzzing** for the relay protocol, framing, ARP, and
      classifier parsers.
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
- [ ] **Virtual IP collision detection.** Addresses are a 16-bit hash of
      the node id: ~2^-16 per pair, ~1% at 36 members. Detect on join and
      re-derive with a salt.
- [ ] **Relay metrics/stats endpoint** (the original spec mentioned one):
      Prometheus counters for sessions, forwarded bytes, drops.
- [ ] **Multi-relay / geo-routing** — members pick the nearest relay;
      relays mesh to each other.
- [ ] **Room persistence & named identities** across restarts; reconnect to
      the last room automatically.
- [ ] **Access control beyond invite codes** — revocable codes, per-member
      kick/ban, room passwords.
- [ ] **Bandwidth/QoS** controls and per-room MTU negotiation.

---

### Suggested order

1. P0 MTU fix + buffer audit, then the two-machine smoke test (these
   gate "does it actually work end to end").
2. Linux build/test (P1) — unblocks the cross-platform promise.
3. Auto-reconnect + P2P→relay fallback (P2) — the biggest reliability wins.
4. Packaging + CI (P1/P5) in parallel once the above is solid.
