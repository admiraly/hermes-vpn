# Deploying Hermes — step by step

This is the end-to-end runbook for standing up Hermes: the two servers
(**signaling** + **relay**) and the **client** (daemon + desktop UI), on
both **Linux** and **Windows**.

> **Keeping this current.** Every port, environment variable, and file
> path below is the value hard-coded in the source today, with the file it
> lives in noted in [§1](#1-reference--ports-env-vars-file-locations). If
> you change a default in code, update the matching row here. This file is
> versioned with the code, so a given commit's instructions always match
> that commit's binaries.

---

## 0. The pieces

| Component | Binary | Role | Runs on | Listens |
|---|---|---|---|---|
| Signaling | `hermes-signaling` | Rendezvous: auth, rooms, candidate exchange | A server you control (or localhost) | `8787/tcp` |
| Relay | `hermes-relay` | Forwards end-to-end-encrypted traffic for relayed / fallback rooms | A server you control (or localhost) | `8788/udp` |
| Daemon | `hermes-daemon` | Owns the virtual adapter + engine; serves the UI over local IPC | Each user's machine (elevated) | local socket |
| UI | `hermes-ui` (Tauri app) | The app you click | Each user's machine | talks to daemon |

You need **at least one signaling server** for any room. You need a
**relay server** only if you want "central server" rooms or P2P rooms with
relay fallback. Both servers are tiny, stateless, and safe to restart any
time — clients reconnect/re-register automatically.

---

## 1. Reference — ports, env vars, file locations

**Servers**

| Server | Bind env var | Default | Log env | Defined in |
|---|---|---|---|---|
| Signaling | `HERMES_SIGNALING_BIND` | `0.0.0.0:8787` | `RUST_LOG` (default `info`) | `hermes-signaling/src/main.rs` |
| Relay | `HERMES_RELAY_BIND` | `0.0.0.0:8788` | `RUST_LOG` (default `info`) | `hermes-relay/src/main.rs` |

- Signaling HTTP routes: `GET /health` → `ok`, `GET /v1` → WebSocket.
- Client signaling address form: `ws://host:8787/v1`, or `wss://host/v1`
  behind a TLS proxy.
- Client relay address form: `host:8788` (plain `host:port`, no scheme).

**Client file locations** (data dir, holds `identity.key` + `servers.toml`)

| OS | Daemon data dir | Daemon IPC socket |
|---|---|---|
| Linux (run as your user) | `~/.local/share/Hermes/` | `$XDG_RUNTIME_DIR/hermes/daemon.sock` |
| Linux (run via `sudo`) | `/root/.local/share/Hermes/` | `/run/user/0/hermes/...` (⚠ see [§5a](#5a-linux-client)) |
| Windows | `%APPDATA%\hermes\Hermes\data\` | `\\.\pipe\hermes-daemon` |

---

## 2. Build the binaries

You can build everything from one `cargo` workspace. Skip to a prebuilt
release if you have one; otherwise:

### 2a. Linux (servers, and optionally the client)

```sh
# Toolchain
sudo apt update
sudo apt install -y build-essential pkg-config curl
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"

# Source
git clone <your-repo-url> hermes && cd hermes

# Servers only (this is all a VPS needs):
cargo build --release -p hermes-signaling -p hermes-relay
# → target/release/hermes-signaling, target/release/hermes-relay
```

For the **client** on Linux you also need the daemon and the UI:

```sh
# Daemon
cargo build --release -p hermes-daemon          # → target/release/hermes-daemon

# UI (Tauri) — extra system libs:
sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev \
                    libayatana-appindicator3-dev librsvg2-dev libssl-dev nodejs npm
cd hermes-ui
npm install
npx tauri build        # → src-tauri/target/release/bundle/ (AppImage/.deb)
# or for development: npx tauri dev
```

### 2b. Windows (client, and optionally the servers)

Rust on Windows needs a C linker. Either works:

- **MSVC**: install "Build Tools for Visual Studio" with the *Desktop
  development with C++* workload, then use the default
  `stable-x86_64-pc-windows-msvc` toolchain.
- **MinGW (no admin)**: this is what the repo is developed against.
  ```powershell
  winget install BrechtSanders.WinLibs.POSIX.UCRT   # portable GCC
  rustup toolchain install stable-x86_64-pc-windows-gnu
  cd hermes
  rustup override set stable-x86_64-pc-windows-gnu   # scoped to this dir
  ```
  Open a fresh terminal afterwards so `gcc` is on `PATH`.

Then:

```powershell
# Daemon
cargo build --release -p hermes-daemon       # → target\release\hermes-daemon.exe

# UI
cd hermes-ui
npm install
npm run build
npx tauri build       # → src-tauri\target\release\bundle\ (MSI/NSIS installer)

# (Optional) the servers also build on Windows:
cargo build --release -p hermes-signaling -p hermes-relay
```

See [BUILDING.md](../BUILDING.md) for toolchain detail and gotchas.

---

## 3. Deploy the signaling server (Linux VPS)

1. **Copy the binary** to the server:
   ```sh
   scp target/release/hermes-signaling user@your-server:/tmp/
   ssh user@your-server
   sudo mkdir -p /opt/hermes && sudo mv /tmp/hermes-signaling /opt/hermes/
   ```

2. **Try it in the foreground** first:
   ```sh
   HERMES_SIGNALING_BIND=0.0.0.0:8787 RUST_LOG=info /opt/hermes/hermes-signaling
   ```
   From another terminal: `curl http://your-server:8787/health` → `ok`.

3. **Run it as a service** — `/etc/systemd/system/hermes-signaling.service`:
   ```ini
   [Unit]
   Description=Hermes signaling server
   After=network-online.target
   Wants=network-online.target

   [Service]
   ExecStart=/opt/hermes/hermes-signaling
   Environment=HERMES_SIGNALING_BIND=0.0.0.0:8787
   Environment=RUST_LOG=info
   Restart=always
   RestartSec=2
   DynamicUser=yes
   NoNewPrivileges=yes
   ProtectSystem=strict
   ProtectHome=yes

   [Install]
   WantedBy=multi-user.target
   ```
   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now hermes-signaling
   sudo systemctl status hermes-signaling
   ```

4. **Add TLS (strongly recommended for anything public).** Terminate TLS
   with a reverse proxy so clients use `wss://`. With Caddy
   (`/etc/caddy/Caddyfile`):
   ```caddyfile
   signal.example.net {
       reverse_proxy 127.0.0.1:8787
   }
   ```
   ```sh
   sudo systemctl reload caddy
   ```
   Your client signaling address is then **`wss://signal.example.net/v1`**.
   Without a proxy it's `ws://your-server:8787/v1` (unencrypted control
   channel — fine for a LAN/testing, not for the public internet).

5. **Firewall**: open `8787/tcp` (or `443/tcp` if only the proxy is public).
   ```sh
   sudo ufw allow 8787/tcp
   ```

---

## 4. Deploy the relay server (Linux VPS)

The relay is pure UDP — no TLS proxy needed or possible (payloads are
already WireGuard ciphertext; registrations are Ed25519-signed).

1. **Copy and try it**:
   ```sh
   scp target/release/hermes-relay user@your-server:/tmp/
   ssh user@your-server
   sudo mv /tmp/hermes-relay /opt/hermes/
   HERMES_RELAY_BIND=0.0.0.0:8788 RUST_LOG=info /opt/hermes/hermes-relay
   ```

2. **Service** — `/etc/systemd/system/hermes-relay.service` (same as the
   signaling unit, with these two lines changed):
   ```ini
   ExecStart=/opt/hermes/hermes-relay
   Environment=HERMES_RELAY_BIND=0.0.0.0:8788
   ```
   ```sh
   sudo systemctl daemon-reload
   sudo systemctl enable --now hermes-relay
   ```

3. **Firewall**: open `8788/udp`.
   ```sh
   sudo ufw allow 8788/udp
   ```
   Your client relay address is **`your-server:8788`**.

> You can run the signaling and relay servers on the **same** VPS — they
> use different ports and protocols (8787/tcp vs 8788/udp).

---

## 5. Install & run the client

The client is two processes: the **daemon** (privileged, owns the virtual
adapter) and the **UI** (runs as you). Start the daemon first.

### 5a. Linux client

The daemon needs `CAP_NET_ADMIN`. **Use `setcap`, not `sudo`** — that way
the daemon runs as *your* user and shares your `$XDG_RUNTIME_DIR`, so the
UI can find its socket. (Running via `sudo` puts the socket under root's
runtime dir and the UI won't connect.)

```sh
# One-time: ensure the TUN module is available
sudo modprobe tun

# Grant the capability to the daemon binary (re-run after each rebuild)
sudo setcap cap_net_admin=+ep target/release/hermes-daemon

# Start the daemon as your normal user
./target/release/hermes-daemon
```

Then launch the UI (the AppImage/.deb you built, or `npx tauri dev`) **as
the same user**. It connects to the daemon automatically.

### 5b. Windows client

1. **Get `wintun.dll`**: download from <https://www.wintun.net>, take the
   `amd64` build, and place `wintun.dll` **next to `hermes-daemon.exe`**.

2. **Run the daemon as Administrator** (it must create the wintun adapter):
   right-click `hermes-daemon.exe` → *Run as administrator*, or from an
   elevated PowerShell:
   ```powershell
   .\hermes-daemon.exe
   ```

3. **Run the UI.** Install/launch the Tauri app you built.
   > ⚠ If the UI shows "Cannot reach the Hermes daemon", run the UI **as
   > Administrator too** — a non-elevated app may be unable to open the
   > elevated daemon's named pipe. Running both elevated is the simple fix
   > until a service installer lands.

---

## 6. Point the client at your servers

Out of the box the client only knows `localhost` servers. Add yours:

### Option A — in the UI (easiest)

1. Open the app → **⚙ Servers**.
2. Under **Add a server**, add your **Signaling** entry
   (`wss://signal.example.net/v1`) and your **Relay** entry
   (`your-server:8788`). Give each a name.
3. In the signaling list, select the radio next to your server to make it
   **active** (this is what *Connect* will use).

### Option B — a hosted directory (best for many users)

Host one JSON file and every client picks up new servers on refresh — no
client changes. See
[SERVER-OPERATIONS.md → "the directory manifest"](SERVER-OPERATIONS.md#publishing-servers-to-all-clients-the-directory-manifest)
and the example [hermes-servers.example.json](hermes-servers.example.json).
In the UI: **⚙ Servers → Server directory → paste the URL → Save**, then
**Refresh now**.

### Option C — edit `servers.toml` directly (headless)

The daemon persists the directory at `<data dir>/servers.toml`
(see [§1](#1-reference--ports-env-vars-file-locations)). You can edit it
while the daemon is stopped; keys: `manifest_url`, `active_signaling`,
`custom_signaling`/`custom_relays` (each a `[[...]]` array of
`{ name, address }`).

---

## 7. Create or join a room

1. In the UI, click **Connect to signaling server**.
2. **Create Room** and pick a mode:
   - **Pure peer-to-peer** — direct tunnels; optionally tick *"fall back to
     a relay if a direct connection can't be made"* and pick your relay.
   - **Via central server** — all traffic through the relay you pick (works
     behind any NAT/firewall).
3. Share the **invite code** (the *Copy* button) out-of-band with the other
   members.
4. On the other machine: **Connect** → **Join Room** → paste the code.

The peer list shows each member's **Path** (Direct / Relayed), live
**Traffic**, and **Handshake** age, so you can confirm how each link
connected.

---

## 8. Verify & troubleshoot

| Symptom | Likely cause / fix |
|---|---|
| `curl …/health` fails | Signaling not running or firewall closed (`8787/tcp`). |
| Client won't connect to signaling | Wrong address (needs `…/v1`), or `wss://` vs `ws://` mismatch with your proxy. |
| UI: "Cannot reach the Hermes daemon" | Daemon not started; on Linux you used `sudo` (socket under root — use `setcap` instead); on Windows run the UI elevated. |
| Windows daemon fails to start | `wintun.dll` missing next to the exe, or not running as Administrator. |
| Linux daemon: "operation not permitted" | Missing `CAP_NET_ADMIN` (`setcap …`) or `tun` module not loaded (`modprobe tun`). |
| Relayed room never connects | Relay unreachable: `8788/**udp**` closed, or wrong `host:port` (no scheme). |
| Peer stuck on "Connecting" then "Stale" (P2P) | Both sides behind hard NAT — enable relay fallback or use a central-server room. |
| Large transfers stall | Almost always MTU; the adapter is pinned to 1340 — if you changed it, re-check the budget in `hermes-core/src/tap/mod.rs`. |

Useful logs: run any component with `RUST_LOG=debug` (servers and daemon)
to see registrations, room events, and path decisions.

---

## 9. Updating to a new version

1. Rebuild (`git pull` then the `cargo build --release …` from [§2](#2-build-the-binaries)).
2. **Servers**: copy the new binary over the old one and
   `sudo systemctl restart hermes-signaling hermes-relay`. Clients
   reconnect/re-register on their own.
3. **Client**: replace the daemon binary; on Linux **re-run `setcap`**
   (it's cleared on replace); reinstall the UI bundle.
4. If the signaling or IPC **protocol version** changed (constants in
   `hermes-core/src/lib.rs` / `hermes-daemon/src/protocol.rs`), update
   servers and clients together — mismatched versions are rejected at
   handshake by design.

For hardened systemd units and fleet/manifest operations, see
[SERVER-OPERATIONS.md](SERVER-OPERATIONS.md).
