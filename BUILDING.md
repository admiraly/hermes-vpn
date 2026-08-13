# Building Hermes

Hermes targets **stable Rust 1.85+** (developed against current stable)
and **Node 18+** for the UI.

## Linux

```sh
sudo apt install -y build-essential pkg-config   # or your distro's equivalent
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

git clone <repo> && cd hermes
cargo build --workspace --release
```

UI extras (only on the machine that builds the desktop app):

```sh
sudo apt install -y libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev \
                    librsvg2-dev libssl-dev
cd hermes-ui && npm install && npx tauri build
```

Runtime requirements:

- The **daemon** needs `CAP_NET_ADMIN` for the TUN/TAP adapter:
  `sudo setcap cap_net_admin=+ep target/release/hermes-daemon`
  (or just run it with `sudo`). The `tun` kernel module must be loaded.
  Note `setcap` genuinely suffices: the adapter's MAC, address, and link
  state are configured over netlink from inside the process. It must stay
  that way — capabilities are not inherited across `exec`, so shelling out
  to `ip` would silently break the unprivileged path even though the device
  itself gets created. Re-run `setcap` after replacing the binary; it is
  cleared on write.
- `hermes-signaling` and `hermes-relay` are plain unprivileged binaries.

## Windows

Rust on Windows needs a linker. Either flavor works:

### Option A — MSVC (the usual choice)

Install [Build Tools for Visual Studio](https://visualstudio.microsoft.com/downloads/)
with the "Desktop development with C++" workload, then build with the
default `stable-x86_64-pc-windows-msvc` toolchain.

### Option B — MinGW-w64 (no admin rights required)

```powershell
winget install BrechtSanders.WinLibs.POSIX.UCRT     # portable GCC, per-user
rustup toolchain install stable-x86_64-pc-windows-gnu
cd hermes
rustup override set stable-x86_64-pc-windows-gnu    # scoped to this directory
cargo build --workspace
```

Open a fresh terminal after the winget install so `gcc` is on `PATH`.
This is the configuration the repository is developed and tested with.

### Windows runtime notes

- The **daemon** must run as **Administrator** to create the wintun
  adapter.
- [`wintun.dll`](https://www.wintun.net) (the `amd64` build) must sit
  next to `hermes-daemon.exe`.
- The UI talks to the daemon over the `\\.\pipe\hermes-daemon` named
  pipe and needs no elevation itself.

## The UI

```sh
cd hermes-ui
npm install
npm run build        # type-check + bundle the frontend (required once before cargo check)
npx tauri dev        # development with hot reload
npx tauri build      # distributable bundle
```

Note: `cargo check -p hermes-ui` fails until `hermes-ui/dist/` exists —
Tauri embeds the frontend at compile time. Run `npm run build` first.

## Tests

```sh
cargo test --workspace
```

This includes real end-to-end tests: the relay and signaling test suites
spawn the actual server binaries and drive them over loopback — including
a complete WireGuard handshake through the relay. No elevated privileges
needed; only the TAP adapter itself requires admin, and no test touches it.

## Servers on a VPS

`hermes-signaling` and `hermes-relay` are small static-ish binaries with
no runtime dependencies beyond glibc. Build with
`cargo build --release -p hermes-signaling -p hermes-relay` on a Linux
box (or in CI) and copy `target/release/hermes-{signaling,relay}` to the
server. See [docs/SERVER-OPERATIONS.md](docs/SERVER-OPERATIONS.md).
