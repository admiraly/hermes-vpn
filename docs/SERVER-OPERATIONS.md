# Server operations — running and publishing the Hermes fleet

This is the operator's guide: how to run signaling and relay servers,
and how to make new servers appear in every user's client.

## The two server types

| Binary | Protocol | Default port | Purpose |
|---|---|---|---|
| `hermes-signaling` | WebSocket (HTTP upgrade) | `8787/tcp` | Rendezvous: auth, rooms, candidate exchange |
| `hermes-relay` | UDP | `8788/udp` | Forwards end-to-end-encrypted traffic for relayed rooms |

Both are single static binaries with no config files — environment
variables only. Neither needs root (they bind high ports), neither
stores anything on disk, and both are safe to restart at any time
(clients re-register / reconnect automatically).

## Running a signaling server

```sh
HERMES_SIGNALING_BIND=0.0.0.0:8787 RUST_LOG=info ./hermes-signaling
```

- Health check: `GET /health` → `ok` (point your uptime monitor here).
- WebSocket endpoint: `/v1`.
- For public deployments, put it behind a TLS-terminating reverse proxy
  (Caddy, nginx) so clients connect via `wss://`:

```caddyfile
signal.example.net {
    reverse_proxy 127.0.0.1:8787
}
```

The client address for this server is then `wss://signal.example.net/v1`.

## Running a relay server

```sh
HERMES_RELAY_BIND=0.0.0.0:8788 RUST_LOG=info ./hermes-relay
```

- Pure UDP — no TLS proxy needed or possible (the payload is WireGuard
  ciphertext; registrations are Ed25519-signed).
- Open `8788/udp` in the firewall. That's the whole setup.
- Sizing: the relay copies packets between sockets; a small VPS handles
  hundreds of Mbit/s. Each room member costs one map entry (~100 bytes).

> **Multi-homed hosts just work.** With the default wildcard bind
> (`0.0.0.0:8788`) the relay opens one socket per local IPv4 address
> (re-scanned every 30 s) and always answers a client from the address it
> sent to — clients and their NATs drop replies from any other source.
> Set `HERMES_RELAY_BIND=<ip>:8788` only to restrict it to one address.

## systemd units

`/etc/systemd/system/hermes-signaling.service`:

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

`/etc/systemd/system/hermes-relay.service` — identical except:

```ini
ExecStart=/opt/hermes/hermes-relay
Environment=HERMES_RELAY_BIND=0.0.0.0:8788
```

Then `systemctl enable --now hermes-signaling hermes-relay`.

## Publishing servers to all clients: the directory manifest

Clients fetch a JSON manifest from a URL you control, merge it into
their server list, and cache it on disk for offline starts. **Adding a
new server to the fleet = adding one line to this file.** No client
update, no reinstall.

Manifest format (see [hermes-servers.example.json](hermes-servers.example.json)):

```json
{
  "version": 1,
  "signaling": [
    { "name": "EU — Frankfurt", "address": "wss://eu1.example.net/v1" },
    { "name": "US — Chicago",   "address": "wss://us1.example.net/v1" }
  ],
  "relays": [
    { "name": "EU — Frankfurt relay", "address": "eu1.example.net:8788" },
    { "name": "US — Chicago relay",   "address": "us1.example.net:8788" }
  ]
}
```

Host it anywhere that serves HTTPS with a stable URL:

- a GitHub repo (`https://raw.githubusercontent.com/you/hermes-fleet/main/servers.json`),
- any static host / object storage / your VPS.

Rules:

- `name` is the identity — renaming an entry effectively removes and
  re-adds it. Same-named entries shadow built-ins; user-added entries
  shadow yours.
- Signaling addresses are full WebSocket URLs (`wss://host/v1`);
  relay addresses are `host:port`.
- Removing a line removes the server from clients on their next refresh
  (startup or the *Refresh now* button).

Users point their client at the manifest once: **⚙ Servers → Server
directory → paste URL → Save**. Ship a default by setting the URL in
your distributed builds (`servers.toml` in the daemon data dir, key
`manifest_url`) — after that, the fleet is entirely under your control.

## Checklist: bringing a new region online

1. Provision a VPS; copy `hermes-signaling` and/or `hermes-relay` to
   `/opt/hermes/`.
2. Install the systemd units, open `8787/tcp` (proxied via TLS) and/or
   `8788/udp`.
3. Verify: `curl https://<host>/health` → `ok`; for the relay, create a
   relayed test room against it.
4. Add the new entries to your hosted `servers.json`.
5. Done — clients see the new servers on their next directory refresh.
