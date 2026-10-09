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

Behind a proxy, also set **`HERMES_SIGNALING_TRUST_PROXY=1`**: abuse limits
are per client IP, and without it every client appears to come from the
proxy's address and shares one allowance. (Only set it when a proxy you
control is in front — otherwise clients could forge `X-Forwarded-For`.)

Clients connecting over plaintext `ws://` to a remote host get a prominent
warning: invite codes can be read on the network path, and a code is all
it takes to join a room.

### Signaling limits (per client IP)

| Variable | Default | What it limits |
|---|---|---|
| `HERMES_SIGNALING_CONNECTIONS_PER_MIN` | 120 | New WebSocket connections (excess gets HTTP 429) |
| `HERMES_SIGNALING_ROOM_OPS_PER_MIN` | 60 | `create_room` + `join_room` attempts — caps invite-code guessing |
| `HERMES_SIGNALING_IDLE_TIMEOUT_SECS` | 45 | Silence before a connection is considered dead (clients ping every 15 s) |
| `HERMES_SIGNALING_TRUST_PROXY` | off | Take the client IP from `X-Forwarded-For` |

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

### Relay limits

| Variable | Default | What it limits |
|---|---|---|
| `HERMES_RELAY_REGISTERS_PER_SEC` | 100 | `REGISTER`s per source IP (checked before the signature) |
| `HERMES_RELAY_MAX_SESSIONS_PER_IP` | 256 | Sessions per source IP (generous for CGNAT) |
| `HERMES_RELAY_MAX_SESSIONS` | 100000 | Sessions in total |

Packets for a member that hasn't registered yet are held briefly (up to 4
per destination, 3 s, 4096 overall) and delivered once it registers.

## Metrics (optional)

Both servers can expose Prometheus metrics. They're **off by default**: set a
bind address to turn them on, and keep it on localhost or an internal
interface (the numbers are aggregate — no node ids, addresses or invite
codes — but there's no reason to publish them).

| Variable | Serves |
|---|---|
| `HERMES_SIGNALING_METRICS_BIND=127.0.0.1:9101` | `/metrics`, `/health` for the signaling server |
| `HERMES_RELAY_METRICS_BIND=127.0.0.1:9102` | `/metrics`, `/health` for the relay |

```sh
curl -s http://127.0.0.1:9102/metrics
```

Useful series: `hermes_relay_sessions`, `hermes_relay_forwarded_bytes_total`,
`hermes_relay_registers_total{result="bad_signature|replay|limited"}`,
`hermes_relay_dropped_packets_total{reason=…}`, `hermes_signaling_sessions`,
`hermes_signaling_rooms`, `hermes_signaling_auth_failures_total`,
`hermes_signaling_room_events_total{kind="invalid_code|rate_limited|…"}`.
A rising `bad_signature`, `invalid_code` or `rate_limited` count is the
signature of someone probing the server.

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
