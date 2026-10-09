// Demo backend for browser previews (no Tauri, no daemon). Simulates a
// node with a plausible little network so every screen and state of the
// UI is reachable: connect, create/join a room, peers appearing with
// live traffic, (via ?demo=relaydown) a relay-health incident, and (via
// ?demo=insecure) a plaintext ws:// signaling server.

import type {
  DaemonEvent,
  LinkStats,
  Peer,
  RoomMode,
  ServerListing,
  StateSnapshot,
} from "./types";

type Handler = (event: DaemonEvent) => void;
const handlers = new Set<Handler>();

function emit(event: DaemonEvent) {
  for (const h of handlers) h(event);
}

const DEMO_PEERS: Array<{ alias: string; ip: string; relayed: boolean }> = [
  { alias: "lisa-desktop", ip: "10.42.183.20", relayed: false },
  { alias: "kai-laptop", ip: "10.42.97.4", relayed: true },
  { alias: "server-rack", ip: "10.42.12.201", relayed: false },
];

interface DemoState {
  connected: boolean;
  room: StateSnapshot["room"];
  invite: string | null;
  alias: string;
  peers: Peer[];
  links: LinkStats[];
  relayHealthy: boolean | null;
  servers: ServerListing;
  timers: number[];
}

const state: DemoState = {
  connected: false,
  room: null,
  alias: "this-machine",
  invite: null,
  peers: [],
  links: [],
  relayHealthy: null,
  servers: {
    signaling: [
      { name: "Local", address: "ws://127.0.0.1:8787/v1", source: "built_in" },
      { name: "EU — Frankfurt", address: "wss://eu1.hermes.example/v1", source: "manifest" },
      { name: "US — Chicago", address: "wss://us1.hermes.example/v1", source: "manifest" },
      { name: "My VPS", address: "wss://vpn.my-domain.dev/v1", source: "custom" },
    ],
    relays: [
      { name: "Local relay", address: "127.0.0.1:8788", source: "built_in" },
      { name: "EU — Frankfurt relay", address: "eu1.hermes.example:8788", source: "manifest" },
      { name: "My VPS relay", address: "vpn.my-domain.dev:8788", source: "custom" },
    ],
    manifest_url: "https://raw.githubusercontent.com/you/hermes-fleet/main/servers.json",
    active_signaling: "EU — Frankfurt",
  },
  timers: [],
};

function nodeId(seed: string): string {
  // Stable fake base64-ish ids per alias.
  let h = 0;
  for (const c of seed) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  return btoa(`${seed}-${h}`).replace(/[+/=]/g, "").padEnd(43, "x").slice(0, 43);
}

const insecureDemo = new URLSearchParams(location.search).get("demo") === "insecure";

function snapshot(): StateSnapshot {
  return {
    node_id_base64: nodeId("this-machine"),
    alias: state.alias,
    connected: state.connected,
    local_endpoint: state.connected ? "192.168.1.34:52913" : null,
    reflexive_endpoint: state.connected ? "84.163.20.77:52913" : null,
    room: state.room,
    peers: state.peers,
    links: state.links,
    relay_healthy: state.relayHealthy,
    signaling_url: state.connected ? (insecureDemo ? "ws" : "wss") + "://signal.example.net/v1" : null,
    signaling_insecure: state.connected && insecureDemo,
  };
}

function addDemoPeer(i: number) {
  const spec = DEMO_PEERS[i];
  if (!spec || !state.room) return;
  const relayed = state.room.mode === "relayed" ? true : spec.relayed;
  const peer: Peer = {
    node_id: nodeId(spec.alias),
    wireguard_public: [],
    alias: spec.alias,
    virtual_ipv4: spec.ip,
    virtual_mac: "02:aa:bb:cc:dd:0" + i,
    status: "connecting",
    latency_ms: null,
  };
  state.peers.push(peer);
  emit({ event: "peer_added", peer });

  // Connect after a moment, then start ticking traffic.
  const t = window.setTimeout(() => {
    peer.status = { connected: relayed ? "Relayed" : "Direct" };
    emit({ event: "peer_status_changed", node_id: peer.node_id, status: peer.status });
    state.links.push({
      node_id: peer.node_id,
      relayed,
      bytes_tx: 12_000 + i * 7_000,
      bytes_rx: 9_000 + i * 5_000,
      frames_tx: 80,
      frames_rx: 64,
      last_handshake_secs: 1,
      rtt_ms: relayed ? 38 + i * 3 : 9 + i * 4,
    });
  }, 700 + i * 900);
  state.timers.push(t);
}

function startTicking() {
  const t = window.setInterval(() => {
    for (const l of state.links) {
      l.bytes_tx += Math.floor(Math.random() * 42_000);
      l.bytes_rx += Math.floor(Math.random() * 61_000);
      l.frames_tx += Math.floor(Math.random() * 30);
      l.frames_rx += Math.floor(Math.random() * 30);
      l.last_handshake_secs = Math.min(l.last_handshake_secs + 2, 120);
      if (l.last_handshake_secs >= 118) l.last_handshake_secs = 2;
      if (l.rtt_ms !== null) {
        l.rtt_ms = Math.max(1, l.rtt_ms + Math.round((Math.random() - 0.5) * 6));
      }
    }
  }, 2000) as unknown as number;
  state.timers.push(t);
}

function enterRoom(name: string, mode: RoomMode, relay: string | null, created: boolean) {
  state.room = {
    id: "d3adbeef-0000-4000-8000-000000000000",
    name,
    subnet_prefix: [10, 42],
    mode,
    relay_addr: relay,
    is_owner: created,
  };
  state.relayHealthy = relay ? true : null;
  state.invite = created ? "WLFK-7X4K-QR2S" : null;
  emit({
    event: "room_entered",
    room_id: state.room.id,
    invite_code: state.invite,
    mode,
    relay_addr: relay,
  });
  DEMO_PEERS.forEach((_, i) => {
    const t = window.setTimeout(() => addDemoPeer(i), 400 + i * 1200);
    state.timers.push(t);
  });
  startTicking();

  // Optional scripted incident for design review: ?demo=relaydown
  if (relay && new URLSearchParams(location.search).get("demo") === "relaydown") {
    const t1 = window.setTimeout(() => {
      state.relayHealthy = false;
      emit({ event: "relay_unhealthy", relay });
    }, 6000);
    const t2 = window.setTimeout(() => {
      state.relayHealthy = true;
      emit({ event: "relay_restored", relay });
    }, 14000);
    state.timers.push(t1, t2);
  }
}

function leaveRoom() {
  for (const t of state.timers) {
    clearTimeout(t);
    clearInterval(t);
  }
  state.timers = [];
  state.room = null;
  state.invite = null;
  state.peers = [];
  state.links = [];
  state.relayHealthy = null;
}

export async function mockInvoke(cmd: string, args?: Record<string, unknown>): Promise<unknown> {
  await new Promise((r) => setTimeout(r, 120)); // feel like IPC
  switch (cmd) {
    case "get_state":
      return snapshot();
    case "get_identity":
      return nodeId("this-machine");
    case "connect":
      state.connected = true;
      return null;
    case "create_room":
      enterRoom(
        String(args?.name ?? "room"),
        (args?.mode as RoomMode) ?? "peer_to_peer",
        (args?.relayAddr as string | null) ?? null,
        true,
      );
      return null;
    case "join_room":
      enterRoom("game night", "peer_to_peer", null, false);
      return null;
    case "kick_member":
      state.peers = state.peers.filter((p) => p.node_id !== args?.nodeId);
      emit({ event: "peer_removed", node_id: String(args?.nodeId) });
      return null;
    case "rotate_invite":
      state.invite = "QRST-9K2M-WLFX";
      emit({ event: "invite_rotated", invite_code: state.invite });
      return null;
    case "leave_room":
      leaveRoom();
      return null;
    case "get_peers":
      return state.peers;
    case "get_servers":
      return state.servers;
    case "add_server": {
      const entry = {
        name: String(args?.name),
        address: String(args?.address),
        source: "custom" as const,
      };
      const list = args?.kind === "relay" ? state.servers.relays : state.servers.signaling;
      list.push(entry);
      return null;
    }
    case "remove_server": {
      const list = args?.kind === "relay" ? state.servers.relays : state.servers.signaling;
      const idx = list.findIndex((s) => s.name === args?.name);
      if (idx >= 0) list.splice(idx, 1);
      return null;
    }
    case "set_active_signaling":
      state.servers.active_signaling = String(args?.name);
      return null;
    case "set_manifest_url":
      state.servers.manifest_url = (args?.url as string | null) ?? null;
      return null;
    case "refresh_servers":
      return null;
    case "set_alias": {
      const alias = String(args?.alias ?? "").trim();
      if (!alias || alias.length > 32) throw new Error("display name must be 1–32 characters");
      state.alias = alias;
      return null;
    }
    default:
      throw new Error(`demo backend: unknown command ${cmd}`);
  }
}

export function mockSubscribe(handler: Handler): () => void {
  handlers.add(handler);
  return () => handlers.delete(handler);
}
