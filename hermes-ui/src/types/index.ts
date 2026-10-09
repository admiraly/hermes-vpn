// Mirrors hermes_daemon::protocol and hermes_core::room wire formats.
// Keep in sync when changing the Rust side.

export type PathKind = "Direct" | "DirectUpnp" | "Relayed";

export type RoomMode = "peer_to_peer" | "relayed";

export type PeerStatus =
  | "discovered"
  | "connecting"
  | { connected: PathKind }
  | "stale"
  | "gone";

export interface Peer {
  node_id: string;
  wireguard_public: number[];
  alias: string;
  virtual_ipv4: string;
  virtual_mac: string;
  status: PeerStatus;
  latency_ms: number | null;
}

export interface RoomSummary {
  id: string;
  name: string;
  subnet_prefix: [number, number];
  mode: RoomMode;
  relay_addr: string | null;
  /** We created this room and may remove members or replace the invite code. */
  is_owner: boolean;
}

export interface LinkStats {
  node_id: string;
  relayed: boolean;
  bytes_tx: number;
  bytes_rx: number;
  frames_tx: number;
  frames_rx: number;
  last_handshake_secs: number;
  /** Round-trip time from the in-tunnel latency ping; null until measured. */
  rtt_ms: number | null;
}

export interface StateSnapshot {
  node_id_base64: string;
  /** Our display name, as peers see it. */
  alias: string;
  connected: boolean;
  local_endpoint: string | null;
  reflexive_endpoint: string | null;
  room: RoomSummary | null;
  peers: Peer[];
  links: LinkStats[];
  relay_healthy: boolean | null;
  /** Signaling server URL of the current session. */
  signaling_url: string | null;
  /** Plaintext ws:// to a remote host: invite codes are readable in transit. */
  signaling_insecure: boolean;
}

export type ServerSource = "built_in" | "manifest" | "custom";

export interface ServerEntry {
  name: string;
  address: string;
  source: ServerSource;
}

export interface ServerListing {
  signaling: ServerEntry[];
  relays: ServerEntry[];
  manifest_url: string | null;
  active_signaling: string | null;
}

export type DaemonEvent =
  | {
      event: "room_entered";
      room_id: string;
      invite_code: string | null;
      mode: RoomMode;
      relay_addr: string | null;
    }
  | { event: "kicked"; banned: boolean }
  | { event: "invite_rotated"; invite_code: string }
  | { event: "peer_added"; peer: Peer }
  | { event: "peer_status_changed"; node_id: string; status: PeerStatus }
  | { event: "peer_removed"; node_id: string }
  | { event: "signaling_error"; code: string; message: string }
  | { event: "signaling_disconnected" }
  | { event: "signaling_reconnecting"; attempt: number }
  | { event: "signaling_reconnected" }
  | { event: "relay_unhealthy"; relay: string }
  | { event: "relay_restored"; relay: string };
