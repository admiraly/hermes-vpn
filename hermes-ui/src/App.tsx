import { useEffect, useState } from "react";
import { invoke, isDemo, onDaemonEvent } from "./api";
import { CreateOrJoinRoom } from "./components/CreateOrJoinRoom";
import { PeerList } from "./components/PeerList";
import { RoomView } from "./components/RoomView";
import { SettingsPanel } from "./components/SettingsPanel";
import type {
  LinkStats,
  Peer,
  DaemonEvent,
  StateSnapshot,
  RoomSummary,
  ServerListing,
} from "./types";

type Banner = { kind: "warn" | "bad"; text: string } | null;

export function App() {
  const [identity, setIdentity] = useState<string | null>(null);
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [localEndpoint, setLocalEndpoint] = useState<string | null>(null);
  const [reflexiveEndpoint, setReflexiveEndpoint] = useState<string | null>(null);
  const [room, setRoom] = useState<RoomSummary | null>(null);
  const [relayHealthy, setRelayHealthy] = useState<boolean | null>(null);
  const [inviteCode, setInviteCode] = useState<string | null>(null);
  const [peers, setPeers] = useState<Peer[]>([]);
  const [links, setLinks] = useState<LinkStats[]>([]);
  const [activeSignaling, setActiveSignaling] = useState<string | null>(null);
  const [banner, setBanner] = useState<Banner>(null);
  const [reconnecting, setReconnecting] = useState(false);
  const [idCopied, setIdCopied] = useState(false);
  const [showSettings, setShowSettings] = useState(false);

  const applySnapshot = (snap: StateSnapshot) => {
    setIdentity(snap.node_id_base64);
    setConnected(snap.connected);
    setLocalEndpoint(snap.local_endpoint);
    setReflexiveEndpoint(snap.reflexive_endpoint);
    setRoom(snap.room);
    setPeers(snap.peers);
    setLinks(snap.links);
    setRelayHealthy(snap.relay_healthy);
  };

  // One-shot state load on mount, plus the active signaling server name
  // for the connect screen.
  useEffect(() => {
    invoke<StateSnapshot>("get_state")
      .then(applySnapshot)
      .catch((e) =>
        setBanner({
          kind: "bad",
          text: `Cannot reach the Hermes background service: ${e}`,
        }),
      );
    invoke<ServerListing>("get_servers")
      .then((l) => setActiveSignaling(l.active_signaling ?? l.signaling[0]?.name ?? null))
      .catch(() => {});
  }, []);

  // Poll live state while connected so per-peer traffic counters and the
  // direct/relayed path stay current (events are discrete; stats tick).
  useEffect(() => {
    if (!connected) return;
    const id = setInterval(() => {
      invoke<StateSnapshot>("get_state")
        .then((snap) => {
          setLinks(snap.links);
          setPeers(snap.peers);
          setRoom(snap.room);
          setRelayHealthy(snap.relay_healthy);
        })
        .catch(() => {
          /* transient; the events channel surfaces hard failures */
        });
    }, 2000);
    return () => clearInterval(id);
  }, [connected]);

  // Subscribe to daemon events.
  useEffect(() => {
    let unlisten: (() => void) | null = null;
    onDaemonEvent((event: DaemonEvent) => {
      switch (event.event) {
        case "room_entered":
          if (event.invite_code) setInviteCode(event.invite_code);
          invoke<StateSnapshot>("get_state").then(applySnapshot);
          break;
        case "peer_added":
          setPeers((prev) => {
            const idx = prev.findIndex((p) => p.node_id === event.peer.node_id);
            if (idx >= 0) {
              const next = prev.slice();
              next[idx] = event.peer;
              return next;
            }
            return [...prev, event.peer];
          });
          break;
        case "peer_status_changed":
          setPeers((prev) =>
            prev.map((p) =>
              p.node_id === event.node_id ? { ...p, status: event.status } : p,
            ),
          );
          break;
        case "peer_removed":
          setPeers((prev) => prev.filter((p) => p.node_id !== event.node_id));
          break;
        case "signaling_error":
          setBanner({ kind: "bad", text: `${event.code}: ${event.message}` });
          break;
        case "signaling_disconnected":
          setConnected(false);
          setReconnecting(true);
          setBanner({
            kind: "warn",
            text: "Signaling connection lost — tunnels keep running; reconnecting…",
          });
          break;
        case "signaling_reconnecting":
          setReconnecting(true);
          setBanner({
            kind: "warn",
            text: `Reconnecting to signaling server (attempt ${event.attempt})…`,
          });
          break;
        case "signaling_reconnected":
          setConnected(true);
          setReconnecting(false);
          setBanner(null);
          break;
        case "relay_unhealthy":
          setRelayHealthy(false);
          setBanner({
            kind: "bad",
            text: `Relay ${event.relay} is not responding — relayed traffic may be down (retrying automatically).`,
          });
          break;
        case "relay_restored":
          setRelayHealthy(true);
          setBanner(null);
          break;
      }
    }).then((fn) => {
      unlisten = fn;
    });
    return () => {
      if (unlisten) unlisten();
    };
  }, []);

  const handleConnect = async () => {
    setBanner(null);
    setConnecting(true);
    try {
      await invoke("connect", { signalingUrl: null });
      setConnected(true);
      const snap = await invoke<StateSnapshot>("get_state");
      setLocalEndpoint(snap.local_endpoint);
      setReflexiveEndpoint(snap.reflexive_endpoint);
    } catch (e) {
      setBanner({ kind: "bad", text: String(e) });
    } finally {
      setConnecting(false);
    }
  };

  const handleLeave = async () => {
    try {
      await invoke("leave_room");
      setRoom(null);
      setInviteCode(null);
      setPeers([]);
      setLinks([]);
      setRelayHealthy(null);
    } catch (e) {
      setBanner({ kind: "bad", text: String(e) });
    }
  };

  const copyIdentity = async () => {
    if (!identity) return;
    try {
      await navigator.clipboard.writeText(identity);
      setIdCopied(true);
      setTimeout(() => setIdCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  };

  const statusPill = reconnecting ? (
    <span className="pill warn">
      <span className="dot pulsing" /> Reconnecting…
    </span>
  ) : connected ? (
    <span className="pill ok">
      <span className="dot" /> Connected
    </span>
  ) : (
    <span className="pill">
      <span className="dot" /> Offline
    </span>
  );

  return (
    <>
      <header className="titlebar">
        <div className="logo">H</div>
        <h1>Hermes</h1>
        <div className="spacer" />
        {statusPill}
        <button
          className="node-chip"
          onClick={copyIdentity}
          title="Your node id — click to copy"
        >
          {idCopied ? "copied ✓" : identity ? `${identity.slice(0, 10)}…` : "…"}
        </button>
        <button
          className="subtle"
          onClick={() => setShowSettings((s) => !s)}
          title="Servers & settings"
        >
          {showSettings ? "✕" : "⚙"}
        </button>
      </header>

      <main className="content">
        {banner && (
          <div className={`infobar ${banner.kind}`} role="alert">
            <span className="ico">{banner.kind === "bad" ? "⛔" : "⚠"}</span>
            <span>{banner.text}</span>
            <button className="subtle close" onClick={() => setBanner(null)}>
              ✕
            </button>
          </div>
        )}

        {showSettings ? (
          <SettingsPanel
            onClose={() => setShowSettings(false)}
            onActiveChanged={setActiveSignaling}
          />
        ) : !connected && !room ? (
          <div className="card hero">
            <div className="glyph">⛨</div>
            <h2>Your private LAN, anywhere</h2>
            <p>
              Connect to a signaling server to create a room or join one with
              an invite code. Traffic between members is always end-to-end
              encrypted.
            </p>
            <button className="primary" onClick={handleConnect} disabled={connecting}>
              {connecting ? "Connecting…" : "Connect"}
            </button>
            {activeSignaling && (
              <div className="via">
                via <b>{activeSignaling}</b> — change under ⚙
              </div>
            )}
          </div>
        ) : !room ? (
          <CreateOrJoinRoom />
        ) : (
          <>
            <RoomView
              room={room}
              relayHealthy={relayHealthy}
              inviteCode={inviteCode}
              localEndpoint={localEndpoint}
              reflexiveEndpoint={reflexiveEndpoint}
              onLeave={handleLeave}
            />
            <div className="card" style={{ padding: "6px 8px" }}>
              <PeerList peers={peers} links={links} inviteCode={inviteCode} />
            </div>
          </>
        )}
      </main>

      {isDemo && <div className="demo-note">demo mode — no daemon connected</div>}
    </>
  );
}
