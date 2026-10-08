import { useEffect, useState } from "react";
import { invoke } from "../api";
import type { RoomMode, ServerEntry, ServerListing } from "../types";

export function CreateOrJoinRoom() {
  const [roomName, setRoomName] = useState("");
  const [inviteCode, setInviteCode] = useState("");
  const [roomMode, setRoomMode] = useState<RoomMode>("peer_to_peer");
  const [relays, setRelays] = useState<ServerEntry[]>([]);
  const [relayAddr, setRelayAddr] = useState<string>("");
  const [p2pFallback, setP2pFallback] = useState(true);
  const [busy, setBusy] = useState<"create" | "join" | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    invoke<ServerListing>("get_servers")
      .then((listing) => {
        setRelays(listing.relays);
        setRelayAddr((prev) => prev || listing.relays[0]?.address || "");
      })
      .catch((e) => setError(String(e)));
  }, []);

  const wantsRelay = roomMode === "relayed" || (roomMode === "peer_to_peer" && p2pFallback);

  const handleCreate = async () => {
    setError(null);
    if (wantsRelay && !relayAddr) {
      setError(
        roomMode === "relayed"
          ? "Pick a relay server for a relayed room."
          : "Pick a relay to fall back to, or disable the fallback.",
      );
      return;
    }
    setBusy("create");
    try {
      await invoke("create_room", {
        name: roomName.trim(),
        mode: roomMode,
        relayAddr: wantsRelay ? relayAddr : null,
      });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  const handleJoin = async () => {
    setError(null);
    setBusy("join");
    try {
      await invoke("join_room", { code: inviteCode.trim().toUpperCase() });
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <>
      {error && (
        <div className="infobar bad" role="alert">
          <span className="ico">⛔</span>
          <span>{error}</span>
        </div>
      )}
      <div className="duo">
        <div className="card">
          <h2>Create a room</h2>
          <p className="sub">A room is a private virtual LAN for you and your invitees.</p>
          <div className="stack">
            <input
              placeholder="Room name (e.g. game night)"
              value={roomName}
              onChange={(e) => setRoomName(e.target.value)}
              maxLength={40}
            />

            <div className="segmented" role="radiogroup" aria-label="Traffic mode">
              <button
                className={`seg ${roomMode === "peer_to_peer" ? "on" : ""}`}
                role="radio"
                aria-checked={roomMode === "peer_to_peer"}
                onClick={() => setRoomMode("peer_to_peer")}
              >
                <span className="t">Peer-to-peer</span>
                <span className="d">
                  Direct tunnels between members. Lowest latency.
                </span>
              </button>
              <button
                className={`seg ${roomMode === "relayed" ? "on" : ""}`}
                role="radio"
                aria-checked={roomMode === "relayed"}
                onClick={() => setRoomMode("relayed")}
              >
                <span className="t">Via central server</span>
                <span className="d">
                  All traffic through a relay. Works behind any firewall.
                </span>
              </button>
            </div>

            {roomMode === "peer_to_peer" && (
              <label className="check">
                <input
                  type="checkbox"
                  checked={p2pFallback}
                  onChange={(e) => setP2pFallback(e.target.checked)}
                />
                Fall back to a relay if a direct connection can't be made
              </label>
            )}

            {wantsRelay && (
              <div className="row">
                <label style={{ flex: "none" }}>Relay</label>
                <select
                  value={relayAddr}
                  onChange={(e) => setRelayAddr(e.target.value)}
                  style={{ flex: 1 }}
                >
                  {relays.length === 0 && <option value="">No relays configured</option>}
                  {relays.map((r) => (
                    <option key={r.name} value={r.address}>
                      {r.name} ({r.address})
                    </option>
                  ))}
                </select>
              </div>
            )}

            <div className="row">
              <button
                className="primary"
                onClick={handleCreate}
                disabled={!roomName.trim() || busy !== null}
              >
                {busy === "create" ? "Creating…" : "Create room"}
              </button>
            </div>
          </div>
        </div>

        <div className="card">
          <h2>Join a room</h2>
          <p className="sub">Paste the invite code someone shared with you.</p>
          <div className="stack">
            <input
              className="code-input"
              placeholder="WLFK-7X4K-QR2S"
              value={inviteCode}
              onChange={(e) => setInviteCode(e.target.value.toUpperCase())}
              maxLength={14}
              spellCheck={false}
            />
            <button
              className="primary"
              onClick={handleJoin}
              disabled={inviteCode.trim().length < 12 || busy !== null}
            >
              {busy === "join" ? "Joining…" : "Join room"}
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
