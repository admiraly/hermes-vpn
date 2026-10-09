import { useState } from "react";
import type { RoomSummary } from "../types";

export function RoomView({
  room,
  relayHealthy,
  inviteCode,
  localEndpoint,
  reflexiveEndpoint,
  onLeave,
  onRotateInvite,
}: {
  room: RoomSummary;
  relayHealthy: boolean | null;
  inviteCode: string | null;
  localEndpoint: string | null;
  reflexiveEndpoint: string | null;
  onLeave: () => void;
  onRotateInvite: () => void;
}) {
  const [copied, setCopied] = useState(false);

  const copyInvite = async () => {
    if (!inviteCode) return;
    try {
      await navigator.clipboard.writeText(inviteCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      /* clipboard unavailable */
    }
  };

  const modePill =
    room.mode === "relayed" ? (
      <span
        className={`pill ${relayHealthy === false ? "bad" : "accent"}`}
        title={`All traffic relayed via ${room.relay_addr ?? "?"} (end-to-end encrypted)`}
      >
        <span className="dot" />
        {relayHealthy === false
          ? "relay unreachable"
          : `via central server · ${room.relay_addr ?? ""}`}
      </span>
    ) : room.relay_addr ? (
      <span
        className={`pill ${relayHealthy === false ? "bad" : "ok"}`}
        title={`Direct peer-to-peer, falling back to ${room.relay_addr} when needed`}
      >
        <span className="dot" /> P2P · relay fallback
      </span>
    ) : (
      <span className="pill ok" title="Direct peer-to-peer tunnels only">
        <span className="dot" /> pure P2P
      </span>
    );

  return (
    <div className="card">
      <div className="room-head">
        <span className="name">{room.name}</span>
        {modePill}
        <div className="spacer" />
        {inviteCode && (
          <span className="invite" title="Share this code so others can join">
            <code>{inviteCode}</code>
            <button onClick={copyInvite}>{copied ? "Copied ✓" : "Copy"}</button>
            {room.is_owner && (
              <button
                onClick={() => {
                  if (
                    window.confirm(
                      "Replace the invite code? The old code stops working; people already in the room stay.",
                    )
                  )
                    onRotateInvite();
                }}
                title="Revoke the current code and make a new one"
              >
                New code
              </button>
            )}
          </span>
        )}
        <button className="danger" onClick={onLeave}>
          Leave
        </button>
      </div>
      <div className="netline" style={{ marginTop: 12 }}>
        {localEndpoint && (
          <span>
            local <b className="mono">{localEndpoint}</b>
          </span>
        )}
        {reflexiveEndpoint && (
          <span>
            public <b className="mono">{reflexiveEndpoint}</b>
          </span>
        )}
        <span>
          subnet <b className="mono">10.{room.subnet_prefix[1]}.0.0/16</b>
        </span>
      </div>
    </div>
  );
}
