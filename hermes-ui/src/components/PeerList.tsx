import type { LinkStats, Peer, PeerStatus } from "../types";

export function PeerList({
  peers,
  links,
  inviteCode,
}: {
  peers: Peer[];
  links: LinkStats[];
  inviteCode: string | null;
}) {
  if (peers.length === 0) {
    return (
      <div className="empty">
        <span className="big">◌</span>
        No one else is here yet.
        {inviteCode ? (
          <>
            <br />
            Share the invite code <code>{inviteCode}</code> to bring peers in.
          </>
        ) : null}
      </div>
    );
  }

  const linkByNode = new Map(links.map((l) => [l.node_id, l]));

  return (
    <table className="peers">
      <thead>
        <tr>
          <th>Member</th>
          <th>Virtual IP</th>
          <th>Path</th>
          <th>Traffic ↑ / ↓</th>
          <th>Handshake</th>
          <th>Latency</th>
        </tr>
      </thead>
      <tbody>
        {peers.map((peer) => {
          const link = linkByNode.get(peer.node_id);
          return (
            <tr key={peer.node_id}>
              <td style={{ fontWeight: 600 }}>{peer.alias}</td>
              <td>
                <code>{peer.virtual_ipv4}</code>
              </td>
              <td>{renderPath(peer.status, link)}</td>
              <td className="mono">
                {link ? `${fmtBytes(link.bytes_tx)} / ${fmtBytes(link.bytes_rx)}` : "—"}
              </td>
              <td className="mono">{renderHandshake(link)}</td>
              <td className="mono">{renderLatency(link?.rtt_ms ?? peer.latency_ms)}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}

/** The live link wins for path display (it reflects relay fallback); we
 *  fall back to the last-known status when no tunnel exists yet. */
function renderPath(status: PeerStatus, link?: LinkStats) {
  if (link) {
    return link.relayed ? (
      <span className="pill accent">
        <span className="dot" /> relayed
      </span>
    ) : (
      <span className="pill ok">
        <span className="dot" /> direct
      </span>
    );
  }
  if (typeof status === "string") {
    switch (status) {
      case "discovered":
      case "connecting":
        return (
          <span className="pill warn">
            <span className="dot pulsing" /> connecting
          </span>
        );
      case "stale":
        return (
          <span className="pill bad">
            <span className="dot" /> unreachable
          </span>
        );
      case "gone":
        return (
          <span className="pill">
            <span className="dot" /> left
          </span>
        );
    }
  }
  return status.connected === "Relayed" ? (
    <span className="pill accent">
      <span className="dot" /> relayed
    </span>
  ) : (
    <span className="pill ok">
      <span className="dot" /> direct
    </span>
  );
}

function renderLatency(ms: number | null | undefined): string {
  return ms == null ? "—" : `${ms} ms`;
}

function renderHandshake(link?: LinkStats): string {
  if (!link) return "—";
  if (link.last_handshake_secs === 0) {
    return link.bytes_tx + link.bytes_rx > 0 ? "handshaking…" : "—";
  }
  return `${link.last_handshake_secs}s ago`;
}

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}
