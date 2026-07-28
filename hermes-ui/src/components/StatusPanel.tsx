interface StatusPanelProps {
  connected: boolean;
  local: string | null;
  reflexive: string | null;
}

export function StatusPanel({ connected, local, reflexive }: StatusPanelProps) {
  return (
    <div
      style={{
        marginBottom: 24,
        padding: 12,
        background: "#f6f6f7",
        borderRadius: 6,
        fontSize: 14,
      }}
    >
      <div style={{ display: "flex", gap: 16, alignItems: "center" }}>
        <span>{connected ? "🟢 Connected" : "🔴 Disconnected"}</span>
        {local && (
          <span>
            Local: <code>{local}</code>
          </span>
        )}
        {reflexive && (
          <span>
            Public: <code>{reflexive}</code>
          </span>
        )}
      </div>
    </div>
  );
}
