import { useCallback, useEffect, useState } from "react";
import { invoke } from "../api";
import type { ServerEntry, ServerListing } from "../types";

const sourceLabel: Record<ServerEntry["source"], string> = {
  built_in: "built-in",
  manifest: "directory",
  custom: "yours",
};

function ServerRows({
  entries,
  active,
  onSelect,
  onRemove,
  radioName,
}: {
  entries: ServerEntry[];
  active?: string | null;
  onSelect?: (name: string) => void;
  onRemove: (name: string) => void;
  radioName: string;
}) {
  return (
    <div>
      {entries.map((s) => (
        <div className="server-row" key={s.name}>
          {onSelect && (
            <input
              type="radio"
              name={radioName}
              checked={active === s.name}
              onChange={() => onSelect(s.name)}
              title="Use this server"
            />
          )}
          <span className="nm">{s.name}</span>
          <span className={`tag ${s.source === "custom" ? "custom" : ""}`}>
            {sourceLabel[s.source]}
          </span>
          <span className="addr mono">{s.address}</span>
          {s.source === "custom" && (
            <button className="subtle danger" onClick={() => onRemove(s.name)} title="Remove">
              ✕
            </button>
          )}
        </div>
      ))}
    </div>
  );
}

export function SettingsPanel({
  onClose,
  onActiveChanged,
}: {
  onClose: () => void;
  onActiveChanged?: (name: string | null) => void;
}) {
  const [listing, setListing] = useState<ServerListing | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const [newKind, setNewKind] = useState<"signaling" | "relay">("signaling");
  const [newName, setNewName] = useState("");
  const [newAddress, setNewAddress] = useState("");
  const [manifestUrl, setManifestUrl] = useState("");

  const reload = useCallback(() => {
    invoke<ServerListing>("get_servers")
      .then((l) => {
        setListing(l);
        setManifestUrl(l.manifest_url ?? "");
        onActiveChanged?.(l.active_signaling ?? l.signaling[0]?.name ?? null);
      })
      .catch((e) => setError(String(e)));
  }, [onActiveChanged]);

  useEffect(reload, [reload]);

  const run = async (action: () => Promise<unknown>, success?: string) => {
    setError(null);
    setInfo(null);
    try {
      await action();
      if (success) setInfo(success);
      reload();
    } catch (e) {
      setError(String(e));
    }
  };

  if (!listing) {
    return (
      <div className="card">
        <p className="sub">Loading servers… {error && <span>{error}</span>}</p>
      </div>
    );
  }

  return (
    <>
      <div className="settings-head">
        <h2>Servers</h2>
        <button onClick={onClose}>Done</button>
      </div>

      {error && (
        <div className="infobar bad" role="alert">
          <span className="ico">⛔</span>
          <span>{error}</span>
        </div>
      )}
      {info && (
        <div className="infobar" style={{ background: "var(--ok-dim)", color: "var(--ok)" }}>
          <span className="ico">✓</span>
          <span>{info}</span>
        </div>
      )}

      <div className="card">
        <h3>Signaling servers</h3>
        <p className="sub">
          The rendezvous point used to find peers. The selected one is used
          when you connect.
        </p>
        <ServerRows
          radioName="active-signaling"
          entries={listing.signaling}
          active={listing.active_signaling ?? listing.signaling[0]?.name}
          onSelect={(name) =>
            run(() => invoke("set_active_signaling", { name }), `Now using ${name}`)
          }
          onRemove={(name) => run(() => invoke("remove_server", { kind: "signaling", name }))}
        />
      </div>

      <div className="card">
        <h3>Relay (central) servers</h3>
        <p className="sub">
          Available when creating relayed rooms or as a P2P fallback. Relays
          only ever see encrypted traffic.
        </p>
        <ServerRows
          radioName="relay-list"
          entries={listing.relays}
          onRemove={(name) => run(() => invoke("remove_server", { kind: "relay", name }))}
        />
      </div>

      <div className="card">
        <h3>Add a server</h3>
        <div className="form-grid">
          <select value={newKind} onChange={(e) => setNewKind(e.target.value as typeof newKind)}>
            <option value="signaling">Signaling</option>
            <option value="relay">Relay</option>
          </select>
          <input placeholder="Name" value={newName} onChange={(e) => setNewName(e.target.value)} />
          <input
            placeholder={newKind === "signaling" ? "wss://host/v1" : "host:8788"}
            value={newAddress}
            onChange={(e) => setNewAddress(e.target.value)}
            spellCheck={false}
          />
          <button
            className="primary"
            disabled={!newName.trim() || !newAddress.trim()}
            onClick={() =>
              run(async () => {
                await invoke("add_server", {
                  kind: newKind,
                  name: newName.trim(),
                  address: newAddress.trim(),
                });
                setNewName("");
                setNewAddress("");
              }, "Server added")
            }
          >
            Add
          </button>
        </div>
      </div>

      <div className="card">
        <h3>Server directory</h3>
        <p className="sub">
          A JSON file the Hermes operator hosts. New official servers appear
          here automatically after a refresh.
        </p>
        <div className="row">
          <input
            placeholder="https://example.com/hermes-servers.json"
            value={manifestUrl}
            onChange={(e) => setManifestUrl(e.target.value)}
            style={{ flex: 1 }}
            spellCheck={false}
          />
          <button
            onClick={() =>
              run(
                () => invoke("set_manifest_url", { url: manifestUrl.trim() || null }),
                "Directory URL saved",
              )
            }
          >
            Save
          </button>
          <button onClick={() => run(() => invoke("refresh_servers"), "Directory refreshed")}>
            Refresh now
          </button>
        </div>
      </div>
    </>
  );
}
