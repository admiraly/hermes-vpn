// Thin API layer: inside Tauri it forwards to the real IPC bridge; in a
// plain browser (design preview, `npm run dev` without the shell) it
// serves a self-contained demo backend so the full UI is explorable
// without a daemon or admin rights.

import { invoke as tauriInvoke } from "@tauri-apps/api/core";
import { listen as tauriListen } from "@tauri-apps/api/event";
import type { DaemonEvent } from "./types";
import { mockInvoke, mockSubscribe } from "./mock";

export const isDemo = !("__TAURI_INTERNALS__" in window);

export async function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (isDemo) return mockInvoke(cmd, args) as Promise<T>;
  return tauriInvoke<T>(cmd, args);
}

/** Subscribe to daemon events; returns an unlisten function. */
export async function onDaemonEvent(
  handler: (event: DaemonEvent) => void,
): Promise<() => void> {
  if (isDemo) return mockSubscribe(handler);
  return tauriListen<DaemonEvent>("hermes://event", (e) => handler(e.payload));
}
