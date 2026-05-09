/*
 * Tiny REST client for the embedded dashboard. Same-origin only — the gateway
 * rejects non-localhost Origin headers on mutating requests, so the bundle is
 * served from the gateway itself in production. The `dev` script proxies to
 * 127.0.0.1:18970.
 *
 * Auth: optional bearer token persisted in localStorage. The gateway accepts
 * either Authorization: Bearer or X-DefenseClaw-Token. Mutating calls also
 * need X-DefenseClaw-Client + Content-Type: application/json.
 */

const TOKEN_KEY = "dc.token";
const CLIENT_ID = "dc-web/0.1";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null): void {
  if (token) localStorage.setItem(TOKEN_KEY, token);
  else localStorage.removeItem(TOKEN_KEY);
}

export interface ApiError extends Error {
  status: number;
  body: unknown;
}

function makeError(status: number, body: unknown): ApiError {
  const err = new Error(`HTTP ${status}`) as ApiError;
  err.status = status;
  err.body = body;
  return err;
}

async function request<T>(
  method: "GET" | "HEAD" | "POST" | "PUT" | "PATCH" | "DELETE",
  path: string,
  body?: unknown,
): Promise<T> {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  const token = getToken();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    headers["X-DefenseClaw-Client"] = CLIENT_ID;
    init.body = JSON.stringify(body);
  }

  const res = await fetch(path, init);
  const text = await res.text();
  let parsed: unknown = null;
  if (text) {
    try { parsed = JSON.parse(text); } catch { parsed = text; }
  }
  if (!res.ok) {
    // 401 from any caller is hoisted to a window event so a single global
    // banner (dc-token-banner) can prompt for the token without each view
    // having to handle it individually.
    if (res.status === 401) {
      window.dispatchEvent(new CustomEvent("dc:auth-failure", {
        detail: { path, method, body: parsed },
      }));
    }
    throw makeError(res.status, parsed);
  }
  return parsed as T;
}

export const api = {
  get:    <T>(path: string)               => request<T>("GET", path),
  post:   <T>(path: string, body?: unknown) => request<T>("POST", path, body ?? {}),
  put:    <T>(path: string, body?: unknown) => request<T>("PUT", path, body ?? {}),
  patch:  <T>(path: string, body?: unknown) => request<T>("PATCH", path, body ?? {}),
  delete: <T>(path: string)               => request<T>("DELETE", path),
};

/* ------------------------------- Schemas -------------------------------- */

export type SubsystemState =
  | "running" | "starting" | "reconnecting" | "degraded"
  | "stopped" | "error" | "disabled";

export interface Subsystem {
  state: SubsystemState;
  since?: string;
  details?: Record<string, unknown>;
}

export interface Provenance {
  schema_version: number;
  content_hash: string;
  generation: number;
  binary_version: string;
}

export interface Health {
  api: Subsystem;
  gateway: Subsystem;
  guardrail: Subsystem;
  sinks: Subsystem;
  telemetry: Subsystem;
  watcher: Subsystem;
  provenance: Provenance;
  started_at: string;
  uptime_ms: number;
}
