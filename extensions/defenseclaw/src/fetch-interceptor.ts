/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * LLM Fetch Interceptor
 *
 * Patches globalThis.fetch to redirect outbound LLM API calls through the
 * DefenseClaw guardrail proxy at localhost:{guardrailPort}, regardless of
 * which provider or model the user selected in OpenClaw.
 *
 * The original upstream URL is preserved in the X-DC-Target-URL header so
 * the proxy can route to the correct upstream after inspection.
 */

import { createRequire } from "node:module";
import { createEgressReporter, type EgressReporter } from "./egress-telemetry.js";
import { loadSidecarConfig } from "./sidecar-config.js";
import {
  HEADER_DEFENSECLAW_AGENT_ID,
  HEADER_DEFENSECLAW_AGENT_INSTANCE_ID,
  HEADER_DEFENSECLAW_AGENT_NAME,
  HEADER_DEFENSECLAW_POLICY_ID,
  HEADER_DEFENSECLAW_RUN_ID,
  HEADER_DEFENSECLAW_SESSION_ID,
  HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID,
  HEADER_DEFENSECLAW_TRACE_ID,
} from "./correlation-headers.js";
// Canonical provider config — single source of truth shared with the Go proxy.
// Copied from internal/configs/providers.json by `make plugin`.
import providersConfig from "./providers.json" with { type: "json" };
const _require = createRequire(import.meta.url);
// Use CommonJS require() for https/http — ESM module objects are frozen and
// cannot have properties reassigned, but the CJS exports object is mutable.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const https = _require("https") as typeof import("https");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const http = _require("http") as typeof import("http");

/**
 * Domains that should be intercepted. Seeded from the embedded
 * providers.json at import time; can be extended at runtime by
 * `bootstrapProviderOverlay()` once the sidecar's
 * GET /v1/config/providers endpoint is reachable. Declared `let` so
 * the overlay can grow the list in place without the rest of the
 * module holding a stale snapshot.
 */
let LLM_DOMAINS: string[] = providersConfig.providers.flatMap(
  (p: { domains: string[] }) => p.domains,
);

/**
 * Ollama runs locally — intercept by matching its default port.
 * Seeded from providers.json; can be extended at runtime by the
 * overlay fetch so new Ollama deployments on non-standard ports do
 * not silently bypass the guardrail.
 */
let OLLAMA_PORTS: string[] = providersConfig.ollama_ports.map(String);

/**
 * Apply a merged provider registry from the Go sidecar. Additive
 * only — we never drop a built-in domain or port because the
 * interceptor MUST default to the safer (more intercepting) choice
 * when the overlay is absent or malformed. Kept tiny and exported
 * so unit tests can exercise the merge without running a live
 * sidecar.
 */
export function applyProviderRegistry(reg: {
  providers?: Array<{ domains?: string[] | null }>;
  ollama_ports?: number[] | null;
}): void {
  // Tolerate a sidecar that returns a shape we don't recognize (e.g.
  // older schema, corrupted response). Silently no-op rather than
  // throw: the built-in list still provides full coverage for every
  // provider we ship with.
  if (!reg || typeof reg !== "object") return;
  // Domain matching downstream (isLLMUrl, isLLMHost) lower-cases the
  // request host but compares to the raw entry. Normalize here so an
  // overlay entry hand-edited to "Api.OpenAI.com" still matches
  // traffic to api.openai.com.
  const seenDomains = new Set(LLM_DOMAINS.map((d) => d.toLowerCase()));
  const seenPorts = new Set(OLLAMA_PORTS);
  // Cap the number of additions to guard against a runaway /
  // corrupted sidecar response (defense-in-depth; the Go side already
  // bounds the overlay file size).
  const MAX_ADDITIONS = 1024;
  let added = 0;
  for (const p of reg.providers ?? []) {
    if (added >= MAX_ADDITIONS) break;
    for (const d of p?.domains ?? []) {
      if (added >= MAX_ADDITIONS) break;
      if (typeof d !== "string") continue;
      const norm = d.trim().toLowerCase();
      // Reject obviously malformed entries: empty, contains whitespace,
      // a scheme, or a path. The Python CLI normalizes these already;
      // this is the defensive server-side filter for hand-edits.
      if (norm === "" || /[\s/\\]/.test(norm) || norm.includes("://")) continue;
      if (seenDomains.has(norm)) continue;
      seenDomains.add(norm);
      LLM_DOMAINS.push(norm);
      added++;
    }
  }
  // Cap port additions independently of domains: a runaway overlay
  // with tens of thousands of bogus ports would otherwise turn every
  // isLLMUrl call into a linear scan through garbage. Real-world
  // Ollama deployments have 1-2 ports.
  const MAX_PORT_ADDITIONS = 64;
  let portsAdded = 0;
  for (const port of reg.ollama_ports ?? []) {
    if (portsAdded >= MAX_PORT_ADDITIONS) break;
    // Require integer (not float, not NaN, not Infinity). 3.14 would
    // otherwise stringify to "3.14" and sit in OLLAMA_PORTS as a
    // dead entry, a sure sign of operator error.
    if (typeof port !== "number" || !Number.isInteger(port)) continue;
    if (port <= 0 || port > 65535) continue;
    const s = String(port);
    if (seenPorts.has(s)) continue;
    seenPorts.add(s);
    OLLAMA_PORTS.push(s);
    portsAdded++;
  }
}

/**
 * Fetch the merged provider registry from the local sidecar. Runs
 * once at interceptor startup on a best-effort basis. Failures are
 * swallowed so a sidecar that does not yet serve the endpoint (or
 * that is slow to boot) cannot hold up the plugin's own start-up —
 * the built-in list still provides full coverage for every provider
 * we ship with.
 *
 * A tight 2s timeout prevents a misbehaving sidecar from blocking
 * the extension host indefinitely.
 */
export async function bootstrapProviderOverlay(
  guardrailPort: number,
  options?: { timeoutMs?: number; fetchImpl?: typeof fetch },
): Promise<void> {
  const timeoutMs = options?.timeoutMs ?? 2000;
  const doFetch = options?.fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") return;
  // Mirror the Go-side 1 MiB overlay cap. The merged registry is
  // tiny (a few KB) but a compromised or buggy sidecar must not be
  // able to exhaust the extension host's memory just by serving a
  // giant response body. 2 MiB gives 2x headroom over Go's 1 MiB
  // ceiling without leaving room for abuse.
  const MAX_RESPONSE_BYTES = 2 * 1024 * 1024;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await doFetch(
      `http://127.0.0.1:${guardrailPort}/v1/config/providers`,
      { method: "GET", signal: ctrl.signal, cache: "no-store" },
    );
    if (!res.ok) return;
    // If Content-Length advertises more than the cap, bail early —
    // no sense allocating a 100 MiB buffer just to reject it. A
    // missing or lying Content-Length is still defended by the
    // streaming read below, which bounds actual bytes consumed.
    const lenHdr = res.headers?.get?.("content-length");
    if (lenHdr) {
      const n = parseInt(lenHdr, 10);
      if (Number.isFinite(n) && n > MAX_RESPONSE_BYTES) return;
    }
    // Prefer a true streaming read capped at MAX_RESPONSE_BYTES so
    // a lying Content-Length header (or a hostile sidecar) cannot
    // force us to allocate past the cap. We only fall back to
    // res.text() for mock-based environments where res.body is not
    // exposed (e.g. older Node shims used in tests).
    let text: string | null = null;
    const resBody = (res as unknown as { body?: ReadableStream<Uint8Array> }).body;
    if (resBody && typeof resBody.getReader === "function") {
      const bytes = await readStreamBounded(resBody, MAX_RESPONSE_BYTES);
      if (bytes.byteLength > MAX_RESPONSE_BYTES) return;
      text = decodeUtf8Safe(bytes);
    } else if (typeof (res as Response).text === "function") {
      const t = await (res as Response).text();
      if (t.length > MAX_RESPONSE_BYTES) return;
      text = t;
    } else {
      // Last-resort: older shim without text() nor body. res.json()
      // has no native byte cap, so we only reach here if every
      // better path is unavailable.
      const body = await res.json();
      applyProviderRegistry(
        body as {
          providers?: Array<{ domains?: string[] | null }>;
          ollama_ports?: number[] | null;
        },
      );
      return;
    }
    if (text == null) return;
    const body: unknown = JSON.parse(text);
    applyProviderRegistry(
      body as {
        providers?: Array<{ domains?: string[] | null }>;
        ollama_ports?: number[] | null;
      },
    );
  } catch {
    // Sidecar unreachable / malformed body — we stay on the built-in
    // list. The Go side logs the failure via its own stderr alert.
  } finally {
    clearTimeout(timer);
  }
}

/** Header name the proxy reads to determine the real upstream URL. */
export const TARGET_URL_HEADER = "X-DC-Target-URL";

/**
 * Header carrying the real LLM provider key to the proxy.
 * Kept separate from Authorization so the original Authorization header
 * (which may carry a different token) is preserved verbatim.
 */
export const AI_AUTH_HEADER = "X-AI-Auth";

/**
 * Header carrying the defenseclaw proxy authentication token (the openclaw
 * gateway token from OPENCLAW_GATEWAY_TOKEN / gateway.token in config.yaml).
 * The proxy validates this for non-loopback connections; loopback connections
 * are trusted by network topology alone.
 */
export const DC_AUTH_HEADER = "X-DC-Auth";

/**
 * Extract the lower-cased hostname from a URL string. Returns "" for
 * inputs that do not parse as absolute URLs (options-bag callers,
 * relative URLs, malformed inputs); isLLMUrl then falls through to
 * the Ollama port rules so a relative URL to a local Ollama still
 * gets intercepted.
 */
function extractHost(urlStr: string): string {
  try {
    return new URL(urlStr).hostname.toLowerCase();
  } catch {
    return "";
  }
}

/**
 * Host-boundary domain match. A registered entry "api.openai.com"
 * matches the exact host "api.openai.com" and any subdomain
 * ("staging.api.openai.com") but NOT a suffix injection like
 * "api.openai.com.evil.test" or a substring match somewhere inside
 * the query string. Entries are stored lower-cased (see
 * applyProviderRegistry + providers.json build step).
 */
function matchesLLMDomain(host: string): boolean {
  if (!host) return false;
  for (const domain of LLM_DOMAINS) {
    // Path-style entries (e.g. "googleapis.com/v1/projects") are
    // legacy compatibility — they can never match a hostname, so
    // skip them. Host-based matching uses only the host-prefix of
    // such entries.
    const slash = domain.indexOf("/");
    const bare = slash >= 0 ? domain.slice(0, slash) : domain;
    if (!bare) continue;
    if (host === bare) return true;
    if (host.endsWith("." + bare)) return true;
  }
  return false;
}

export function isLLMUrl(url: string, guardrailPort: number): boolean {
  const host = extractHost(url);
  if (matchesLLMDomain(host)) return true;
  // Ollama: localhost or 127.0.0.1 on known Ollama ports, but NOT the proxy port.
  // Host-boundary matched so an attacker-controlled hostname with
  // "localhost:11434" embedded cannot forge a hit.
  if (host === "localhost" || host === "127.0.0.1" || host === "::1") {
    let port = "";
    try {
      port = new URL(url).port;
    } catch {
      port = "";
    }
    if (!port) return false;
    if (port === String(guardrailPort)) return false;
    return OLLAMA_PORTS.includes(port);
  }
  return false;
}

function isAlreadyProxied(url: string, guardrailPort: number): boolean {
  // Only skip requests already targeting the guardrail proxy itself.
  return (
    url.includes(`127.0.0.1:${guardrailPort}`) ||
    url.includes(`localhost:${guardrailPort}`)
  );
}

// ---------------------------------------------------------------------------
// Layer 1: request-shape detection
//
// The providers.json allowlist catches the major providers by hostname, but
// any LLM whose endpoint we have not yet learned about would slip through
// (the "silent bypass" failure mode). Layer 1 adds a second rail that
// inspects the *shape* of each outbound HTTP request — path suffix, body
// schema, method, destination classification — and forces the request
// through the guardrail proxy whenever it walks like an LLM call, even
// when we have never seen the host before.
//
// This is intentionally cheap: no network, no parsing beyond a best-effort
// JSON peek, and we return "none" on any error so a broken heuristic never
// blocks real traffic.
// ---------------------------------------------------------------------------

/** Path fragments that identify LLM or agent APIs across providers. */
export const LLM_PATH_SUFFIXES: ReadonlyArray<string> = [
  "/chat/completions",
  "/completions",
  "/messages",
  ":generateContent",
  ":streamGenerateContent",
  "/converse",
  "/converse-stream",
  "/api/chat",
  "/api/generate",
  "/responses",
  "/backend-api/codex/responses",
];

/** Top-level JSON body keys that identify an LLM request payload. */
export const LLM_BODY_KEYS: ReadonlyArray<string> = [
  "messages",
  "contents",
  "input",
  "prompt",
  "inputs",
];

/**
 * Domains we *never* want to intercept: package registries, artifact
 * mirrors, telemetry, loopback control planes. Soft-allow branches in the
 * proxy consult the same list on the Go side (see internal/gateway/shape.go).
 */
export const KNOWN_SAFE_DOMAINS: ReadonlyArray<string> = [
  "github.com",
  "raw.githubusercontent.com",
  "codeload.github.com",
  "objects.githubusercontent.com",
  "registry.npmjs.org",
  "npmjs.org",
  "yarnpkg.com",
  "pypi.org",
  "files.pythonhosted.org",
  "crates.io",
  "rubygems.org",
  "sentry.io",
  "datadoghq.com",
  "segment.io",
  "segment.com",
];

export type LLMBodyShape = "messages" | "prompt" | "input" | "contents" | "none";

/** Classify a parsed JSON body into one of the known LLM shapes. */
export function classifyBodyShape(body: unknown): LLMBodyShape {
  if (!body || typeof body !== "object") return "none";
  const obj = body as Record<string, unknown>;
  if (Array.isArray(obj.messages)) return "messages";
  if (Array.isArray(obj.contents)) return "contents";
  if (typeof obj.input === "string" || Array.isArray(obj.input)) return "input";
  if (Array.isArray(obj.inputs)) return "input";
  if (typeof obj.prompt === "string") return "prompt";
  return "none";
}

function extractPath(urlStr: string): string {
  try {
    return new URL(urlStr).pathname;
  } catch {
    // options-bag style without an absolute URL; treat the raw path as-is
    return urlStr;
  }
}

/** Returns true when the URL ends with (or contains) a known LLM path fragment. */
export function hasLLMPathSuffix(urlStr: string): boolean {
  const path = extractPath(urlStr);
  return LLM_PATH_SUFFIXES.some(s => path.endsWith(s) || path.includes(s));
}

/** Returns true when the hostname is on the package-registry / telemetry allowlist. */
export function isKnownSafeDomain(urlStr: string): boolean {
  let host = "";
  try {
    host = new URL(urlStr).hostname.toLowerCase();
  } catch {
    return false;
  }
  if (!host) return false;
  return KNOWN_SAFE_DOMAINS.some(d => host === d || host.endsWith("." + d));
}

/**
 * Request-shape test: does this look like an LLM call even though the
 * hostname is not in providers.json? We require either an LLM-looking
 * path or an LLM-looking body key, and we always skip GET requests and
 * known-safe hostnames.
 *
 * Callers pass the best body shape they could cheaply compute — when no
 * body was available (e.g. https.request, streaming body) that degrades
 * to path-only detection, which is still better than fail-open.
 */
export function isLLMShapedRequest(
  urlStr: string,
  method: string,
  bodyShape: LLMBodyShape,
  guardrailPort: number,
): boolean {
  if (!urlStr) return false;
  if (isAlreadyProxied(urlStr, guardrailPort)) return false;
  const m = (method || "GET").toUpperCase();
  if (m === "GET" || m === "HEAD" || m === "OPTIONS") return false;
  if (isKnownSafeDomain(urlStr)) return false;
  if (hasLLMPathSuffix(urlStr)) return true;
  if (bodyShape !== "none") return true;
  return false;
}

/**
 * Best-effort, read-once-safe body peek. Inputs we know how to sniff
 * cheaply (string, Uint8Array, ArrayBuffer, Request) are decoded and
 * JSON-parsed; anything else (ReadableStream, FormData, Blob) returns
 * "none" rather than consuming the stream and breaking the downstream
 * fetch.
 *
 * Limit is 64 KiB: an LLM payload's shape is always visible in the
 * first page of JSON, and capping the peek prevents a hostile caller
 * from fouling heap via a multi-GB body.
 */
const BODY_PEEK_CAP_BYTES = 64 * 1024;

/**
 * Safe UTF-8 decode that never throws on a mid-codepoint slice. Used
 * by peekBodyForShape so a body cap that lands inside a multibyte
 * sequence does not produce a parse error that misclassifies the
 * shape.
 */
function decodeUtf8Safe(buf: ArrayBufferView): string {
  return new TextDecoder("utf-8", { fatal: false }).decode(buf);
}

/**
 * Read at most `cap` bytes from a stream without consuming beyond
 * that cap. The stream is released early if the first chunks exceed
 * the cap; subsequent chunks are never read, so a pathological body
 * (GBs) never allocates past `cap` bytes. Returns the raw byte
 * sequence so the caller can decide on encoding.
 */
async function readStreamBounded(
  stream: ReadableStream<Uint8Array>,
  cap: number,
): Promise<Uint8Array> {
  const reader = stream.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (total < cap) {
      const { value, done } = await reader.read();
      if (done) break;
      if (!value) continue;
      if (total + value.byteLength > cap) {
        chunks.push(value.subarray(0, cap - total));
        total = cap;
        break;
      }
      chunks.push(value);
      total += value.byteLength;
    }
  } finally {
    // Cancel the rest of the stream so the underlying transport
    // does not keep delivering bytes we will never consume.
    try {
      await reader.cancel();
    } catch {
      /* ignore */
    }
    try {
      reader.releaseLock();
    } catch {
      /* ignore */
    }
  }
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

export async function peekBodyForShape(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<LLMBodyShape> {
  try {
    if (input instanceof Request) {
      // input.clone() keeps the caller's Request body intact for the
      // downstream originalFetch call. Prefer a streaming read
      // capped at BODY_PEEK_CAP_BYTES so a multi-GB body cannot
      // exhaust the extension host's memory; only fall back to a
      // full-body .text() if the runtime does not expose
      // Request.body (older Node / test mocks).
      const cloned = input.clone();
      const stream = (cloned as unknown as { body?: ReadableStream<Uint8Array> })
        .body;
      let bytes: Uint8Array;
      if (stream && typeof stream.getReader === "function") {
        bytes = await readStreamBounded(stream, BODY_PEEK_CAP_BYTES);
      } else {
        const text = await cloned.text().catch(() => "");
        if (!text) return "none";
        // Text path: cap on character count as a byte upper-bound
        // (UTF-16 char count ≥ UTF-8 byte count in practice for
        // typical ASCII-dominant LLM payloads; worst case 4-byte
        // codepoints still fit well under 64 KiB).
        const capped = text.length > BODY_PEEK_CAP_BYTES
          ? text.slice(0, BODY_PEEK_CAP_BYTES)
          : text;
        try {
          return classifyBodyShape(JSON.parse(capped));
        } catch {
          return "none";
        }
      }
      if (bytes.byteLength === 0) return "none";
      try {
        return classifyBodyShape(JSON.parse(decodeUtf8Safe(bytes)));
      } catch {
        return "none";
      }
    }
    const body = init?.body as unknown;
    if (body == null) return "none";
    if (typeof body === "string") {
      try {
        return classifyBodyShape(JSON.parse(body.slice(0, BODY_PEEK_CAP_BYTES)));
      } catch {
        return "none";
      }
    }
    if (body instanceof Uint8Array) {
      const slice = body.subarray(0, BODY_PEEK_CAP_BYTES);
      try {
        return classifyBodyShape(JSON.parse(decodeUtf8Safe(slice)));
      } catch {
        return "none";
      }
    }
    if (body instanceof ArrayBuffer) {
      const view = new Uint8Array(body).subarray(0, BODY_PEEK_CAP_BYTES);
      try {
        return classifyBodyShape(JSON.parse(decodeUtf8Safe(view)));
      } catch {
        return "none";
      }
    }
    // ReadableStream, FormData, Blob, etc. — consuming them would break
    // the downstream fetch. Fall back to path-only detection.
    return "none";
  } catch {
    return "none";
  }
}

/**
 * Extract the provider API key from whichever header the provider SDK uses.
 * Different providers use different auth mechanisms:
 *   - OpenAI / OpenRouter / Gemini compat: Authorization: Bearer <key>
 *   - Anthropic: x-api-key: <key>
 *   - Azure OpenAI: api-key: <key>
 *   - Gemini native: ?key= query param (handled separately, not in headers)
 *   - Bedrock: AWS SigV4 (multiple headers, not a simple key)
 *   - Ollama: no auth
 *
 * Returns the key prefixed with "Bearer " for consistency, or empty string.
 */
function extractProviderKey(headers: Headers): string {
  // Authorization: Bearer <key> — most providers
  const auth = headers.get("Authorization") ?? "";
  if (auth && !auth.startsWith("Bearer sk-dc-")) {
    return auth;
  }
  // x-api-key — Anthropic
  const xApiKey = headers.get("x-api-key") ?? "";
  if (xApiKey) {
    return `Bearer ${xApiKey}`;
  }
  // api-key — Azure OpenAI
  const apiKey = headers.get("api-key") ?? "";
  if (apiKey) {
    return `Bearer ${apiKey}`;
  }
  return "";
}

/**
 * Same as extractProviderKey but for Node http.request headers (plain object,
 * case-sensitive keys).
 */
function extractProviderKeyFromRecord(hdrs: Record<string, string>): string {
  const auth = hdrs["Authorization"] ?? hdrs["authorization"] ?? "";
  if (auth && !auth.startsWith("Bearer sk-dc-")) {
    return auth;
  }
  const xApiKey = hdrs["x-api-key"] ?? hdrs["X-Api-Key"] ?? "";
  if (xApiKey) {
    return `Bearer ${xApiKey}`;
  }
  const apiKey = hdrs["api-key"] ?? hdrs["Api-Key"] ?? "";
  if (apiKey) {
    return `Bearer ${apiKey}`;
  }
  return "";
}

/**
 * Synchronous snapshot of DefenseClaw correlation headers injected onto
 * every intercepted LLM request. Returning an empty object is legal: the
 * Go side treats any missing header as "unknown". Anything the getter
 * does return is forwarded verbatim to the guardrail proxy so the audit /
 * gateway.jsonl / OTel surfaces all see the same keys at once.
 */
export type CorrelationHeadersGetter = () => Record<string, string>;

/**
 * Build the proxy-hop headers (X-DC-Target-URL, X-AI-Auth, X-DC-Auth) plus
 * any caller-supplied correlation headers (X-DefenseClaw-*) the guardrail
 * proxy's CorrelationMiddleware stamps onto the audit envelope.
 *
 * OpenClaw already resolves the real provider API key and sets it in the
 * appropriate header for each provider SDK. We extract it from whichever
 * header is used and forward it as X-AI-Auth for uniform proxy handling.
 */
function buildProxyHeaders(
  targetOrigin: string,
  providerKey: string,
  getCorrelationHeaders: CorrelationHeadersGetter,
): Record<string, string> {
  const hdrs: Record<string, string> = {
    [TARGET_URL_HEADER]: targetOrigin,
  };

  if (providerKey) {
    hdrs[AI_AUTH_HEADER] = providerKey;
  }

  // X-DC-Auth: proxy authentication token for remote deployments.
  const sidecarToken = loadSidecarConfig().token;
  if (sidecarToken) {
    hdrs[DC_AUTH_HEADER] = `Bearer ${sidecarToken}`;
  }

  // v7 correlation: inject X-DefenseClaw-* headers so the proxy's
  // CorrelationMiddleware can stamp agent_id / session_id / run_id /
  // trace_id / policy_id on every guardrail-* audit row. Without this,
  // every LLM request emitted via the fetch interceptor landed in
  // SQLite with those columns NULL because the proxy has no other way
  // to learn plugin-side identity on an intercepted hop.
  let corr: Record<string, string> | undefined;
  try {
    corr = getCorrelationHeaders();
  } catch {
    // Never let a misbehaving getter break LLM traffic — missing
    // correlation headers are recoverable, blocked LLM calls are not.
  }
  if (corr) {
    for (const [k, v] of Object.entries(corr)) {
      if (v !== undefined && v !== "") hdrs[k] = v;
    }
  }

  return hdrs;
}

/**
 * Default getter that returns nothing. Used when callers construct an
 * interceptor without wiring identity — keeps older call sites working.
 */
const emptyCorrelationHeaders: CorrelationHeadersGetter = () => ({});

/** Canonical header-name set so callers outside this module can stay DRY. */
export const DEFENSECLAW_CORRELATION_HEADER_NAMES = [
  HEADER_DEFENSECLAW_AGENT_ID,
  HEADER_DEFENSECLAW_AGENT_INSTANCE_ID,
  HEADER_DEFENSECLAW_AGENT_NAME,
  HEADER_DEFENSECLAW_POLICY_ID,
  HEADER_DEFENSECLAW_RUN_ID,
  HEADER_DEFENSECLAW_SESSION_ID,
  HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID,
  HEADER_DEFENSECLAW_TRACE_ID,
] as const;

export interface CreateFetchInterceptorOptions {
  guardrailPort: number;
  /**
   * Synchronous snapshot of DefenseClaw X-DefenseClaw-* correlation
   * headers to stamp on every intercepted LLM request. Called once per
   * request — implementations should return cached values rather than
   * performing I/O.
   */
  getCorrelationHeaders?: CorrelationHeadersGetter;
}

/**
 * Creates an interceptor that, when started, patches globalThis.fetch to
 * redirect LLM API calls through the guardrail proxy.
 * Call stop() to restore the original fetch.
 *
 * Accepts either a legacy `guardrailPort` number (backwards-compatible
 * with existing tests) or a structured options bag that additionally
 * carries a correlation-headers getter.
 */
export function createFetchInterceptor(
  portOrOpts: number | CreateFetchInterceptorOptions,
) {
  const interceptorOpts: CreateFetchInterceptorOptions =
    typeof portOrOpts === "number"
      ? { guardrailPort: portOrOpts }
      : portOrOpts;
  const guardrailPort = interceptorOpts.guardrailPort;
  const getCorrelationHeaders =
    interceptorOpts.getCorrelationHeaders ?? emptyCorrelationHeaders;
  const proxyBase = `http://127.0.0.1:${guardrailPort}`;
  let originalFetch: typeof globalThis.fetch | null = null;
  let originalHttpsRequest: typeof https.request | null = null;
  let egressReporter: EgressReporter | null = null;

  // Extract { host, path } from a URL string without throwing. Missing
  // pieces are tolerated so the caller's downstream fetch is never
  // perturbed by a malformed URL in telemetry.
  function extractHostPath(urlStr: string): { host: string; path: string } {
    try {
      const u = new URL(urlStr);
      return { host: u.hostname, path: `${u.pathname}${u.search}` };
    } catch {
      return { host: "", path: urlStr };
    }
  }

  function start(): void {
    if (originalFetch) return; // already started
    originalFetch = globalThis.fetch;
    egressReporter = createEgressReporter({ guardrailPort });

    // Layer 4 (governance): pull the sidecar's merged provider
    // registry so operator-added domains (via `defenseclaw setup
    // provider add` or a hand-edited custom-providers.json) take
    // effect without rebuilding the plugin. Best-effort, short
    // timeout; we use the process-supplied fetch BEFORE we swap it
    // out below so the bootstrap call is not intercepted by the
    // wrapper we're about to install.
    void bootstrapProviderOverlay(guardrailPort, {
      fetchImpl: originalFetch,
    });

    globalThis.fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const urlStr = String(input instanceof Request ? input.url : input);

      // Never self-loop: a request already aimed at the guardrail proxy
      // short-circuits before any shape inspection so we don't peek its body.
      if (isAlreadyProxied(urlStr, guardrailPort)) {
        return originalFetch!(input, init);
      }

      // Layer 0: the known-provider allowlist is cheap and path-free.
      const knownLLM = isLLMUrl(urlStr, guardrailPort);
      let shouldIntercept = knownLLM;
      let shapeBranch: "known" | "shape" | "passthrough" = knownLLM ? "known" : "passthrough";
      let bodyShape: LLMBodyShape = "none";

      // Layer 1: request-shape detection. Only peek the body when the
      // allowlist didn't already match — peeking costs a clone().
      if (!knownLLM) {
        const method = (input instanceof Request ? input.method : init?.method) ?? "GET";
        bodyShape = await peekBodyForShape(input, init);
        if (isLLMShapedRequest(urlStr, method, bodyShape, guardrailPort)) {
          shouldIntercept = true;
          shapeBranch = "shape";
        }
      }

      if (!shouldIntercept) {
        // Layer 3: silent-bypass telemetry. Report every request that
        // left our interceptor without being rewritten so operators
        // can spot "known LLM-shaped call to unknown host" cases.
        const hp = extractHostPath(urlStr);
        egressReporter?.report({
          targetHost: hp.host,
          targetPath: hp.path,
          bodyShape,
          looksLikeLLM: bodyShape !== "none" || hasLLMPathSuffix(urlStr),
          branch: "passthrough",
          decision: "allow",
          reason: "no-match",
        });
        return originalFetch!(input, init);
      }

      let original: URL;
      try {
        original = new URL(urlStr);
      } catch {
        return originalFetch!(input, init);
      }

      // Rewrite: keep path + query, replace scheme://host with proxy.
      const proxied = `${proxyBase}${original.pathname}${original.search}`;

      // Merge all original headers and add proxy-hop headers.
      const headers = new Headers(
        input instanceof Request ? input.headers : (init?.headers as HeadersInit | undefined),
      );
      const providerKey = extractProviderKey(headers);
      const proxyHdrs = buildProxyHeaders(
        original.origin,
        providerKey,
        getCorrelationHeaders,
      );
      for (const [k, v] of Object.entries(proxyHdrs)) {
        headers.set(k, v);
      }

      // Build new init, preserving all original properties.
      const newInit: RequestInit =
        input instanceof Request
          ? { method: input.method, body: input.body, headers }
          : { ...(init ?? {}), headers };

      if (shapeBranch === "shape") {
        console.log(
          `[defenseclaw] intercepted LLM-shaped call → ${urlStr} (body_shape=${bodyShape}) proxied via ${proxyBase}`,
        );
      } else {
        console.log(
          `[defenseclaw] intercepted LLM call → ${urlStr} proxied via ${proxyBase}`,
        );
      }

      const response = await originalFetch!(proxied, newInit);

      const blocked = response.headers.get("x-defenseclaw-blocked") === "true";
      if (blocked) {
        console.warn(
          "[defenseclaw] REQUEST BLOCKED by guardrail policy",
        );
      }

      // Report the routed-through-proxy call so egress telemetry
      // reflects both the "known" and "shape" branches the Go
      // passthrough reports for server-originated traffic.
      const hp = extractHostPath(urlStr);
      egressReporter?.report({
        targetHost: hp.host,
        targetPath: hp.path,
        bodyShape,
        looksLikeLLM: true,
        branch: shapeBranch === "shape" ? "shape" : "known",
        decision: blocked ? "block" : "allow",
        reason: shapeBranch === "shape" ? "shape-match" : "known-provider",
      });

      return response;
    };

    // Also patch https.request so axios, undici, and other non-fetch HTTP
    // clients are intercepted. All of them ultimately use node:https.request.
    originalHttpsRequest = https.request.bind(https);
    const originalHttpRequest = http.request.bind(http);

    type NodeRequestOptions = Record<string, unknown>;
    type NodeIncomingMessage = unknown;
    type NodeClientRequest = ReturnType<typeof http.request>;

    /**
     * Normalize the varied `https.request` call shapes into a single URL string
     * we can match against LLM provider domains. Callers may pass:
     *   - request(url: string)
     *   - request(url: URL)
     *   - request(options)                   // { host|hostname, port, path, protocol }
     *   - request(url, options)              // URL first, then extra options
     * @smithy/node-http-handler v4 passes an options object with `host` (NOT
     * `hostname`), separate `port`, and separate `path`, so we must read both
     * `host` and `hostname` and fold `path` back in to match on domain + path.
     */
    function buildUrlStringFromArgs(
      urlOrOptions: string | URL | NodeRequestOptions,
      secondArg: NodeRequestOptions | ((res: NodeIncomingMessage) => void) | undefined,
    ): string {
      if (typeof urlOrOptions === "string") return urlOrOptions;
      if (urlOrOptions instanceof URL) return urlOrOptions.toString();

      const opts = urlOrOptions as {
        host?: unknown;
        hostname?: unknown;
        port?: unknown;
        path?: unknown;
        protocol?: unknown;
      };
      const overlay = (typeof secondArg === "object" && secondArg !== null
        ? (secondArg as typeof opts)
        : {});

      const host =
        (typeof overlay.hostname === "string" && overlay.hostname) ||
        (typeof overlay.host === "string" && overlay.host) ||
        (typeof opts.hostname === "string" && opts.hostname) ||
        (typeof opts.host === "string" && opts.host) ||
        "";
      const port =
        (overlay.port !== undefined ? String(overlay.port) : "") ||
        (opts.port !== undefined ? String(opts.port) : "");
      const path =
        (typeof overlay.path === "string" && overlay.path) ||
        (typeof opts.path === "string" && opts.path) ||
        "/";
      const proto =
        (typeof overlay.protocol === "string" && overlay.protocol) ||
        (typeof opts.protocol === "string" && opts.protocol) ||
        "https:";

      if (!host) return "";
      const hostPart = port ? `${host}:${port}` : host;
      return `${proto}//${hostPart}${path}`;
    }

    function patchedHttpsRequest(
      urlOrOptions: string | URL | NodeRequestOptions,
      optionsOrCallback?: NodeRequestOptions | ((res: NodeIncomingMessage) => void),
      callback?: (res: NodeIncomingMessage) => void,
    ): NodeClientRequest {
      const urlStr = buildUrlStringFromArgs(urlOrOptions, optionsOrCallback);

      // Path-only shape detection for https.request — the body is
      // written via req.write after this call returns, so peeking is
      // not an option. hasLLMPathSuffix still catches the overwhelming
      // majority of unknown-provider SDKs (Bedrock converse-stream,
      // Anthropic /messages, Gemini :generateContent, ollama /api/chat).
      const shapedForHTTPS = Boolean(
        urlStr &&
          !isKnownSafeDomain(urlStr) &&
          !isAlreadyProxied(urlStr, guardrailPort) &&
          hasLLMPathSuffix(urlStr),
      );
      const knownForHTTPS = Boolean(
        urlStr && isLLMUrl(urlStr, guardrailPort) && !isAlreadyProxied(urlStr, guardrailPort),
      );

      if (urlStr && (knownForHTTPS || shapedForHTTPS)) {
        let opts: NodeRequestOptions = {};
        let cb = callback;

        if (typeof optionsOrCallback === "function") {
          cb = optionsOrCallback;
          opts = typeof urlOrOptions === "string" || urlOrOptions instanceof URL
            ? {} : urlOrOptions as NodeRequestOptions;
        } else if (optionsOrCallback && typeof optionsOrCallback === "object") {
          opts = optionsOrCallback as NodeRequestOptions;
        }

        let originalUrl: URL;
        try {
          originalUrl = new URL(urlStr);
        } catch {
          return originalHttpsRequest!(urlOrOptions as string, optionsOrCallback as NodeRequestOptions, callback);
        }

        const hdrs = opts.headers as Record<string, string> ?? {};
        const providerKey = extractProviderKeyFromRecord(hdrs);
        const proxyHdrs = buildProxyHeaders(
          originalUrl.origin,
          providerKey,
          getCorrelationHeaders,
        );

        // Spread `opts` first, then overwrite target fields. Crucially, drop:
        //
        //  - `host` (smithy passes `host` not `hostname`; Node's `host` wins
        //    over `hostname` in some paths, which would send traffic to the
        //    original LLM domain instead of the proxy);
        //  - `agent` (callers like @smithy/node-http-handler pass an
        //    `https.Agent`. Node's `http.request` rejects an agent whose
        //    `protocol === "https:"` with `ERR_INVALID_PROTOCOL`: "Protocol
        //    'http:' not supported. Expected 'https:'". We want Node to use
        //    the default http agent for the proxy hop, so set `agent: false`);
        //  - TLS-only options (`ca`, `cert`, `key`, ...) which have no meaning
        //    on a plain http.request and could still drag protocol checks in.
        const {
          host: _legacyHost,
          agent: _legacyAgent,
          ca: _ca,
          cert: _cert,
          key: _key,
          pfx: _pfx,
          passphrase: _passphrase,
          servername: _servername,
          ciphers: _ciphers,
          ecdhCurve: _ecdhCurve,
          secureProtocol: _secureProtocol,
          minVersion: _minVersion,
          maxVersion: _maxVersion,
          sigalgs: _sigalgs,
          crl: _crl,
          dhparam: _dhparam,
          rejectUnauthorized: _rejectUnauthorized,
          checkServerIdentity: _checkServerIdentity,
          session: _session,
          allowPartialTrustChain: _allowPartialTrustChain,
          ...restOpts
        } = opts as { host?: unknown; agent?: unknown } & Record<string, unknown>;
        void _legacyHost;
        void _legacyAgent;
        void _ca;
        void _cert;
        void _key;
        void _pfx;
        void _passphrase;
        void _servername;
        void _ciphers;
        void _ecdhCurve;
        void _secureProtocol;
        void _minVersion;
        void _maxVersion;
        void _sigalgs;
        void _crl;
        void _dhparam;
        void _rejectUnauthorized;
        void _checkServerIdentity;
        void _session;
        void _allowPartialTrustChain;
        const newOpts: NodeRequestOptions = {
          ...restOpts,
          hostname: "127.0.0.1",
          port: guardrailPort,
          protocol: "http:",
          path: `${originalUrl.pathname}${originalUrl.search}`,
          headers: { ...hdrs, ...proxyHdrs },
          // Force Node to pick a default http.Agent for this request. Leaving
          // the caller's https.Agent in place would throw at socket allocation.
          agent: false,
        };

        if (!knownForHTTPS && shapedForHTTPS) {
          console.log(`[defenseclaw] intercepted LLM-shaped call (https.request) → ${urlStr} (path-match) proxied via ${proxyBase}`);
        } else {
          console.log(`[defenseclaw] intercepted LLM call (https.request) → ${urlStr} proxied via ${proxyBase}`);
        }
        // Egress telemetry for the https.request branches. body_shape
        // is intentionally "none" because req.write happens after we
        // return — the body is not observable here.
        {
          const hp = extractHostPath(urlStr);
          egressReporter?.report({
            targetHost: hp.host,
            targetPath: hp.path,
            bodyShape: "none",
            looksLikeLLM: true,
            branch: !knownForHTTPS && shapedForHTTPS ? "shape" : "known",
            decision: "allow",
            reason: !knownForHTTPS && shapedForHTTPS ? "shape-match" : "known-provider",
          });
        }
        return http.request(newOpts as unknown as Parameters<typeof http.request>[0], cb as Parameters<typeof http.request>[1]);
      }

      // Non-intercepted https.request — report silent passthrough so
      // the TUI/egress event log sees LLM-looking calls slipping past
      // the known-provider + shape rails (e.g. an unknown SDK we
      // have never classified).
      if (urlStr) {
        const hp = extractHostPath(urlStr);
        egressReporter?.report({
          targetHost: hp.host,
          targetPath: hp.path,
          bodyShape: "none",
          looksLikeLLM: hasLLMPathSuffix(urlStr),
          branch: "passthrough",
          decision: "allow",
          reason: "no-match",
        });
      }
      return originalHttpsRequest!(urlOrOptions as string, optionsOrCallback as NodeRequestOptions, callback);
    }

    https.request = patchedHttpsRequest as typeof https.request;

    console.log(
      `[defenseclaw] LLM fetch interceptor active (proxy: ${proxyBase})`,
    );
  }

  function stop(): void {
    if (originalFetch) {
      globalThis.fetch = originalFetch;
      originalFetch = null;
    }
    // Restore https.request (safe because we used CJS require, not frozen ESM)
    if (originalHttpsRequest) {
      https.request = originalHttpsRequest;
    }
    if (egressReporter) {
      egressReporter.stop();
      egressReporter = null;
    }
    console.log("[defenseclaw] LLM fetch interceptor stopped");
  }

  return { start, stop };
}
