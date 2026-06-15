/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Ollama discovery-probe passthrough.
 *
 * The OpenClaw agent probes Ollama on startup with GET /api/tags. Those
 * discovery / health endpoints carry no prompt or completion content, so
 * the guardrail has nothing to inspect — and intercepting them with no
 * reachable Ollama returns an unparseable response that the agent treats
 * as a hard failure (it then never falls back to its real provider).
 *
 * These tests pin that the discovery GETs go direct while inference
 * endpoints (/api/chat) stay intercepted, and that an inference call
 * cannot disguise itself as a probe.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createRequire } from "node:module";

import {
  createFetchInterceptor,
  isOllamaDiscoveryProbe,
} from "../fetch-interceptor.js";

const _require = createRequire(import.meta.url);
const http = _require("http") as typeof import("http");
const https = _require("https") as typeof import("https");

const guardrailPort = 14010;

describe("isOllamaDiscoveryProbe", () => {
  it("matches GET discovery endpoints on the Ollama loopback port", () => {
    for (const path of ["/api/tags", "/api/version", "/api/ps"]) {
      expect(
        isOllamaDiscoveryProbe(`http://127.0.0.1:11434${path}`, "GET", guardrailPort),
      ).toBe(true);
      expect(
        isOllamaDiscoveryProbe(`http://localhost:11434${path}`, "get", guardrailPort),
      ).toBe(true);
    }
  });

  it("does NOT match inference endpoints (those stay intercepted)", () => {
    expect(
      isOllamaDiscoveryProbe("http://127.0.0.1:11434/api/chat", "POST", guardrailPort),
    ).toBe(false);
    expect(
      isOllamaDiscoveryProbe("http://127.0.0.1:11434/api/generate", "POST", guardrailPort),
    ).toBe(false);
  });

  it("requires GET — a non-GET to a discovery path is not a probe", () => {
    expect(
      isOllamaDiscoveryProbe("http://127.0.0.1:11434/api/tags", "POST", guardrailPort),
    ).toBe(false);
  });

  it("cannot be disguised via a crafted query string", () => {
    // pathname is /api/chat; the /api/tags lives only in the query.
    expect(
      isOllamaDiscoveryProbe(
        "http://127.0.0.1:11434/api/chat?x=/api/tags",
        "GET",
        guardrailPort,
      ),
    ).toBe(false);
  });

  it("is scoped to loopback hosts and the Ollama port", () => {
    // Non-loopback host.
    expect(
      isOllamaDiscoveryProbe("http://evil.example:11434/api/tags", "GET", guardrailPort),
    ).toBe(false);
    // Non-Ollama port (e.g. the guardrail proxy itself).
    expect(
      isOllamaDiscoveryProbe(
        `http://127.0.0.1:${guardrailPort}/api/tags`,
        "GET",
        guardrailPort,
      ),
    ).toBe(false);
  });
});

describe("discovery probes go direct; inference stays proxied (http path)", () => {
  type Captured = { opts: Record<string, unknown> };
  const captured: Captured[] = [];
  let originalHttpRequest: typeof http.request;
  let originalHttpGet: typeof http.get;
  let originalHttpsRequest: typeof https.request;
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    captured.length = 0;
    originalHttpRequest = http.request;
    originalHttpGet = http.get;
    originalHttpsRequest = https.request;
    const sink: typeof http.request = ((
      opts: Record<string, unknown>,
    ) => {
      captured.push({ opts });
      return {
        on: () => undefined,
        end: () => undefined,
        write: () => undefined,
        destroy: () => undefined,
      } as unknown as ReturnType<typeof http.request>;
    }) as typeof http.request;
    http.request = sink;
    http.get = sink as unknown as typeof http.get;
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    http.request = originalHttpRequest;
    http.get = originalHttpGet;
    https.request = originalHttpsRequest;
  });

  it("lets a GET /api/tags reach the real Ollama port (not the proxy)", () => {
    http.get(
      {
        hostname: "127.0.0.1",
        port: 11434,
        method: "GET",
        path: "/api/tags",
        headers: {},
      } as unknown as Parameters<typeof http.get>[0],
      () => undefined,
    );
    expect(captured.length).toBeGreaterThanOrEqual(1);
    const opts = captured[0].opts as { hostname?: string; port?: number };
    // Direct passthrough: original Ollama port, NOT rewritten to the proxy.
    expect(opts.port).toBe(11434);
    expect(opts.hostname).toBe("127.0.0.1");
  });

  it("still proxies a POST /api/chat (inference is inspected)", () => {
    http.request(
      {
        hostname: "127.0.0.1",
        port: 11434,
        method: "POST",
        path: "/api/chat",
        headers: { "content-type": "application/json" },
      } as unknown as Parameters<typeof http.request>[0],
      () => undefined,
    );
    expect(captured.length).toBeGreaterThanOrEqual(1);
    const opts = captured[0].opts as { hostname?: string; port?: number };
    expect(opts.hostname).toBe("127.0.0.1");
    expect(opts.port).toBe(guardrailPort);
  });
});

describe("discovery probes go direct (fetch path)", () => {
  let originalFetch: typeof globalThis.fetch;
  let interceptor: ReturnType<typeof createFetchInterceptor>;
  const seen: string[] = [];

  beforeEach(() => {
    seen.length = 0;
    originalFetch = globalThis.fetch;
    // Sink the real fetch the interceptor captures so we can observe the
    // URL it ultimately calls (original for passthrough, proxy for
    // intercepted).
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      seen.push(String(input instanceof Request ? input.url : input));
      return new Response("{}", { status: 200 });
    }) as typeof globalThis.fetch;
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    globalThis.fetch = originalFetch;
  });

  // start() fires a best-effort provider-overlay bootstrap fetch to
  // /v1/config/providers, so filter background traffic out of the
  // captured set before asserting on the request under test.
  const meaningful = () => seen.filter((u) => !u.includes("/v1/config/providers"));

  it("forwards GET /api/tags to the original Ollama URL unchanged", async () => {
    await globalThis.fetch("http://127.0.0.1:11434/api/tags");
    // Sent verbatim to the real Ollama port — never rewritten to the proxy.
    expect(meaningful()).toEqual(["http://127.0.0.1:11434/api/tags"]);
  });

  it("rewrites POST /api/chat to the guardrail proxy", async () => {
    await globalThis.fetch("http://127.0.0.1:11434/api/chat", {
      method: "POST",
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
      headers: { "content-type": "application/json" },
    });
    const calls = meaningful();
    // Inference is proxied: routed at the guardrail port, never sent
    // direct to the raw Ollama endpoint.
    expect(calls.some((u) => u.includes(`127.0.0.1:${guardrailPort}`))).toBe(true);
    expect(calls).not.toContain("http://127.0.0.1:11434/api/chat");
  });
});
