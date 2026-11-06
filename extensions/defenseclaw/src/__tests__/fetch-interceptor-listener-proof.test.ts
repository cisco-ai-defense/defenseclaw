/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * GAP-0594: a proxied model call carries the provider key and the gateway
 * token only to a guardrail listener that proved it is this account's
 * gateway. A failed proof answers as a gateway outage and sends nothing.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFetchInterceptor, GATEWAY_DOWN_MESSAGE } from "../fetch-interceptor.js";
import { ListenerProofError, _setListenerProofForTest } from "../listener-proof.js";
import { _resetSidecarConfigCache } from "../sidecar-config.js";

const TOKEN = "c".repeat(64);

describe("proxy hop listener proof", () => {
  const originalFetch = globalThis.fetch;
  const saved = { home: process.env.DEFENSECLAW_HOME, token: process.env.DEFENSECLAW_GATEWAY_TOKEN };
  let calls: Array<{ url: string; headers: Headers }>;
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    process.env.DEFENSECLAW_HOME = mkdtempSync(join(tmpdir(), "dc-proof-"));
    process.env.DEFENSECLAW_GATEWAY_TOKEN = TOKEN;
    _resetSidecarConfigCache();
    calls = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), headers: new Headers(init?.headers) });
      return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
    }) as typeof fetch;
    interceptor = createFetchInterceptor(14011);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    globalThis.fetch = originalFetch;
    if (saved.home === undefined) delete process.env.DEFENSECLAW_HOME;
    else process.env.DEFENSECLAW_HOME = saved.home;
    if (saved.token === undefined) delete process.env.DEFENSECLAW_GATEWAY_TOKEN;
    else process.env.DEFENSECLAW_GATEWAY_TOKEN = saved.token;
    _resetSidecarConfigCache();
    _setListenerProofForTest(async () => {});
    vi.restoreAllMocks();
  });

  const modelCall = () =>
    fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: "Bearer sk-provider-key" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
    });

  it("sends nothing to a guardrail listener that fails the proof", async () => {
    _setListenerProofForTest(async () => {
      throw new ListenerProofError("not this account's gateway");
    });
    const res = await modelCall();
    expect(res.status).toBe(503);
    expect((await res.json()).error.message).toBe(GATEWAY_DOWN_MESSAGE);
    expect(calls.filter((c) => c.url.includes(":14011/v1/chat/completions"))).toEqual([]);
  });

  it("sends no provider key without a token to prove the listener with", async () => {
    const savedLegacy = process.env.OPENCLAW_GATEWAY_TOKEN;
    process.env.DEFENSECLAW_GATEWAY_TOKEN = "";
    process.env.OPENCLAW_GATEWAY_TOKEN = "";
    _resetSidecarConfigCache();
    try {
      // The real proof: with no token it refuses before any connection.
      _setListenerProofForTest(undefined);
      const res = await modelCall();
      expect(res.status).toBe(503);
      expect(calls.filter((c) => c.url.includes(":14011/v1/chat/completions"))).toEqual([]);
    } finally {
      if (savedLegacy === undefined) delete process.env.OPENCLAW_GATEWAY_TOKEN;
      else process.env.OPENCLAW_GATEWAY_TOKEN = savedLegacy;
    }
  });

  it("proves the listener before every proxied model call", async () => {
    let proofs = 0;
    _setListenerProofForTest(async () => {
      proofs++;
    });
    await modelCall();
    await modelCall();
    // One proof per model call; egress telemetry proves for its own posts too.
    expect(proofs).toBeGreaterThanOrEqual(2);
    expect(calls.filter((c) => c.url.includes(":14011/v1/chat/completions"))).toHaveLength(2);
  });

  it("sends the provider key and the token to a proven listener", async () => {
    const proven: string[] = [];
    _setListenerProofForTest(async (host, port) => {
      proven.push(`${host}:${port}`);
    });
    const res = await modelCall();
    expect(res.status).toBe(200);
    expect(proven).toContain("127.0.0.1:14011");
    const hop = calls.find((c) => c.url.includes(":14011/v1/chat/completions"));
    expect(hop?.headers.get("x-dc-auth")).toBe(`Bearer ${TOKEN}`);
    expect(hop?.headers.get("x-ai-auth") ?? "").toContain("sk-provider-key");
  });

  // GAP-0580 with GAP-0594: only a proof that found nothing listening, or
  // timed out, is an outage the saved open mode continues through.
  function openInterceptor(): void {
    interceptor.stop();
    interceptor = createFetchInterceptor({ guardrailPort: 14011, getOutageMode: () => "open" });
    interceptor.start();
  }

  it("continues to the provider in the saved open mode when the proof finds nothing listening", async () => {
    openInterceptor();
    _setListenerProofForTest(async () => {
      throw new ListenerProofError("connect ECONNREFUSED 127.0.0.1:14011", true);
    });
    const res = await modelCall();
    expect(res.status).toBe(200);
    expect(calls.filter((c) => c.url.includes(":14011/v1/chat/completions"))).toEqual([]);
    const direct = calls.filter((c) => c.url === "https://api.openai.com/v1/chat/completions");
    expect(direct).toHaveLength(1);
    expect(direct[0].headers.get("authorization")).toBe("Bearer sk-provider-key");
    expect(direct[0].headers.get("x-dc-auth")).toBeNull();
  });

  it("keeps a listener that fails the proof blocked in the saved open mode", async () => {
    openInterceptor();
    _setListenerProofForTest(async () => {
      throw new ListenerProofError("not this account gateway");
    });
    const res = await modelCall();
    expect(res.status).toBe(503);
    expect((await res.json()).error.message).toBe(GATEWAY_DOWN_MESSAGE);
    expect(calls.filter((c) => c.url.includes("chat/completions"))).toEqual([]);
  });
});
