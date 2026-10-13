/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * #473: OpenClaw 2026.6.x can emit LLM traffic that never increments
 * gateway.log "INCOMING REQUEST" while :4000 still answers liveliness.
 * The interceptor must rewrite a sentinel OpenAI chat URL onto the
 * local proxy without leaving the box.
 */

import { createServer } from "node:http";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createFetchInterceptor,
  INTERCEPTION_PROBE_HEADER,
} from "../fetch-interceptor.js";
import { isOpenClawClientProcess, logInfo } from "../log.js";

const guardrailPort = 14173;

describe("OpenClaw interception self-test", () => {
  const realFetch = globalThis.fetch;
  const forwarded: string[] = [];
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    forwarded.length = 0;
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      forwarded.push(String(input instanceof Request ? input.url : input));
      return new Response("ok");
    }) as typeof fetch;
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it("rewrites a sentinel OpenAI chat URL onto the local guardrail proxy", async () => {
    const result = await interceptor.verifyInterception();
    expect(result.ok).toBe(true);
    expect(result.destination).toBe(`http://127.0.0.1:${guardrailPort}/v1/chat/completions`);
    expect(result.layers.fetch).toBe(true);
    expect(result.layers.httpsRequest).toBe(true);
    expect(result.layers.httpRequest).toBe(true);
    expect(result.layers.httpGet).toBe(true);
    expect(result.layers.undiciDispatcher).toBe(true);
    expect(result.reason).toBe("interception-self-test");
    expect(forwarded.some((url) => url.includes("api.openai.com"))).toBe(false);
  });

  it("intercepts a request that carries its own dispatcher (GAP-0190)", async () => {
    // OpenClaw sends every model request through an SSRF-guarded fetch that hands undici a
    // per-request dispatcher, which skips globalThis.fetch and the global dispatcher.
    const { Agent, request } = createRequire(import.meta.url)("undici") as typeof import("undici");
    const agent = new Agent();
    try {
      const response = await request("https://api.openai.com/v1/chat/completions", {
        method: "POST",
        headers: { "content-type": "application/json", [INTERCEPTION_PROBE_HEADER]: "1" },
        body: "{}",
        dispatcher: agent,
      });
      expect(response.headers[INTERCEPTION_PROBE_HEADER.toLowerCase()]).toBe("1");
      await response.body.text();
    } finally {
      await agent.close();
    }
    expect(forwarded.some((url) => url.includes("api.openai.com"))).toBe(false);
  });

  it("sends the origin only as X-DC-Target-URL from the undici layer (GAP-0242)", async () => {
    // The proxy appends the request path to X-DC-Target-URL; a path in the header too sent
    // allowed model calls to .../openai/v1/responses/openai/v1/responses.
    const { Agent, request } = createRequire(import.meta.url)("undici") as typeof import("undici");
    const seen: { path?: string; target?: string } = {};
    const proxy = createServer((req, res) => {
      seen.path = req.url;
      seen.target = String(req.headers["x-dc-target-url"]);
      res.end("{}");
    });
    await new Promise<void>((resolve) => proxy.listen(guardrailPort, "127.0.0.1", resolve));
    const agent = new Agent();
    try {
      const response = await request("https://bedrock-runtime.us-east-1.amazonaws.com/openai/v1/responses", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
        dispatcher: agent,
      });
      await response.body.text();
    } finally {
      await agent.close();
      await new Promise<void>((resolve) => proxy.close(() => resolve()));
    }
    expect(seen.path).toBe("/openai/v1/responses");
    expect(seen.target).toBe("https://bedrock-runtime.us-east-1.amazonaws.com");
  });

  it("records fetch, http, https, and undici layers on the startup banner", () => {
    const layers = interceptor.describeLayers();
    expect(layers.fetch).toBe(true);
    expect(layers.httpsRequest).toBe(true);
    expect(layers.httpRequest).toBe(true);
    expect(layers.httpGet).toBe(true);
    expect(layers.undiciDispatcher).toBe(true);
    expect(layers.hostUndiciDispatcher).toBe(true);
    const banner = vi.mocked(console.log).mock.calls.map((call) => String(call[0]));
    expect(banner.some((line) => line.includes("interceptor layers") && line.includes("undici=true"))).toBe(true);
  });

  it("prints a repeated self-test result once (GAP-1454)", async () => {
    vi.mocked(console.log).mockClear();
    await interceptor.runSelfTest();
    await interceptor.runSelfTest();
    const lines = vi.mocked(console.log).mock.calls.map((call) => String(call[0]));
    expect(lines.filter((line) => line.includes("interception self-test ok=true"))).toHaveLength(1);
  });

  it("keeps routine lines out of an interactive terminal unless verbose (GAP-1454)", () => {
    const tty = Object.getOwnPropertyDescriptor(process.stdout, "isTTY");
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    try {
      vi.stubEnv("DEFENSECLAW_DEBUG", "");
      vi.mocked(console.log).mockClear();
      logInfo("[defenseclaw] routine");
      expect(console.log).not.toHaveBeenCalled();
      vi.stubEnv("DEFENSECLAW_DEBUG", "1");
      logInfo("[defenseclaw] routine");
      expect(console.log).toHaveBeenCalledWith("[defenseclaw] routine");
    } finally {
      vi.unstubAllEnvs();
      if (tty) Object.defineProperty(process.stdout, "isTTY", tty);
      else delete (process.stdout as { isTTY?: boolean }).isTTY;
    }
  });

  it("keeps routine lines out of OpenClaw CLI commands even when piped (GAP-1737)", () => {
    expect(isOpenClawClientProcess("openclaw")).toBe(true);
    expect(isOpenClawClientProcess("openclaw-tui")).toBe(true);
    expect(isOpenClawClientProcess("openclaw-gateway")).toBe(false);
    expect(isOpenClawClientProcess("node")).toBe(false);
    const title = process.title;
    try {
      vi.stubEnv("DEFENSECLAW_DEBUG", "");
      process.title = "openclaw";
      vi.mocked(console.log).mockClear();
      logInfo("[defenseclaw] routine");
      expect(console.log).not.toHaveBeenCalled();
    } finally {
      process.title = title;
      vi.unstubAllEnvs();
    }
  });

  it("does not emit the probe header toward a real provider host", async () => {
    await interceptor.verifyInterception();
    expect(forwarded.filter((url) => url.includes("api.openai.com"))).toEqual([]);
    expect(INTERCEPTION_PROBE_HEADER).toBe("X-DC-Interception-Probe");
  });
});
