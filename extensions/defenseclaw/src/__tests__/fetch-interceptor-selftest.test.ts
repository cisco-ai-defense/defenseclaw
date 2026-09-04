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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createFetchInterceptor,
  INTERCEPTION_PROBE_HEADER,
} from "../fetch-interceptor.js";

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
    expect(result.reason).toBe("interception-self-test");
    expect(forwarded.some((url) => url.includes("api.openai.com"))).toBe(false);
  });

  it("records fetch, http, https, and undici layers on the startup banner", () => {
    const layers = interceptor.describeLayers();
    expect(layers.fetch).toBe(true);
    expect(layers.httpsRequest).toBe(true);
    expect(layers.httpRequest).toBe(true);
    expect(layers.httpGet).toBe(true);
    const banner = vi.mocked(console.log).mock.calls.map((call) => String(call[0]));
    expect(banner.some((line) => line.includes("interceptor layers") && line.includes("fetch=true"))).toBe(true);
  });

  it("does not emit the probe header toward a real provider host", async () => {
    await interceptor.verifyInterception();
    expect(forwarded.filter((url) => url.includes("api.openai.com"))).toEqual([]);
    expect(INTERCEPTION_PROBE_HEADER).toBe("X-DC-Interception-Probe");
  });
});
