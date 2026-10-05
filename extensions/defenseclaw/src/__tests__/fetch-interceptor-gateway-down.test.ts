/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * GAP-2428: with the DefenseClaw gateway down, a proxied model call is
 * refused (fail-closed). The agent must be told why, not only "connection
 * refused by the provider endpoint".
 */

import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFetchInterceptor, GATEWAY_DOWN_MESSAGE } from "../fetch-interceptor.js";

const _require = createRequire(import.meta.url);
const https = _require("https") as typeof import("https");
const http = _require("http") as typeof import("http");

function refused(): Error & { code: string } {
  return Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:14010"), { code: "ECONNREFUSED" });
}

describe("gateway down: refused proxy hop", () => {
  const originalFetch = globalThis.fetch;
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    globalThis.fetch = (async () => {
      throw new TypeError("fetch failed", { cause: refused() });
    }) as typeof fetch;
    http.request = (() =>
      Object.assign(new EventEmitter(), { end: () => undefined, write: () => true })) as unknown as typeof http.request;
    interceptor = createFetchInterceptor(14010);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    globalThis.fetch = originalFetch;
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
    vi.restoreAllMocks();
  });

  it("answers a refused fetch with a provider-shaped error naming the gateway", async () => {
    const res = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
    });
    expect(res.status).toBe(503);
    expect(res.headers.get("x-should-retry")).toBe("false");
    expect((await res.json()).error.message).toBe(GATEWAY_DOWN_MESSAGE);
  });

  it("names the gateway in a refused https.request error and keeps its code", () => {
    const req = https.request({
      host: "bedrock-runtime.us-east-1.amazonaws.com",
      method: "POST",
      path: "/model/m/converse-stream",
      port: 443,
    });
    let seen: (Error & { code?: string }) | undefined;
    req.on("error", (err) => {
      seen = err;
    });
    req.emit("error", refused());
    expect(seen?.message).toBe(GATEWAY_DOWN_MESSAGE);
    expect(seen?.code).toBe("ECONNREFUSED");
    expect(GATEWAY_DOWN_MESSAGE).toContain("defenseclaw-gateway start");
  });
});
