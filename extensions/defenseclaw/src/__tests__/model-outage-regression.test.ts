/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 */

import { createRequire } from "node:module";
import { afterEach, expect, it, vi } from "vitest";
import { createFetchInterceptor } from "../fetch-interceptor.js";

const require = createRequire(import.meta.url);
const http = require("node:http") as typeof import("node:http");
const originalFetch = globalThis.fetch;
const originalHttpRequest = http.request;

const refused = () => Object.assign(new Error("gateway connect failed"), { code: "ECONNREFUSED" });

afterEach(() => {
  globalThis.fetch = originalFetch;
  http.request = originalHttpRequest;
  vi.restoreAllMocks();
});

it("continues a provider request under the saved open mode after a proxy outage", async () => {
  const destinations: string[] = [];
  globalThis.fetch = vi.fn(async (url: RequestInfo | URL) => {
    destinations.push(String(url));
    if (String(url).startsWith("http://127.0.0.1:14010")) throw refused();
    return new Response("provider answer", { status: 200 });
  }) as typeof fetch;
  http.request = vi.fn(() => ({ on: () => undefined, emit: () => true })) as unknown as typeof http.request;
  const interceptor = createFetchInterceptor({
    guardrailPort: 14010,
    getOutageMode: () => "open",
  });
  interceptor.start();
  try {
    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST", body: "model request",
    });
    expect(response.status).toBe(200);
    expect(destinations.filter((url) => url.includes("chat/completions"))).toEqual([
      "http://127.0.0.1:14010/v1/chat/completions",
      "https://api.openai.com/v1/chat/completions",
    ]);
  } finally {
    interceptor.stop();
  }
});
