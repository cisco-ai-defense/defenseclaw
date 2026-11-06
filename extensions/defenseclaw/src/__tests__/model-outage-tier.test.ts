/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 */

import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createFetchInterceptor, MODEL_OUTAGE_WARNING } from "../fetch-interceptor.js";

const _require = createRequire(import.meta.url);
const http = _require("node:http") as typeof import("node:http");
const https = _require("node:https") as typeof import("node:https");
const undici = _require("undici") as {
  getGlobalDispatcher: () => unknown;
  setGlobalDispatcher: (dispatcher: unknown) => void;
};

function refused(): Error & { code: string } {
  return Object.assign(new Error("gateway connect failed"), { code: "ECONNREFUSED" });
}

function requestStub() {
  const req = new EventEmitter() as import("node:http").ClientRequest;
  req.write = vi.fn(() => true) as typeof req.write;
  req.end = vi.fn(() => req) as typeof req.end;
  return req;
}

describe("saved model outage tier", () => {
  const originalFetch = globalThis.fetch;
  const originalHttpRequest = http.request;
  const originalHttpsRequest = https.request;
  const originalDispatcher = undici.getGlobalDispatcher();
  let interceptor: ReturnType<typeof createFetchInterceptor> | undefined;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
  });

  afterEach(() => {
    interceptor?.stop();
    interceptor = undefined;
    globalThis.fetch = originalFetch;
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
    undici.setGlobalDispatcher(originalDispatcher);
    vi.restoreAllMocks();
  });

  it("continues an ordinary fetch with its provider URL, body and credentials after a classified outage", async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const dispatched: string[] = [];
    undici.setGlobalDispatcher({
      dispatch: (opts: { origin: string }) => { dispatched.push(String(opts.origin)); return true; },
      close: async () => undefined,
      destroy: async () => undefined,
    });
    globalThis.fetch = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ url: String(input), init });
      if (String(input).startsWith("http://127.0.0.1:14010")) throw refused();
      (undici.getGlobalDispatcher() as { dispatch: (opts: { origin: string }, handler: object) => boolean })
        .dispatch({ origin: new URL(String(input)).origin }, {});
      return new Response(JSON.stringify({ answer: "ok" }), { status: 200 });
    }) as typeof fetch;
    http.request = vi.fn(() => requestStub()) as unknown as typeof http.request;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();

    const response = await fetch("https://api.openai.com/v1/chat/completions", {
      method: "POST", headers: { Authorization: "Bearer provider-token" }, body: "request-body",
    });
    expect(response.status).toBe(200);
    const modelCalls = calls.filter((call) => call.url.includes("chat/completions"));
    expect(modelCalls.map((call) => call.url)).toEqual([
      "http://127.0.0.1:14010/v1/chat/completions",
      "https://api.openai.com/v1/chat/completions",
    ]);
    expect(modelCalls[1].init?.body).toBe("request-body");
    expect(new Headers(modelCalls[1].init?.headers).get("Authorization")).toBe("Bearer provider-token");
    expect(new Headers(modelCalls[1].init?.headers).get("X-DC-Target-URL")).toBeNull();
    expect(dispatched).toEqual(["https://api.openai.com"]);
    expect(console.warn).toHaveBeenCalledWith(MODEL_OUTAGE_WARNING);
  });

  it.each(["closed", "protected"] as const)("keeps the %s saved tier closed on a fetch outage", async (mode) => {
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    http.request = vi.fn(() => requestStub()) as unknown as typeof http.request;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => mode });
    interceptor.start();
    const response = await fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "request-body" });
    expect(response.status).toBe(503);
    expect(console.warn).not.toHaveBeenCalledWith(MODEL_OUTAGE_WARNING);
  });

  it("replays a Node HTTP model request to the configured provider after a classified outage", () => {
    const proxy = requestStub();
    const direct = requestStub();
    proxy.getHeaders = vi.fn(() => ({
      authorization: "Bearer provider-token",
      host: "127.0.0.1:14010",
      "x-dc-target-url": "https://api.openai.com",
      "x-ai-auth": "Bearer provider-token",
    }));
    http.request = vi.fn((_opts, callback?: (response: unknown) => void) => {
      if (callback) proxy.on("response", callback);
      return proxy;
    }) as unknown as typeof http.request;
    const directCall = vi.fn((_url: string | URL | Record<string, unknown>, _opts?: unknown) => direct);
    https.request = directCall as unknown as typeof https.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();

    const response = vi.fn();
    const req = https.request("https://api.openai.com/v1/chat/completions", {
      method: "POST", headers: { Authorization: "Bearer provider-token" },
    }, response);
    req.write("request-body");
    req.end();
    req.emit("error", refused());
    expect(directCall).toHaveBeenCalledTimes(1);
    expect(directCall.mock.calls[0][0]).toBe("https://api.openai.com/v1/chat/completions");
    expect((directCall.mock.calls[0][1] as { headers: Record<string, unknown> }).headers)
      .toEqual({ authorization: "Bearer provider-token" });
    expect(direct.write).toHaveBeenCalledWith(Buffer.from("request-body"));
    expect(direct.end).toHaveBeenCalledTimes(1);
    direct.emit("response", { statusCode: 200 });
    expect(response).toHaveBeenCalledWith({ statusCode: 200 });
  });

  it("keeps a plain HTTP provider on HTTP during outage continuation", () => {
    const proxy = requestStub();
    const direct = requestStub();
    const requests = [proxy, direct];
    const httpCall = vi.fn((_target: unknown, _callback?: unknown) => requests.shift() ?? requestStub());
    http.request = httpCall as unknown as typeof http.request;
    https.request = vi.fn(() => requestStub()) as unknown as typeof https.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();

    const req = http.request({ host: "127.0.0.1", port: 11434, path: "/api/chat", method: "POST" });
    req.write("request-body");
    req.end();
    req.emit("error", refused());
    expect(httpCall).toHaveBeenCalledTimes(2);
    expect(httpCall.mock.calls[1][0]).toMatchObject({ protocol: "http:", port: 11434 });
    expect(direct.write).toHaveBeenCalledWith(Buffer.from("request-body"));
  });

  it("retries an undici model dispatch with its original destination and headers", () => {
    const origins: string[] = [];
    const directHeaders: unknown[] = [];
    const base = {
      dispatch: vi.fn((opts: { origin: string; headers: unknown }, handler: { onError?: (err: Error) => void }) => {
        origins.push(String(opts.origin));
        if (String(opts.origin).startsWith("http://127.0.0.1:14010")) handler.onError?.(refused());
        else directHeaders.push(opts.headers);
        return true;
      }),
      close: async () => undefined,
      destroy: async () => undefined,
    };
    undici.setGlobalDispatcher(base);
    http.request = vi.fn(() => requestStub()) as unknown as typeof http.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();

    const handler = { onError: vi.fn() };
    const opts = { origin: "https://api.openai.com", path: "/v1/chat/completions", method: "POST", headers: { Authorization: "Bearer provider-token" } };
    const dispatcher = undici.getGlobalDispatcher() as { dispatch: (options: typeof opts, sink: typeof handler) => boolean };
    dispatcher.dispatch(opts, handler);
    expect(origins).toEqual(["http://127.0.0.1:14010", "https://api.openai.com"]);
    expect(directHeaders[0]).toEqual({ Authorization: "Bearer provider-token" });
    expect(handler.onError).not.toHaveBeenCalled();
  });

  it("keeps an undici request closed when the saved mode is closed", () => {
    const origins: string[] = [];
    const base = {
      dispatch: vi.fn((opts: { origin: string }, handler: { onError?: (err: Error) => void }) => {
        origins.push(String(opts.origin));
        handler.onError?.(refused());
        return true;
      }),
      close: async () => undefined,
      destroy: async () => undefined,
    };
    undici.setGlobalDispatcher(base);
    http.request = vi.fn(() => requestStub()) as unknown as typeof http.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "closed" });
    interceptor.start();
    const handler = { onError: vi.fn() };
    (undici.getGlobalDispatcher() as { dispatch: (opts: { origin: string; path: string }, sink: typeof handler) => boolean })
      .dispatch({ origin: "https://api.openai.com", path: "/v1/chat/completions" }, handler);
    expect(origins).toEqual(["http://127.0.0.1:14010"]);
    expect(handler.onError).toHaveBeenCalledTimes(1);
  });
});
