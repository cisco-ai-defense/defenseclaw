/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 * SPDX-License-Identifier: Apache-2.0
 */

import { EventEmitter } from "node:events";
import { createRequire } from "node:module";
import { Readable } from "node:stream";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createFetchInterceptor, GATEWAY_DOWN_MESSAGE, MODEL_OUTAGE_WARNING } from "../fetch-interceptor.js";
import { ListenerProofError, _setListenerProofForTest } from "../listener-proof.js";

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

/** The undici layer dispatches once the listener proof has settled (GAP-0594). */
const proofSettled = () => new Promise((resolve) => setImmediate(resolve));

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
    _setListenerProofForTest(async () => {});
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
    expect(httpCall.mock.calls[1][1]).toBeUndefined();
    expect(direct.write).toHaveBeenCalledWith(Buffer.from("request-body"));
  });

  it("preserves the Node HTTPS options-object request shape on continuation", () => {
    const proxy = requestStub();
    const direct = requestStub();
    http.request = vi.fn(() => proxy) as unknown as typeof http.request;
    const directCall = vi.fn((_target: unknown, _callback?: unknown) => direct);
    https.request = directCall as unknown as typeof https.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();

    const req = https.request({ hostname: "api.openai.com", path: "/v1/chat/completions", method: "POST" });
    req.end("request-body");
    req.emit("error", refused());
    expect(directCall).toHaveBeenCalledTimes(1);
    expect(directCall.mock.calls[0][0]).toMatchObject({ hostname: "api.openai.com", path: "/v1/chat/completions" });
    expect(directCall.mock.calls[0][1]).toBeUndefined();
    expect(direct.write).toHaveBeenCalledWith(Buffer.from("request-body"));
  });

  it("continues every Node HTTP overload with its original authorization and body", async () => {
    const seen: Array<{ authorization: string; body: string }> = [];
    const provider = http.createServer((req, res) => {
      const parts: Buffer[] = [];
      req.on("data", (part: Buffer) => parts.push(part));
      req.on("end", () => {
        seen.push({ authorization: String(req.headers.authorization ?? ""), body: Buffer.concat(parts).toString() });
        res.writeHead(200);
        res.end("ok");
      });
    });
    const proxy = http.createServer((_req, res) => res.destroy());
    const listen = (server: import("node:http").Server) => new Promise<number>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve((server.address() as import("node:net").AddressInfo).port));
    });
    const close = (server: import("node:http").Server) => new Promise<void>((resolve) => server.close(() => resolve()));
    const providerPort = await listen(provider);
    const proxyPort = await listen(proxy);
    const plainURL = `http://127.0.0.1:${providerPort}/v1/chat/completions`;
    const credentialURL = `http://fixture:password@127.0.0.1:${providerPort}/v1/chat/completions`;
    const options = () => ({
      host: "127.0.0.1", port: providerPort, path: "/v1/chat/completions",
      method: "POST", headers: { Authorization: "Bearer fixture" },
    });
    const withURL = () => ({ method: "POST", headers: { Authorization: "Bearer fixture" } });
    type ResponseCallback = (res: import("node:http").IncomingMessage) => void;
    const cases: Array<{ name: string; expected: string; send: (callback: ResponseCallback) => import("node:http").ClientRequest }> = [
      { name: "options", expected: "Bearer fixture", send: () => http.request(options()) },
      { name: "options, callback", expected: "Bearer fixture", send: (cb) => http.request(options(), cb) },
      { name: "URL string", expected: "Basic Zml4dHVyZTpwYXNzd29yZA==", send: () => http.request(credentialURL) },
      { name: "URL string, callback", expected: "Basic Zml4dHVyZTpwYXNzd29yZA==", send: (cb) => http.request(credentialURL, cb) },
      { name: "URL string, options", expected: "Bearer fixture", send: () => http.request(plainURL, withURL()) },
      { name: "URL string, options, callback", expected: "Bearer fixture", send: (cb) => http.request(plainURL, withURL(), cb) },
      { name: "URL object", expected: "Basic Zml4dHVyZTpwYXNzd29yZA==", send: () => http.request(new URL(credentialURL)) },
      { name: "URL object, callback", expected: "Basic Zml4dHVyZTpwYXNzd29yZA==", send: (cb) => http.request(new URL(credentialURL), cb) },
      { name: "URL object, options", expected: "Bearer fixture", send: () => http.request(new URL(plainURL), withURL()) },
      { name: "URL object, options, callback", expected: "Bearer fixture", send: (cb) => http.request(new URL(plainURL), withURL(), cb) },
    ];
    interceptor = createFetchInterceptor({ guardrailPort: proxyPort, getOutageMode: () => "open" });
    interceptor.start();
    try {
      for (const tc of cases) {
        for (const body of ["", "request-body"]) {
          const received = await new Promise<{ status: number; record: typeof seen[number] }>((resolve, reject) => {
            const onResponse: ResponseCallback = (res) => {
              res.resume();
              res.on("end", () => resolve({ status: res.statusCode ?? 0, record: seen.at(-1)! }));
            };
            const req = tc.send(onResponse);
            req.on("response", onResponse);
            req.on("error", reject);
            if (body) req.setHeader("Content-Length", Buffer.byteLength(body));
            req.end(body || undefined);
          });
          expect(received.status, tc.name).toBe(200);
          expect(received.record.authorization, tc.name).toBe(tc.expected);
          expect(received.record.body, tc.name).toBe(body);
        }
      }
    } finally {
      interceptor.stop();
      interceptor = undefined;
      await close(proxy);
      await close(provider);
    }
  });

  it("retries an undici model dispatch with its original destination and headers", async () => {
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
    await proofSettled();
    expect(origins).toEqual(["http://127.0.0.1:14010", "https://api.openai.com"]);
    expect(directHeaders[0]).toEqual({ Authorization: "Bearer provider-token" });
    expect(handler.onError).not.toHaveBeenCalled();
  });

  it("replays a streamed undici body after the proxy consumes it", async () => {
    const bodies: string[] = [];
    let finish!: () => void;
    const completed = new Promise<void>((resolve) => { finish = resolve; });
    const base = {
      dispatch: vi.fn((opts: { origin: string; body: AsyncIterable<Uint8Array | string> }, handler: { onError?: (err: Error) => void }) => {
        void (async () => {
          let body = "";
          for await (const chunk of opts.body) body += chunk.toString();
          bodies.push(body);
          if (String(opts.origin).startsWith("http://127.0.0.1:14010")) handler.onError?.(refused());
          else finish();
        })();
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
    const dispatcher = undici.getGlobalDispatcher() as {
      dispatch: (opts: { origin: string; path: string; body: Readable }, handler: object) => boolean;
    };
    dispatcher.dispatch({
      origin: "https://api.openai.com", path: "/v1/chat/completions",
      body: Readable.from(["request", "-body"]),
    }, { onError: vi.fn() });
    await completed;
    expect(bodies).toEqual(["request-body", "request-body"]);
  });

  it("keeps an undici request closed when the saved mode is closed", async () => {
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
    await proofSettled();
    expect(origins).toEqual(["http://127.0.0.1:14010"]);
    expect(handler.onError).toHaveBeenCalledTimes(1);
  });

  // GAP-0580 with GAP-0594: a listener proof that found nothing listening, or
  // timed out, is an outage; a listener that answered without the proof is
  // not, and gets nothing in every tier.
  const unreachable = () => new ListenerProofError("connect ECONNREFUSED 127.0.0.1:14010", true);
  const unproven = () => new ListenerProofError("the listener on 127.0.0.1:14010 did not prove it is the DefenseClaw gateway");

  function recordingDispatcher() {
    const seen: Array<{ origin: string; headers: unknown }> = [];
    undici.setGlobalDispatcher({
      dispatch: vi.fn((opts: { origin: string; headers: unknown }) => {
        seen.push({ origin: String(opts.origin), headers: opts.headers });
        return true;
      }),
      close: async () => undefined,
      destroy: async () => undefined,
    });
    return seen;
  }

  it("dispatches an undici model request to its provider when the proof finds nothing listening", async () => {
    const seen = recordingDispatcher();
    http.request = vi.fn(() => requestStub()) as unknown as typeof http.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();
    _setListenerProofForTest(async () => { throw unreachable(); });
    const handler = { onError: vi.fn() };
    (undici.getGlobalDispatcher() as { dispatch: (opts: object, sink: typeof handler) => boolean }).dispatch(
      { origin: "https://api.openai.com", path: "/v1/chat/completions", method: "POST", headers: { Authorization: "Bearer provider-token" } },
      handler,
    );
    await proofSettled();
    expect(seen).toEqual([{ origin: "https://api.openai.com", headers: { Authorization: "Bearer provider-token" } }]);
    expect(handler.onError).not.toHaveBeenCalled();
    expect(console.warn).toHaveBeenCalledWith(MODEL_OUTAGE_WARNING);
  });

  it.each([
    ["open", unproven],
    ["closed", unreachable],
  ] as const)("answers an undici request as a closed gateway outage (saved %s mode)", async (mode, failure) => {
    const seen = recordingDispatcher();
    http.request = vi.fn(() => requestStub()) as unknown as typeof http.request;
    globalThis.fetch = vi.fn(async () => { throw refused(); }) as typeof fetch;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => mode });
    interceptor.start();
    _setListenerProofForTest(async () => { throw failure(); });
    const handler = { onConnect: vi.fn(), onHeaders: vi.fn(), onData: vi.fn(), onComplete: vi.fn(), onError: vi.fn() };
    (undici.getGlobalDispatcher() as { dispatch: (opts: object, sink: typeof handler) => boolean }).dispatch(
      { origin: "https://api.openai.com", path: "/v1/chat/completions", method: "POST", headers: { Authorization: "Bearer provider-token" } },
      handler,
    );
    await proofSettled();
    expect(seen).toEqual([]);
    expect(handler.onHeaders.mock.calls[0][0]).toBe(503);
    expect(String(handler.onData.mock.calls[0][0])).toContain("defenseclaw_gateway_down");
    expect(console.warn).not.toHaveBeenCalledWith(MODEL_OUTAGE_WARNING);
  });

  it("replays a Node HTTP model request after a proven connection found nothing listening", () => {
    const proxy = requestStub();
    const direct = requestStub();
    http.request = vi.fn(() => proxy) as unknown as typeof http.request;
    const directCall = vi.fn((_url: unknown, _opts?: unknown) => direct);
    https.request = directCall as unknown as typeof https.request;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();
    const req = https.request("https://api.openai.com/v1/chat/completions", {
      method: "POST", headers: { Authorization: "Bearer provider-token" },
    });
    req.end("request-body");
    req.emit("error", unreachable());
    expect(directCall).toHaveBeenCalledTimes(1);
    expect(direct.write).toHaveBeenCalledWith(Buffer.from("request-body"));
  });

  it("keeps a Node HTTP model request failed for a listener that fails the proof in the open mode", () => {
    const proxy = requestStub();
    http.request = vi.fn(() => proxy) as unknown as typeof http.request;
    const directCall = vi.fn(() => requestStub());
    https.request = directCall as unknown as typeof https.request;
    interceptor = createFetchInterceptor({ guardrailPort: 14010, getOutageMode: () => "open" });
    interceptor.start();
    const errors: Error[] = [];
    const req = https.request("https://api.openai.com/v1/chat/completions", {
      method: "POST", headers: { Authorization: "Bearer provider-token" },
    });
    req.on("error", (err) => errors.push(err));
    req.end("request-body");
    req.emit("error", unproven());
    expect(directCall).not.toHaveBeenCalled();
    expect(errors).toHaveLength(1);
    expect(errors[0]).toBeInstanceOf(ListenerProofError);
    expect(errors[0].message).not.toBe(GATEWAY_DOWN_MESSAGE);
    expect(console.warn).not.toHaveBeenCalledWith(MODEL_OUTAGE_WARNING);
  });
});
