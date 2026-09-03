/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * #742: fetch(request, init) must apply init overrides before shape
 * detection and proxy rewrite.
 * #732: peeking a Request body above 64 KiB must not deadlock the
 * cloned tee branch.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFetchInterceptor } from "../fetch-interceptor.js";

const guardrailPort = 14010;

async function readForwardedBody(body: BodyInit | null | undefined): Promise<string> {
  if (body == null) return "";
  if (typeof body === "string") return body;
  if (body instanceof Uint8Array) return new TextDecoder().decode(body);
  if (body instanceof ArrayBuffer) return new TextDecoder().decode(body);
  if (typeof ReadableStream !== "undefined" && body instanceof ReadableStream) {
    return new Response(body).text();
  }
  if (typeof (body as { text?: () => Promise<string> }).text === "function") {
    return (body as { text: () => Promise<string> }).text();
  }
  return String(body);
}

describe("fetch(request, init) interceptor semantics", () => {
  const originalFetch = globalThis.fetch;
  const calls: Array<{ input: string; init?: RequestInit }> = [];
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    calls.length = 0;
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input: String(input), init });
      return new Response("ok");
    }) as typeof fetch;
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("routes a custom-host Request when only init.body is LLM-shaped", async () => {
    const request = new Request("https://custom-provider.test/v1/inference", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event: "not-an-llm" }),
    });

    await fetch(request, {
      method: "PUT",
      body: JSON.stringify({
        messages: [{ role: "user", content: "override-llm-body" }],
      }),
    });

    const proxied = calls.find(
      (call) => call.input === `http://127.0.0.1:${guardrailPort}/v1/inference`,
    );
    expect(proxied).toBeDefined();
    expect(proxied?.init?.method).toBe("PUT");
    expect(await readForwardedBody(proxied?.init?.body)).toBe(
      JSON.stringify({
        messages: [{ role: "user", content: "override-llm-body" }],
      }),
    );
    expect(calls.map((call) => call.input)).not.toContain(
      "https://custom-provider.test/v1/inference",
    );
  });

  it("forwards override method, body, headers, signal, and Request metadata", async () => {
    const controller = new AbortController();
    const request = new Request("https://custom-provider.test/v1/inference", {
      method: "POST",
      headers: { "content-type": "application/json", "x-from-request": "1" },
      body: JSON.stringify({
        messages: [{ role: "user", content: "input-body" }],
      }),
      redirect: "follow",
      credentials: "omit",
    });

    await fetch(request, {
      method: "PUT",
      headers: { "x-from-init": "yes" },
      body: JSON.stringify({
        messages: [{ role: "user", content: "override-body" }],
      }),
      signal: controller.signal,
      redirect: "manual",
      credentials: "include",
      cache: "no-store",
      integrity: "sha256-abc",
      keepalive: true,
      mode: "cors",
      referrer: "https://app.example.test/",
      referrerPolicy: "no-referrer",
    });

    const forwarded = calls.find(
      (call) => call.input === `http://127.0.0.1:${guardrailPort}/v1/inference`,
    )?.init;
    expect(forwarded).toBeDefined();
    expect(forwarded?.method).toBe("PUT");
    expect(await readForwardedBody(forwarded?.body)).toBe(
      JSON.stringify({
        messages: [{ role: "user", content: "override-body" }],
      }),
    );
    const headers = new Headers(forwarded?.headers);
    expect(headers.get("x-from-request")).toBe("1");
    expect(headers.get("x-from-init")).toBe("yes");
    expect(headers.get("X-DC-Target-URL")).toBe("https://custom-provider.test");
    expect(forwarded?.signal).toBeDefined();
    expect(forwarded?.redirect).toBe("manual");
    expect(forwarded?.credentials).toBe("include");
    expect(forwarded?.cache).toBe("no-store");
    expect(forwarded?.integrity).toBe("sha256-abc");
    expect(forwarded?.keepalive).toBe(true);
    expect(forwarded?.mode).toBe("cors");
    expect(forwarded?.referrer).toBe("https://app.example.test/");
    expect(forwarded?.referrerPolicy).toBe("no-referrer");
  });

  it("keeps no-init Request method and body except for proxy headers", async () => {
    const payload = JSON.stringify({
      messages: [{ role: "user", content: "plain" }],
    });
    const request = new Request("https://custom-provider.test/v1/inference", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
      redirect: "error",
    });

    await fetch(request);

    const forwarded = calls.find(
      (call) => call.input === `http://127.0.0.1:${guardrailPort}/v1/inference`,
    )?.init;
    expect(forwarded?.method).toBe("POST");
    expect(forwarded?.redirect).toBe("error");
    expect(await readForwardedBody(forwarded?.body)).toBe(payload);
    expect(new Headers(forwarded?.headers).get("X-DC-Target-URL")).toBe(
      "https://custom-provider.test",
    );
  });

  it("still short-circuits already-proxied requests without rewriting", async () => {
    await fetch(`http://127.0.0.1:${guardrailPort}/v1/chat/completions`, {
      method: "POST",
      body: JSON.stringify({ messages: [] }),
    });
    const passthrough = calls.find(
      (call) =>
        call.input === `http://127.0.0.1:${guardrailPort}/v1/chat/completions`,
    );
    expect(passthrough).toBeDefined();
    expect(new Headers(passthrough?.init?.headers).get("X-DC-Target-URL")).toBeNull();
  });

  it("peeks a >64 KiB Request without hanging and forwards the full body", async () => {
    const payload = JSON.stringify({
      model: "custom",
      messages: [{ role: "user", content: "x".repeat(70_000) }],
    });
    const request = new Request("https://custom-provider.test/v1/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: payload,
    });

    await Promise.race([
      fetch(request),
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("interceptor hung")), 1000);
      }),
    ]);

    const proxied = calls.find(
      (call) => call.input === `http://127.0.0.1:${guardrailPort}/v1/chat`,
    );
    expect(proxied).toBeDefined();
    expect(await readForwardedBody(proxied?.init?.body)).toBe(payload);
  });
});
