/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * hardening regressions for fetch-interceptor.ts.
 *
 * Locks in:
 *   1. isAlreadyProxied parses the URL and only matches loopback host
 *      + the exact guardrail port (no substring bypass).
 *   2. matchesLLMDomain accepts the wildcard entry
 *      "bedrock-runtime.*.amazonaws.com" for real regional Bedrock
 *      hosts and refuses spoofs like "bedrock-runtime.evil.example".
 *      The legacy trailing-dot prefix syntax is NOT honoured (*      finding "Provider allowlist can be spoofed to forward to
 *      internal hosts").
 *   3. URL scrubbing strips secret-bearing query parameters before any
 *      console.log / egress telemetry hop.
 *   4. http.request and http.get are patched so a Node client talking to
 *      Ollama (HTTP) is intercepted, not silently bypassed.
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { createRequire } from "node:module";

import {
  createFetchInterceptor,
  isLLMUrl,
  hasLLMPathSuffix,
  shouldPassthroughChatGPTCodexResponseBackendUrl,
  scrubUrlForLog,
  LLM_PATH_SUFFIXES,
  UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV,
} from "../fetch-interceptor.js";

const _require = createRequire(import.meta.url);
const https = _require("https") as typeof import("https");
const http = _require("http") as typeof import("http");

type RecordedRequest = {
  opts: Record<string, unknown>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cb?: any;
};

describe("isLLMUrl + Bedrock wildcard", () => {
  const guardrailPort = 14010;

  it("matches a real Bedrock regional hostname via the one-label wildcard", () => {
    expect(
      isLLMUrl(
        "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3/invoke",
        guardrailPort,
      ),
    ).toBe(true);
    expect(
      isLLMUrl(
        "https://bedrock-runtime.eu-west-1.amazonaws.com/model/x/invoke-with-response-stream",
        guardrailPort,
      ),
    ).toBe(true);
  });

  it("refuses prefix-only spoofs that the legacy trailing-dot syntax accepted", () => {
    // finding "Provider allowlist can be spoofed to forward
    // to internal hosts": the legacy "bedrock-runtime." trailing-dot
    // entry happily matched any host that simply started with the
    // string. The new "bedrock-runtime.*.amazonaws.com" wildcard
    // entry rejects every spoof below.
    expect(isLLMUrl("https://bedrock-runtime/some/path", guardrailPort)).toBe(false);
    expect(isLLMUrl("https://bedrock-runtime.evil.example/api", guardrailPort)).toBe(false);
    expect(
      isLLMUrl(
        "https://bedrock-runtime.attacker.amazonaws.com.evil.com/api",
        guardrailPort,
      ),
    ).toBe(false);
    expect(isLLMUrl("https://evil-bedrock-runtime.example/api", guardrailPort)).toBe(false);
    // Multi-label middle is NOT one DNS label.
    expect(
      isLLMUrl(
        "https://bedrock-runtime.foo.bar.amazonaws.com/api",
        guardrailPort,
      ),
    ).toBe(false);
  });

  it("includes Bedrock InvokeModel paths in the path-suffix shape detector", () => {
    expect(LLM_PATH_SUFFIXES).toContain("/invoke");
    expect(LLM_PATH_SUFFIXES).toContain("/invoke-with-response-stream");
    expect(hasLLMPathSuffix(
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/anthropic.claude-3/invoke",
    )).toBe(true);
  });
});

describe("ChatGPT Codex OAuth backend passthrough", () => {
  const guardrailPort = 14010;
  let originalUnguardedEnv: string | undefined;

  beforeEach(() => {
    originalUnguardedEnv =
      process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV];
    delete process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV];
  });

  afterEach(() => {
    if (originalUnguardedEnv === undefined) {
      delete process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV];
    } else {
      process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV] =
        originalUnguardedEnv;
    }
    vi.restoreAllMocks();
  });

  it("does not treat ChatGPT Codex responses as passthrough by default", () => {
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://chatgpt.com/backend-api/codex/responses",
      ),
    ).toBe(false);
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://chatgpt.com/backend-api/codex/responses/stream",
      ),
    ).toBe(false);
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://chatgpt.com/backend-api/accounts",
      ),
    ).toBe(false);
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://evil.chatgpt.com/backend-api/codex/responses",
      ),
    ).toBe(false);
  });

  it("allows ChatGPT Codex response passthrough only with explicit opt-in", () => {
    process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV] = "1";

    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://chatgpt.com/backend-api/codex/responses",
      ),
    ).toBe(true);
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://chatgpt.com/backend-api/codex/responses/stream",
      ),
    ).toBe(true);
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://chatgpt.com/backend-api/accounts",
      ),
    ).toBe(false);
    expect(
      shouldPassthroughChatGPTCodexResponseBackendUrl(
        "https://evil.chatgpt.com/backend-api/codex/responses",
      ),
    ).toBe(false);
  });

  it("proxies fetch calls to ChatGPT Codex responses by default", async () => {
    const originalFetch = globalThis.fetch;
    const calls: Array<{ input: string; init?: RequestInit }> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push({ input: String(input), init });
      return new Response("ok");
    }) as typeof fetch;
    const interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();

    try {
      await fetch("https://chatgpt.com/backend-api/codex/responses", {
        method: "POST",
        body: JSON.stringify({ model: "openai/gpt-5.5", input: "ping" }),
      });
    } finally {
      interceptor.stop();
      globalThis.fetch = originalFetch;
    }

    const proxiedCall = calls.find(
      (call) =>
        call.input ===
        `http://127.0.0.1:${guardrailPort}/backend-api/codex/responses`,
    );
    expect(proxiedCall).toBeDefined();
    expect(new Headers(proxiedCall?.init?.headers).get("X-DC-Target-URL")).toBe(
      "https://chatgpt.com",
    );
    expect(calls.map((call) => call.input)).not.toContain(
      "https://chatgpt.com/backend-api/codex/responses",
    );
  });

  it("passes through fetch calls only with explicit unguarded opt-in", async () => {
    process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV] = "1";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const originalFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      calls.push(String(input));
      return new Response("ok");
    }) as typeof fetch;
    const interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();

    try {
      await fetch("https://chatgpt.com/backend-api/codex/responses", {
        method: "POST",
        body: JSON.stringify({ model: "openai/gpt-5.5", input: "ping" }),
      });
    } finally {
      interceptor.stop();
      globalThis.fetch = originalFetch;
    }

    expect(calls).toContain("https://chatgpt.com/backend-api/codex/responses");
    expect(calls).not.toContain(
      `http://127.0.0.1:${guardrailPort}/backend-api/codex/responses`,
    );
    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining(
        UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV,
      ),
    );
  });

  it("warns again after the interceptor is restarted", async () => {
    process.env[UNGUARDED_CHATGPT_CODEX_RESPONSES_ENV] = "1";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response("ok")) as typeof fetch;
    const interceptor = createFetchInterceptor(guardrailPort);

    try {
      interceptor.start();
      await fetch("https://chatgpt.com/backend-api/codex/responses", {
        method: "POST",
        body: JSON.stringify({ model: "openai/gpt-5.5", input: "ping" }),
      });
      interceptor.stop();

      interceptor.start();
      await fetch("https://chatgpt.com/backend-api/codex/responses", {
        method: "POST",
        body: JSON.stringify({ model: "openai/gpt-5.5", input: "pong" }),
      });
    } finally {
      interceptor.stop();
      globalThis.fetch = originalFetch;
    }

    expect(warn).toHaveBeenCalledTimes(2);
  });
});

describe("isAlreadyProxied: no substring bypass", () => {
  const guardrailPort = 14010;
  const captured: RecordedRequest[] = [];
  let originalHttpRequest: typeof http.request;
  let originalHttpsRequest: typeof https.request;
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    captured.length = 0;
    originalHttpRequest = http.request;
    originalHttpsRequest = https.request;
    http.request = ((opts: Record<string, unknown>, cb?: unknown) => {
      captured.push({ opts, cb });
      return {
        on: () => undefined,
        end: () => undefined,
        write: () => undefined,
        destroy: () => undefined,
      } as unknown as ReturnType<typeof http.request>;
    }) as typeof http.request;
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
  });

  it("still intercepts a Bedrock URL whose query param contains '127.0.0.1:<guardrailPort>'", () => {
    // finding "Substring self-proxy check lets LLM requests
    // bypass interception": the URL below contains the literal
    // "127.0.0.1:14010" inside its query string, but the request
    // really targets bedrock-runtime.us-east-1.amazonaws.com. The old
    // substring check would have early-returned and skipped
    // interception entirely.
    https.request(
      {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        method: "POST",
        path: "/model/anthropic.claude-3/invoke?cb=http://127.0.0.1:14010",
        port: 443,
        headers: {},
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(1);
    const opts = captured[0].opts as { hostname?: string; port?: number };
    expect(opts.hostname).toBe("127.0.0.1");
    expect(opts.port).toBe(guardrailPort);
  });
});

describe("URL scrubbing in console.log", () => {
  const guardrailPort = 14010;
  const captured: RecordedRequest[] = [];
  const logs: string[] = [];
  let originalHttpRequest: typeof http.request;
  let originalHttpsRequest: typeof https.request;
  let interceptor: ReturnType<typeof createFetchInterceptor>;
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    captured.length = 0;
    logs.length = 0;
    originalHttpRequest = http.request;
    originalHttpsRequest = https.request;
    http.request = ((opts: Record<string, unknown>, cb?: unknown) => {
      captured.push({ opts, cb });
      return {
        on: () => undefined,
        end: () => undefined,
        write: () => undefined,
        destroy: () => undefined,
      } as unknown as ReturnType<typeof http.request>;
    }) as typeof http.request;
    logSpy = vi.spyOn(console, "log").mockImplementation((msg: string) => {
      logs.push(String(msg));
    });
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();
  });

  afterEach(() => {
    interceptor.stop();
    http.request = originalHttpRequest;
    https.request = originalHttpsRequest;
    logSpy.mockRestore();
  });

  it("redacts ?key=<secret> in Gemini-style URLs before logging", () => {
    https.request(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=AIzaSyVERYSECRET",
      { method: "POST" } as unknown as Parameters<typeof https.request>[1],
      () => undefined,
    );
    const interceptLog = logs.find((l) => l.includes("intercepted LLM call (https.request)"));
    expect(interceptLog).toBeDefined();
    expect(interceptLog).not.toContain("AIzaSyVERYSECRET");
    expect(interceptLog).toContain("key=%3Credacted%3E");
  });

  it("redacts X-Amz-Signature in pre-signed URLs before logging", () => {
    https.request(
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke?X-Amz-Signature=DEADBEEFCAFE",
      { method: "POST" } as unknown as Parameters<typeof https.request>[1],
      () => undefined,
    );
    const interceptLog = logs.find((l) => l.includes("intercepted LLM call (https.request)"));
    expect(interceptLog).toBeDefined();
    expect(interceptLog).not.toContain("DEADBEEFCAFE");
  });
});

describe("http.request and http.get are patched", () => {
  const guardrailPort = 14010;
  const captured: RecordedRequest[] = [];
  let originalHttpRequest: typeof http.request;
  let originalHttpGet: typeof http.get;
  let originalHttpsRequest: typeof https.request;
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    captured.length = 0;
    originalHttpRequest = http.request;
    originalHttpGet = http.get;
    originalHttpsRequest = https.request;
    // Stub the *original* http.request bound copy with a sink so the
    // interceptor's proxy hop lands in `captured`. The patched
    // http.request will see the loopback target and fall through to
    // this sink.
    const sink: typeof http.request = ((
      opts: Record<string, unknown>,
      cb?: unknown,
    ) => {
      captured.push({ opts, cb });
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

  it("intercepts a plain http.request to Ollama and forwards through the proxy", () => {
    // Ollama runs on HTTP at 127.0.0.1:11434 by default. Pre-fix the
    // interceptor only patched https.request, so a Node client using
    // http.request bypassed the guardrail entirely. The patch adds an
    // http.request wrapper that catches Ollama traffic at the loopback
    // host + Ollama port.
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

  it("intercepts http.get for an LLM-shaped path", () => {
    // Some clients call http.get for streaming endpoints; the
    // interceptor must reroute those too.
    http.get(
      {
        hostname: "127.0.0.1",
        port: 11434,
        path: "/api/generate",
      } as unknown as Parameters<typeof http.get>[0],
      () => undefined,
    );
    expect(captured.length).toBeGreaterThanOrEqual(1);
    const opts = captured[0].opts as { hostname?: string; port?: number };
    expect(opts.hostname).toBe("127.0.0.1");
    expect(opts.port).toBe(guardrailPort);
  });

  it("does not intercept Ollama model discovery", () => {
    // OpenClaw probes /api/tags to discover local Ollama models. That
    // request is metadata discovery, not generation, and proxying it through
    // the guardrail path breaks full-live E2E when Ollama is not installed.
    http.get(
      {
        hostname: "127.0.0.1",
        port: 11434,
        path: "/api/tags",
      } as unknown as Parameters<typeof http.get>[0],
      () => undefined,
    );
    expect(captured.length).toBeGreaterThanOrEqual(1);
    const opts = captured[0].opts as { hostname?: string; port?: number; path?: string };
    expect(opts.hostname).toBe("127.0.0.1");
    expect(opts.port).toBe(11434);
    expect(opts.path).toBe("/api/tags");
  });
});

describe("scrubUrlForLog", () => {
  // scrubUrlForLog and the egress telemetry path (extractHostPath) share the
  // same redactor, so these cases pin the redaction applied before BOTH the
  // console.log hop and the /v1/events/egress telemetry hop.
  it("redacts secret query-parameter values but keeps host and path", () => {
    const out = scrubUrlForLog(
      "https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key=AIzaSyVERYSECRET",
    );
    expect(out).not.toContain("AIzaSyVERYSECRET");
    expect(out).toContain("key=%3Credacted%3E");
    expect(out).toContain("generativelanguage.googleapis.com");
    expect(out).toContain("gemini-pro:generateContent");
  });

  it("redacts every query value, not just known secret names", () => {
    const out = scrubUrlForLog(
      "https://bedrock-runtime.us-east-1.amazonaws.com/model/x/invoke?X-Amz-Signature=DEADBEEF&X-Amz-Credential=AKIA123",
    );
    expect(out).not.toContain("DEADBEEF");
    expect(out).not.toContain("AKIA123");
    expect(out).toContain("/model/x/invoke");
  });

  it("strips user:pass@ userinfo credentials", () => {
    const out = scrubUrlForLog("https://alice:s3cr3t@api.example.test/v1/chat/completions");
    expect(out).not.toContain("s3cr3t");
    expect(out).not.toContain("alice");
    expect(out).toContain("api.example.test");
  });

  it("returns URLs without a query string unchanged", () => {
    const url = "https://api.openai.com/v1/chat/completions";
    expect(scrubUrlForLog(url)).toBe(url);
  });

  it("falls back to the original string when the URL cannot be parsed", () => {
    expect(scrubUrlForLog("/api/generate?key=abc")).toBe("/api/generate?key=abc");
  });
});
