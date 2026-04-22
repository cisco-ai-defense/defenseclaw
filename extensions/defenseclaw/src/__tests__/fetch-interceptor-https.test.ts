/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Regression: @smithy/node-http-handler (used by @aws-sdk/client-bedrock-runtime
 * when AWS_BEDROCK_FORCE_HTTP1=1) calls `https.request(options, cb)` with an
 * options bag like { host: "bedrock-runtime.us-east-1.amazonaws.com", path,
 * port, headers } — note `host`, NOT `hostname`.
 *
 * These tests pin the interceptor's ability to match on both shapes so Bedrock
 * traffic actually reaches the guardrail proxy.
 */

import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { createRequire } from "node:module";

import { createFetchInterceptor } from "../fetch-interceptor.js";

// The interceptor mutates CJS `https.request` via createRequire; mirror that
// here so our stubs swap the same exports object.
const _require = createRequire(import.meta.url);
const https = _require("https") as typeof import("https");
const http = _require("http") as typeof import("http");

type RecordedRequest = {
  opts: Record<string, unknown>;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  cb?: any;
};

describe("https.request interception (smithy NodeHttpHandler shape)", () => {
  const guardrailPort = 14010;
  const captured: RecordedRequest[] = [];
  let originalHttpRequest: typeof http.request;
  let originalHttpsRequest: typeof https.request;
  let interceptor: ReturnType<typeof createFetchInterceptor>;

  beforeEach(() => {
    captured.length = 0;
    originalHttpRequest = http.request;
    originalHttpsRequest = https.request;
    // Swap http.request so the interceptor's proxied call lands in `captured`
    // instead of hitting the network.
    http.request = ((
      opts: Record<string, unknown>,
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      cb?: any,
    ) => {
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

  it("redirects Bedrock requests passed as { host, path, port } to the proxy", () => {
    https.request(
      {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        method: "POST",
        path: "/model/anthropic.claude-3-5-sonnet/converse-stream",
        port: 443,
        headers: { "content-type": "application/json" },
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(1);
    const opts = captured[0].opts as {
      hostname?: string;
      host?: string;
      port?: number;
      protocol?: string;
      path?: string;
      headers?: Record<string, string>;
    };
    expect(opts.hostname).toBe("127.0.0.1");
    // `host` must NOT still be the original Bedrock hostname or Node would
    // route there instead of to the proxy.
    expect(opts.host).not.toBe("bedrock-runtime.us-east-1.amazonaws.com");
    expect(opts.port).toBe(guardrailPort);
    expect(opts.protocol).toBe("http:");
    expect(opts.path).toBe(
      "/model/anthropic.claude-3-5-sonnet/converse-stream",
    );
    expect(opts.headers?.["X-DC-Target-URL"]).toBe(
      "https://bedrock-runtime.us-east-1.amazonaws.com",
    );
  });

  it("strips the caller's https.Agent so http.request does not ERR_INVALID_PROTOCOL", () => {
    // Regression: @smithy/node-http-handler passes `agent: <https.Agent>`
    // alongside the options. When we downgrade to `http://127.0.0.1:<port>`
    // we must NOT propagate that agent or Node throws:
    //   Protocol "http:" not supported. Expected "https:"
    const smithyHttpsAgent = new https.Agent({ keepAlive: true });
    https.request(
      {
        host: "bedrock-runtime.us-east-1.amazonaws.com",
        method: "POST",
        path: "/model/x/converse-stream",
        port: 443,
        headers: { "content-type": "application/json" },
        agent: smithyHttpsAgent,
        rejectUnauthorized: true,
        servername: "bedrock-runtime.us-east-1.amazonaws.com",
        ca: "pretend-bundle",
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(1);
    const opts = captured[0].opts as Record<string, unknown>;
    // `agent: false` tells Node to pick a fresh default http.Agent for the
    // proxy hop — anything else (undefined, or the original https.Agent)
    // would let Node fall back to global/https state and reject the request.
    expect(opts.agent).toBe(false);
    // TLS-only options must not leak into the plain-http request we emit to
    // the proxy; they have no meaning over http and may re-trigger protocol
    // checks in downstream Node versions.
    expect(opts).not.toHaveProperty("ca");
    expect(opts).not.toHaveProperty("servername");
    expect(opts).not.toHaveProperty("rejectUnauthorized");
  });

  it("still matches legacy { hostname, path } shape (non-Bedrock clients)", () => {
    https.request(
      {
        hostname: "api.anthropic.com",
        method: "POST",
        path: "/v1/messages",
        headers: { "x-api-key": "sk-ant-test" },
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(1);
    const opts = captured[0].opts as { hostname?: string; port?: number };
    expect(opts.hostname).toBe("127.0.0.1");
    expect(opts.port).toBe(guardrailPort);
  });

  it("stamps X-DefenseClaw-* correlation headers from getCorrelationHeaders", () => {
    // Regression for v7: intercepted LLM traffic must carry the plugin's
    // correlation envelope so the guardrail proxy can stamp agent_id,
    // session_id, run_id, trace_id, policy_id on every guardrail-* audit
    // row. Without this, SQLite rows for every intercepted LLM hop had
    // those columns NULL.
    interceptor.stop();
    interceptor = createFetchInterceptor({
      guardrailPort,
      getCorrelationHeaders: () => ({
        "X-DefenseClaw-Agent-Id": "agent-42",
        "X-DefenseClaw-Session-Id": "session-abc",
        "X-DefenseClaw-Run-Id": "run-xyz",
        "X-DefenseClaw-Trace-Id": "trace-123",
        "X-DefenseClaw-Policy-Id": "policy-strict",
      }),
    });
    interceptor.start();

    https.request(
      {
        host: "api.anthropic.com",
        method: "POST",
        path: "/v1/messages",
        headers: { "x-api-key": "sk-ant-test" },
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(1);
    const opts = captured[0].opts as { headers?: Record<string, string> };
    expect(opts.headers?.["X-DefenseClaw-Agent-Id"]).toBe("agent-42");
    expect(opts.headers?.["X-DefenseClaw-Session-Id"]).toBe("session-abc");
    expect(opts.headers?.["X-DefenseClaw-Run-Id"]).toBe("run-xyz");
    expect(opts.headers?.["X-DefenseClaw-Trace-Id"]).toBe("trace-123");
    expect(opts.headers?.["X-DefenseClaw-Policy-Id"]).toBe("policy-strict");
  });

  it("omits empty correlation header values", () => {
    // Empty/undefined fields must not appear at all — the proxy treats
    // empty strings as "header present, value empty", which can trigger
    // validation warnings on the audit row. The interceptor strips them
    // out so the sidecar sees a clean request envelope.
    interceptor.stop();
    interceptor = createFetchInterceptor({
      guardrailPort,
      getCorrelationHeaders: () => ({
        "X-DefenseClaw-Agent-Id": "agent-42",
        "X-DefenseClaw-Session-Id": "",
      }),
    });
    interceptor.start();

    https.request(
      {
        host: "api.anthropic.com",
        method: "POST",
        path: "/v1/messages",
        headers: {},
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(1);
    const opts = captured[0].opts as { headers?: Record<string, string> };
    expect(opts.headers?.["X-DefenseClaw-Agent-Id"]).toBe("agent-42");
    expect(opts.headers).not.toHaveProperty("X-DefenseClaw-Session-Id");
  });

  it("passes through non-LLM https.request calls", () => {
    let passthroughCalled = false;
    const passthrough = ((..._args: unknown[]) => {
      passthroughCalled = true;
      return {} as unknown as ReturnType<typeof https.request>;
    }) as typeof https.request;

    // Re-start so the interceptor captures our stub as `originalHttpsRequest`
    // for the passthrough path.
    interceptor.stop();
    https.request = passthrough;
    interceptor = createFetchInterceptor(guardrailPort);
    interceptor.start();

    https.request(
      {
        host: "example.com",
        path: "/",
      } as unknown as Parameters<typeof https.request>[0],
      () => undefined,
    );
    expect(captured).toHaveLength(0);
    expect(passthroughCalled).toBe(true);
  });
});
