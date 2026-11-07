/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * GAP-0745: OpenClaw replaces the plugin in a running gateway (config hot
 * reload). It stops a service through the service-level `stop` and ignores
 * what `start` returns, and it registers the new copy before it stops the old
 * one. The transport patch must survive that in every order: one wrapper, no
 * copy left running after its stop, and the new copy guarding the transport.
 */

import http from "node:http";
import https from "node:https";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFetchInterceptor } from "../fetch-interceptor.js";
import { _setListenerProofForTest } from "../listener-proof.js";

const { mockDaemonClient } = vi.hoisted(() => ({
  mockDaemonClient: {
    buildOutboundHeaders: vi.fn(async () => ({})),
    postRaw: vi.fn(),
    applyStickyFromHttpResponse: vi.fn(),
    getStickyAgentInstanceId: vi.fn(() => undefined),
    getEchoedSidecarInstanceId: vi.fn(() => undefined),
  },
}));

vi.mock("@openclaw/plugin-sdk", () => ({
  definePluginEntry: (fn: unknown) => fn,
}));

vi.mock("../client.js", () => ({
  DaemonClient: vi.fn(() => mockDaemonClient),
}));

import pluginSetup from "../index.js";

const STATE_KEY = Symbol.for("defenseclaw.interceptor.state");
const PORT = 14011;

function makeBaseFetch(): typeof fetch {
  return (async () => new Response("ok")) as typeof fetch;
}

describe("interceptor copies across a plugin reload", () => {
  const realFetch = globalThis.fetch;
  let baseFetch: typeof fetch;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    baseFetch = makeBaseFetch();
    globalThis.fetch = baseFetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    vi.restoreAllMocks();
  });

  it("a second copy does not wrap again, and its stop leaves the first copy guarding", () => {
    const first = createFetchInterceptor(PORT);
    first.start();
    const wrapped = globalThis.fetch;
    expect(wrapped).not.toBe(baseFetch);

    const second = createFetchInterceptor(PORT);
    second.start();
    expect(globalThis.fetch).toBe(wrapped);

    second.stop();
    expect(globalThis.fetch).toBe(wrapped);
    expect(first.describeLayers().fetch).toBe(true);

    first.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("new copy registered first, old copy stopped second: the new copy takes over", () => {
    const oldCopy = createFetchInterceptor(PORT);
    oldCopy.start();
    const newCopy = createFetchInterceptor(PORT);
    newCopy.start(); // register-time start while the old copy still guards

    oldCopy.stop();

    expect(newCopy.describeLayers().fetch).toBe(true);
    expect(newCopy.describeLayers().httpsRequest).toBe(true);
    expect(globalThis.fetch).not.toBe(baseFetch);

    newCopy.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("old copy stopped before the new copy starts: the new copy installs", () => {
    const oldCopy = createFetchInterceptor(PORT);
    oldCopy.start();
    oldCopy.stop();
    const newCopy = createFetchInterceptor(PORT);
    newCopy.start();
    expect(newCopy.describeLayers().fetch).toBe(true);
    newCopy.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("a stopped waiting copy is not handed the transport", () => {
    const owner = createFetchInterceptor(PORT);
    owner.start();
    const waiting = createFetchInterceptor(PORT);
    waiting.start();
    waiting.stop();

    owner.stop();

    expect(globalThis.fetch).toBe(baseFetch);
    expect(waiting.describeLayers().fetch).toBe(false);
  });

  it("shared state left by an older plugin build (no waiting queue) still works", () => {
    (globalThis as Record<symbol, unknown>)[STATE_KEY] = {
      llmDomains: [],
      ollamaPorts: [],
      installed: false,
      guardrailPort: null,
    };
    const copy = createFetchInterceptor(PORT);
    copy.start();
    expect(copy.describeLayers().fetch).toBe(true);
    copy.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });
});

describe("llm-interceptor service as OpenClaw calls it", () => {
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    globalThis.fetch = makeBaseFetch();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    vi.restoreAllMocks();
  });

  type Service = { id: string; start: () => Promise<unknown>; stop?: () => unknown };

  function register(): Service {
    const api = {
      config: {},
      pluginConfig: {},
      on: vi.fn(),
      registerService: vi.fn(),
      registerCommand: vi.fn(),
    };
    (pluginSetup as (a: unknown) => void)(api);
    return api.registerService.mock.calls[0][0] as Service;
  }

  it("registers a service-level stop that takes the patch down", async () => {
    const before = globalThis.fetch;
    const service = register();
    expect(typeof service.stop).toBe("function");
    expect(globalThis.fetch).not.toBe(before);

    await service.start();
    await service.stop?.();

    expect(globalThis.fetch).toBe(before);
  });

  it("reload: new copy registers, old copy is stopped, the new copy guards and its stop is clean", async () => {
    const before = globalThis.fetch;
    const oldService = register();
    await oldService.start();
    const patched = globalThis.fetch;

    const newService = register();
    await oldService.stop?.();
    await newService.start();

    expect(globalThis.fetch).not.toBe(before);
    expect(globalThis.fetch).not.toBe(patched);

    await newService.stop?.();
    expect(globalThis.fetch).toBe(before);
  });
});

/**
 * A copy of an older plugin build, as it sits in a running OpenClaw gateway
 * process: it installs a wrapper, marks the shared state installed without a
 * generation or a waiting queue, and its stop restores the transport and then
 * takes the mark down (the 1.0.8 order).
 */
/** A fresh module evaluation, as a plugin reload gives: its own module state over the shared global state. */
async function loadCopy() {
  vi.resetModules();
  const proof = await import("../listener-proof.js");
  proof._setListenerProofForTest(async () => {});
  const { createFetchInterceptor } = await import("../fetch-interceptor.js");
  return { createFetchInterceptor, setProof: proof._setListenerProofForTest };
}

const modelCalls = (seen: string[]) => seen.filter((url) => url.endsWith("/v1/chat/completions"));

/**
 * A copy of an older plugin build, as it sits in a running OpenClaw gateway
 * process: it installs a wrapper, marks the shared state installed without a
 * generation or a waiting queue, and its stop restores the transport and then
 * takes the mark down (the 1.0.8 order).
 */
function startOlderBuildCopy(port: number, nativeFetch: typeof fetch) {
  const state = {
    llmDomains: ["api.openai.com"],
    ollamaPorts: [] as string[],
    installed: true,
    guardrailPort: port as number | null,
  };
  (globalThis as Record<symbol, unknown>)[STATE_KEY] = state;
  const olderWrapper = (async () => new Response("older")) as typeof fetch;
  globalThis.fetch = olderWrapper;
  return {
    olderWrapper,
    stop: () => {
      globalThis.fetch = nativeFetch;
      state.installed = false;
      state.guardrailPort = null;
    },
  };
}

describe("module copies that share the transport, with a live copy of an older build", () => {
  const realFetch = globalThis.fetch;
  let seen: string[];
  let baseFetch: typeof fetch;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    seen = [];
    baseFetch = (async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return new Response("ok");
    }) as typeof fetch;
    globalThis.fetch = baseFetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    vi.restoreAllMocks();
  });

  it("the older copy stops: the new copy installs in the same call, so a model call never goes direct", async () => {
    const older = startOlderBuildCopy(PORT, baseFetch);
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    expect(fresh.describeLayers().fetch).toBe(false);
    expect(globalThis.fetch).toBe(older.olderWrapper);

    older.stop();

    expect(fresh.describeLayers().fetch).toBe(true);
    expect(globalThis.fetch).not.toBe(baseFetch);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);

    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("the older copy never stops: the new copy stays inactive and says a restart is needed", async () => {
    const older = startOlderBuildCopy(PORT, baseFetch);
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    fresh.start();

    expect(globalThis.fetch).toBe(older.olderWrapper);
    expect(fresh.describeLayers().fetch).toBe(false);
    const warnings = (console.warn as unknown as { mock: { calls: unknown[][] } }).mock.calls
      .map((call) => String(call[0]))
      .filter((line) => line.includes("older DefenseClaw plugin copy"));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("Restart the OpenClaw gateway");
    expect(warnings[0]).toContain(String(PORT));
  });

  it("a waiting copy that stops first is not handed the transport by the older copy", async () => {
    const older = startOlderBuildCopy(PORT, baseFetch);
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    fresh.stop();

    older.stop();

    expect(globalThis.fetch).toBe(baseFetch);
    expect(fresh.describeLayers().fetch).toBe(false);
  });

  it("benign twin: no older copy, the new copy installs at once and guards model calls", async () => {
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT);
    fresh.start();
    expect(fresh.describeLayers().fetch).toBe(true);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT}/v1/chat/completions`]);
    fresh.stop();
  });
});

describe("calls admitted before a stop still reach the guardrail proxy", () => {
  const realFetch = globalThis.fetch;
  const realHttpRequest = http.request;
  const realHttpsRequest = https.request;
  let seen: string[];
  let baseFetch: typeof fetch;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    seen = [];
    baseFetch = (async (input: RequestInfo | URL) => {
      seen.push(String(input));
      return new Response("ok");
    }) as typeof fetch;
    globalThis.fetch = baseFetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    http.request = realHttpRequest;
    https.request = realHttpsRequest;
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    vi.restoreAllMocks();
  });

  it("a model call whose listener proof is still pending when the service stops is proxied, not failed", async () => {
    const { createFetchInterceptor, setProof } = await loadCopy();
    let finishProof: () => void = () => undefined;
    setProof(
      () =>
        new Promise<void>((resolve) => {
          finishProof = resolve;
        }),
    );
    const interceptor = createFetchInterceptor(PORT);
    interceptor.start();
    const call = globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    await Promise.resolve();

    interceptor.stop(); // what OpenClaw calls when it replaces the plugin
    finishProof();

    await expect(call).resolves.toBeInstanceOf(Response);
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT}/v1/chat/completions`]);
  });

  it("a kept reference to the patched http and https request functions does not throw after the stop", async () => {
    const { createFetchInterceptor } = await loadCopy();
    const interceptor = createFetchInterceptor(PORT);
    interceptor.start();
    const keptHttp = http.request;
    const keptHttps = https.request;
    interceptor.stop();

    for (const kept of [keptHttp, keptHttps]) {
      const req = (kept as typeof http.request)({
        hostname: "127.0.0.1",
        port: 1,
        path: "/",
        protocol: kept === keptHttps ? "https:" : "http:",
      });
      req.on("error", () => undefined);
      req.destroy();
    }
  });
});
