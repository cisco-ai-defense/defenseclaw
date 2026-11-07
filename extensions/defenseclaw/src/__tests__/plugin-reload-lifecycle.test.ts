/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * GAP-0745: OpenClaw replaces the plugin in a running gateway (config hot
 * reload). It stops a service through the service-level `stop` and ignores
 * what `start` returns, and it registers the new copy before it stops the old
 * one. The transport is patched once per process; a reload hands the config
 * of the new copy to that patch, the stop of a replaced copy leaves it alone,
 * and the last stop takes it out. Every model call stays guarded throughout.
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

  it("a copy that was loaded and stopped again does not take the patch from the copy still running", () => {
    const running = createFetchInterceptor(PORT);
    running.start();
    const transient = createFetchInterceptor(PORT + 1);
    transient.start();
    transient.stop();

    expect(globalThis.fetch).not.toBe(baseFetch);
    expect(running.describeLayers().fetch).toBe(true);

    running.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("shared state without a controller (left by an older plugin build) but not installed still installs", () => {
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
    expect(globalThis.fetch).toBe(patched); // one wrapper, handed to the new copy

    await newService.stop?.();
    expect(globalThis.fetch).toBe(before);
  });
  it("the plugin loaded five times in one process wraps fetch once, and the last stop restores it", async () => {
    const before = globalThis.fetch;
    const services: Service[] = [];
    let wrapper: typeof fetch | undefined;
    for (let i = 0; i < 5; i++) {
      services.push(register());
      wrapper ??= globalThis.fetch;
      expect(globalThis.fetch).toBe(wrapper);
      expect(wrapper).not.toBe(before);
      await services[i].start();
      if (i > 0) await services[i - 1].stop?.();
      expect(globalThis.fetch).toBe(wrapper);
    }
    await services[4].stop?.();
    expect(globalThis.fetch).toBe(before);
  });
});


/** A fresh module evaluation, as a plugin reload gives: its own module state over the shared global state. */
async function loadCopy() {
  vi.resetModules();
  const proof = await import("../listener-proof.js");
  proof._setListenerProofForTest(async () => {});
  const { createFetchInterceptor } = await import("../fetch-interceptor.js");
  return { createFetchInterceptor, setProof: proof._setListenerProofForTest };
}

const MODEL_URL = "https://api.openai.com/v1/chat/completions";
const modelCalls = (seen: string[]) => seen.filter((url) => url.endsWith("/v1/chat/completions"));
const proxiedUrl = (port: number) => `http://127.0.0.1:${port}/v1/chat/completions`;

describe("repeated reloads keep one patch, and every model call stays guarded", () => {
  const realFetch = globalThis.fetch;
  let seen: string[];
  let headersSeen: Array<Headers>;
  let baseFetch: typeof fetch;

  beforeEach(() => {
    vi.spyOn(console, "log").mockImplementation(() => undefined);
    vi.spyOn(console, "warn").mockImplementation(() => undefined);
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    seen = [];
    headersSeen = [];
    baseFetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      seen.push(String(input));
      headersSeen.push(new Headers(init?.headers));
      return new Response("ok");
    }) as typeof fetch;
    globalThis.fetch = baseFetch;
  });

  afterEach(() => {
    vi.useRealTimers();
    globalThis.fetch = realFetch;
    delete (globalThis as Record<symbol, unknown>)[STATE_KEY];
    vi.restoreAllMocks();
  });

  async function callModel(): Promise<void> {
    seen.length = 0;
    headersSeen.length = 0;
    await globalThis.fetch(MODEL_URL, { method: "POST", body: "{}" });
  }

  for (const reloads of [1, 2, 5]) {
    it(`${reloads} reload(s), the new copy registers before the old one stops: one wrapper, calls go to the newest proxy`, async () => {
      let current = (await loadCopy()).createFetchInterceptor({
        guardrailPort: PORT,
        getCorrelationHeaders: () => ({ "X-Test-Copy": "0" }),
      });
      current.start();
      const wrapper = globalThis.fetch;
      expect(wrapper).not.toBe(baseFetch);
      await callModel();
      expect(modelCalls(seen)).toEqual([proxiedUrl(PORT)]);

      for (let i = 1; i <= reloads; i++) {
        const next = (await loadCopy()).createFetchInterceptor({
          guardrailPort: PORT + i,
          getCorrelationHeaders: () => ({ "X-Test-Copy": String(i) }),
        });
        next.start();
        current.stop(); // OpenClaw stops the replaced copy after it registered the new one
        current = next;

        expect(globalThis.fetch).toBe(wrapper);
        await callModel();
        expect(modelCalls(seen)).toEqual([proxiedUrl(PORT + i)]);
        expect(headersSeen[0].get("X-Test-Copy")).toBe(String(i));
        expect(current.describeLayers().fetch).toBe(true);
      }

      current.stop();
      expect(globalThis.fetch).toBe(baseFetch);
    });

    it(`${reloads} reload(s), the old copy stops before the new one starts: no model call goes direct`, async () => {
      let current = (await loadCopy()).createFetchInterceptor(PORT);
      current.start();

      for (let i = 1; i <= reloads; i++) {
        current.stop();
        const next = (await loadCopy()).createFetchInterceptor(PORT + i);
        next.start();
        current = next;

        expect(globalThis.fetch).not.toBe(baseFetch);
        await callModel();
        expect(modelCalls(seen)).toEqual([proxiedUrl(PORT + i)]);
      }

      current.stop();
      expect(globalThis.fetch).toBe(baseFetch);
    });
  }

  it("a replaced copy that is stopped late does not take the patch from its successor", async () => {
    const older = (await loadCopy()).createFetchInterceptor(PORT);
    older.start();
    const newer = (await loadCopy()).createFetchInterceptor(PORT + 1);
    newer.start();
    older.stop();
    older.stop(); // a second stop of the same copy changes nothing

    await callModel();
    expect(modelCalls(seen)).toEqual([proxiedUrl(PORT + 1)]);
    newer.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("the copy that was loaded last stops while an earlier copy is still running: the earlier config guards again", async () => {
    const earlier = (await loadCopy()).createFetchInterceptor(PORT);
    earlier.start();
    const later = (await loadCopy()).createFetchInterceptor(PORT + 1);
    later.start();
    later.stop();

    await callModel();
    expect(modelCalls(seen)).toEqual([proxiedUrl(PORT)]);
    earlier.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("copies loaded five times leave one self-test timer, and none after the last stop", async () => {
    vi.useFakeTimers();
    let current = (await loadCopy()).createFetchInterceptor(PORT);
    current.start();
    await vi.advanceTimersByTimeAsync(0);
    const oneCopy = vi.getTimerCount();
    expect(oneCopy).toBeGreaterThan(0);

    for (let i = 1; i <= 5; i++) {
      const next = (await loadCopy()).createFetchInterceptor(PORT + i);
      next.start();
      current.stop();
      current = next;
      await vi.advanceTimersByTimeAsync(0);
    }
    expect(vi.getTimerCount()).toBe(oneCopy);

    current.stop();
    await vi.advanceTimersByTimeAsync(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  it("a copy that adopted the patch reports on it", async () => {
    const first = (await loadCopy()).createFetchInterceptor(PORT);
    first.start();
    const second = (await loadCopy()).createFetchInterceptor(PORT + 1);
    second.start();
    first.stop();

    expect(second.describeLayers()).toMatchObject({ fetch: true, httpsRequest: true, httpRequest: true });
    const result = await second.verifyInterception();
    expect(result.destination).toBe(proxiedUrl(PORT + 1));
    second.stop();
  });

  it("an older plugin build holds the patch: the new copy leaves it alone, says a restart is needed, and its stop changes nothing", async () => {
    const olderWrapper = (async () => new Response("older")) as typeof fetch;
    (globalThis as Record<symbol, unknown>)[STATE_KEY] = {
      llmDomains: [],
      ollamaPorts: [] as string[],
      installed: true,
      guardrailPort: PORT,
    };
    globalThis.fetch = olderWrapper;
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);

    const copy = (await loadCopy()).createFetchInterceptor(PORT);
    copy.start();
    copy.start();
    expect(globalThis.fetch).toBe(olderWrapper);
    expect(warn.mock.calls.filter((c) => String(c[0]).includes("older DefenseClaw plugin copy"))).toHaveLength(1);

    copy.stop();
    expect(globalThis.fetch).toBe(olderWrapper);
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
