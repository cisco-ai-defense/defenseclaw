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

/**
 * An older build patches the node http layers along with fetch and puts all of
 * them back in the same stop (bound copies of what it found, as 1.0.8 does).
 */
function patchHttpLayersLikeAnOlderBuild(): () => void {
  const putBack = {
    httpsRequest: https.request.bind(https),
    httpRequest: http.request.bind(http),
    httpGet: http.get.bind(http),
  };
  https.request = ((...args: Parameters<typeof https.request>) =>
    putBack.httpsRequest(...args)) as typeof https.request;
  http.request = ((...args: Parameters<typeof http.request>) =>
    putBack.httpRequest(...args)) as typeof http.request;
  http.get = ((...args: Parameters<typeof http.get>) => putBack.httpGet(...args)) as typeof http.get;
  return () => {
    https.request = putBack.httpsRequest;
    http.request = putBack.httpRequest;
    http.get = putBack.httpGet;
  };
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
  const putHttpLayersBack = patchHttpLayersLikeAnOlderBuild();
  return {
    olderWrapper,
    stop: () => {
      globalThis.fetch = nativeFetch;
      putHttpLayersBack();
      state.installed = false;
      state.guardrailPort = null;
    },
  };
}

/**
 * One copy of an older plugin build over the shared state, with the 1.0.8
 * protocol: start() installs only when the mark is down, and stop() always
 * writes the mark down (and the port to null), whether or not this copy
 * installed anything.
 */
function olderBuildCopy(port: number) {
  const globals = globalThis as Record<symbol, unknown>;
  const state = (globals[STATE_KEY] ??= {
    llmDomains: ["api.openai.com"],
    ollamaPorts: [] as string[],
    installed: false,
    guardrailPort: null as number | null,
  }) as { installed: boolean; guardrailPort: number | null };
  let original: typeof fetch | null = null;
  let putHttpLayersBack: (() => void) | null = null;
  return {
    start: () => {
      if (state.installed) return;
      state.installed = true;
      state.guardrailPort = port;
      original = globalThis.fetch;
      globalThis.fetch = (async () => new Response(`older:${port}`)) as typeof fetch;
      putHttpLayersBack = patchHttpLayersLikeAnOlderBuild();
    },
    stop: () => {
      if (original) {
        globalThis.fetch = original;
        original = null;
        putHttpLayersBack?.();
        putHttpLayersBack = null;
      }
      state.installed = false;
      state.guardrailPort = null;
    },
    holds: () => original !== null,
  };
}

describe("module copies that share the transport, with a live copy of an older build", () => {
  const realFetch = globalThis.fetch;
  const realHttpLayers = { httpsRequest: https.request, httpRequest: http.request, httpGet: http.get };
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
    https.request = realHttpLayers.httpsRequest;
    http.request = realHttpLayers.httpRequest;
    http.get = realHttpLayers.httpGet;
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

  it("a copy of the older build that never held the transport stops first: the holder keeps it, then hands it over", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    expect(bystander.holds()).toBe(false);
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();

    bystander.stop();
    expect(fresh.describeLayers().fetch).toBe(false);
    expect(await (await globalThis.fetch("https://api.openai.com/v1/chat/completions")).text()).toBe(`older:${PORT}`);

    holder.stop();
    expect(fresh.describeLayers().fetch).toBe(true);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);

    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("the older build starts again after a hand-over and stops: a later copy gets the transport, no model call goes direct", async () => {
    const older = olderBuildCopy(PORT);
    older.start();
    const { createFetchInterceptor } = await loadCopy();
    const first = createFetchInterceptor(PORT + 1);
    first.start();
    older.stop();
    expect(first.describeLayers().fetch).toBe(true);
    first.stop();
    expect(globalThis.fetch).toBe(baseFetch);

    older.start();
    expect(older.holds()).toBe(true);
    const later = createFetchInterceptor(PORT + 2);
    later.start();
    expect(later.describeLayers().fetch).toBe(false);

    older.stop();
    expect(later.describeLayers().fetch).toBe(true);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 2}/v1/chat/completions`]);
    later.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("a second stop of an older copy after the hand-over does not release the new holder", async () => {
    const older = olderBuildCopy(PORT);
    older.start();
    const { createFetchInterceptor } = await loadCopy();
    const first = createFetchInterceptor(PORT + 1);
    first.start();
    older.stop();
    older.stop();
    const later = createFetchInterceptor(PORT + 2);
    later.start();
    expect(later.describeLayers().fetch).toBe(false);

    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);
    expect((globalThis as Record<symbol, { guardrailPort: number | null }>)[STATE_KEY].guardrailPort).toBe(PORT + 1);

    first.stop();
    expect(later.describeLayers().fetch).toBe(true);
    later.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  /** Another component wraps the global fetch with a delegating wrapper, as any instrumentation can. */
  function wrapFetchLikeAnotherComponent(): string[] {
    const wrapped: string[] = [];
    const previous = globalThis.fetch;
    globalThis.fetch = ((input: RequestInfo | URL, init?: RequestInit) => {
      wrapped.push(String(input));
      return previous(input, init);
    }) as typeof fetch;
    return wrapped;
  }

  /** The same for the node http layers: wrappers that delegate to what they found. */
  function wrapNodeHttpLayersLikeAnotherComponent(): void {
    const httpsRequest = https.request;
    const httpRequest = http.request;
    const httpGet = http.get;
    https.request = ((...args: Parameters<typeof https.request>) => httpsRequest(...args)) as typeof https.request;
    http.request = ((...args: Parameters<typeof http.request>) => httpRequest(...args)) as typeof http.request;
    http.get = ((...args: Parameters<typeof http.get>) => httpGet(...args)) as typeof http.get;
  }

  it("another component wrapped every layer, a copy that never held the transport stops first, then the holder stops: the patch is back, no model call goes direct", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    const wrapped = wrapFetchLikeAnotherComponent();
    wrapNodeHttpLayersLikeAnotherComponent();

    bystander.stop();
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(wrapped).toContain(`http://127.0.0.1:${PORT + 1}/v1/chat/completions`);

    // The stop of the holder puts the old transport back over everything above it;
    // the patch is back inside that stop, before any microtask runs.
    holder.stop();
    expect(globalThis.fetch).not.toBe(baseFetch);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);

    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("another component wrapped fetch, the holder stops first, then a copy that never held it: one guard, nothing patched twice", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    wrapFetchLikeAnotherComponent();

    holder.stop();
    const afterTakeover = globalThis.fetch;
    bystander.stop();

    expect(globalThis.fetch).toBe(afterTakeover);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("another component wraps fetch after the hand-over, then a copy that never held the transport stops: nothing is patched again, and the stop of the current copy leaves the native transport for the next copy", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();

    holder.stop();
    expect(fresh.describeLayers().fetch).toBe(true);
    wrapFetchLikeAnotherComponent();
    const wrappedFetch = globalThis.fetch;
    bystander.stop();

    expect(globalThis.fetch).toBe(wrappedFetch);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
    expect(http.request.name).not.toContain("patched");

    const later = createFetchInterceptor(PORT + 2);
    later.start();
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 2}/v1/chat/completions`]);
    later.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("another component wraps fetch and a node http layer after the hand-over, then a copy that never held the transport stops: nothing is patched again", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    holder.stop();
    const patchedHttps = https.request;
    https.request = ((...args: Parameters<typeof https.request>) =>
      patchedHttps(...args)) as typeof https.request;
    wrapFetchLikeAnotherComponent();
    const wrappedFetch = globalThis.fetch;
    const wrappedHttps = https.request;

    bystander.stop();

    expect(globalThis.fetch).toBe(wrappedFetch);
    expect(https.request).toBe(wrappedHttps);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
    expect(https.request.name).not.toContain("patched");
  });

  it("another component wraps every layer after the hand-over, then a copy that never held the transport stops: the patch is still reachable, so nothing is patched again", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    holder.stop();
    wrapFetchLikeAnotherComponent();
    wrapNodeHttpLayersLikeAnotherComponent();
    const wrappedFetch = globalThis.fetch;

    bystander.stop();

    expect(globalThis.fetch).toBe(wrappedFetch);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);

    const later = createFetchInterceptor(PORT + 2);
    later.start();
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 2}/v1/chat/completions`]);
    later.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  /** Let a pending check of the transport patch settle (it needs microtasks, not I/O). */
  function settleRecheck(): Promise<void> {
    return new Promise((resolve) => setImmediate(resolve));
  }

  /** The same wrapper as above, but it forwards after an await, as any async instrumentation does. */
  function wrapFetchAsynchronously(delay: () => Promise<void>): void {
    const previous = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      await delay();
      return previous(input, init);
    }) as typeof fetch;
  }

  it.each([
    ["one microtask", () => Promise.resolve()],
    ["three microtasks", async () => { await Promise.resolve(); await Promise.resolve(); await Promise.resolve(); }],
    ["a timer", () => new Promise<void>((resolve) => setTimeout(resolve, 5))],
  ])(
    "another component wraps every layer with a wrapper that forwards after %s, then a copy that never held the transport stops: nothing is patched again, and a later copy uses its own proxy",
    async (_name, delay) => {
      const holder = olderBuildCopy(PORT);
      holder.start();
      const bystander = olderBuildCopy(PORT + 5);
      bystander.start();
      const { createFetchInterceptor } = await loadCopy();
      const fresh = createFetchInterceptor(PORT + 1);
      fresh.start();
      holder.stop();
      wrapFetchAsynchronously(delay);
      wrapNodeHttpLayersLikeAnotherComponent();
      const wrappedFetch = globalThis.fetch;

      bystander.stop();
      await new Promise((resolve) => setTimeout(resolve, 30));

      expect(globalThis.fetch).toBe(wrappedFetch);
      fresh.stop();
      expect(globalThis.fetch).toBe(baseFetch);
      expect(http.request.name).not.toContain("patched");

      const later = createFetchInterceptor(PORT + 2);
      later.start();
      await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
      expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 2}/v1/chat/completions`]);
      later.stop();
      expect(globalThis.fetch).toBe(baseFetch);
    },
  );

  it("an older copy removed the patch under an asynchronous wrapper of another component: the patch is put back, no model call goes direct", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    wrapFetchAsynchronously(() => Promise.resolve());
    wrapNodeHttpLayersLikeAnotherComponent();

    bystander.stop();
    holder.stop(); // puts the old transport back over everything above it
    expect(globalThis.fetch).not.toBe(baseFetch);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  /** A wrapper that refuses a call whose signal is already aborted before it delegates, as many instrumentations do. */
  function wrapFetchCheckingAbortedSignal(): void {
    const previous = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (init?.signal?.aborted) throw init.signal.reason;
      return previous(input, init);
    }) as typeof fetch;
  }

  it("the first model call right after the older holder stops is guarded, with no microtask in between", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    wrapFetchLikeAnotherComponent();
    wrapNodeHttpLayersLikeAnotherComponent();

    bystander.stop();
    holder.stop();
    const call = globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    await call;
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);
    fresh.stop();
  });

  it.each([
    ["checks an already aborted signal before it delegates", () => wrapFetchCheckingAbortedSignal(), 30],
    [
      "forwards only after a timer",
      () => wrapFetchAsynchronously(() => new Promise<void>((resolve) => setTimeout(resolve, 150))),
      400,
    ],
  ])(
    "another component wraps every layer with a wrapper that %s, then a copy that never held the transport stops: the stop of the current copy leaves the native transport, and a later copy uses its own proxy",
    async (_name, wrap, waitMs) => {
      const holder = olderBuildCopy(PORT);
      holder.start();
      const bystander = olderBuildCopy(PORT + 5);
      bystander.start();
      const { createFetchInterceptor } = await loadCopy();
      const fresh = createFetchInterceptor(PORT + 1);
      fresh.start();
      holder.stop();
      wrap();
      wrapNodeHttpLayersLikeAnotherComponent();
      const wrappedFetch = globalThis.fetch;

      bystander.stop();
      await new Promise((resolve) => setTimeout(resolve, waitMs));

      expect(globalThis.fetch).toBe(wrappedFetch);
      fresh.stop();
      expect(globalThis.fetch).toBe(baseFetch);
      expect(http.request.name).not.toContain("patched");

      const later = createFetchInterceptor(PORT + 2);
      later.start();
      await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
      expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 2}/v1/chat/completions`]);
      later.stop();
      expect(globalThis.fetch).toBe(baseFetch);
    },
  );

  it("another component wraps the second patch before the check ends: model calls stay guarded once, and the stop restores the native transport", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    holder.stop();
    wrapFetchAsynchronously(() => new Promise<void>((resolve) => setTimeout(resolve, 100)));
    wrapNodeHttpLayersLikeAnotherComponent();

    bystander.stop(); // patched again at once, not yet known to be redundant
    const wrapped = wrapFetchLikeAnotherComponent();
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(wrapped).toEqual([]);

    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(wrapped).toEqual(["https://api.openai.com/v1/chat/completions"]);
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("the older holder removed the patch under a wrapper of another component: the patch stays after the check, and the stop restores the transport it found last", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    wrapFetchAsynchronously(() => Promise.resolve());
    wrapNodeHttpLayersLikeAnotherComponent();

    bystander.stop();
    holder.stop();
    await new Promise((resolve) => setTimeout(resolve, 30));

    expect(globalThis.fetch).not.toBe(baseFetch);
    await globalThis.fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: "{}" });
    expect(modelCalls(seen)).toEqual([`http://127.0.0.1:${PORT + 1}/v1/chat/completions`]);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("the current copy stops while the check of its patch is pending: nothing is patched afterwards", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    holder.stop();
    wrapFetchAsynchronously(() => Promise.resolve());
    wrapNodeHttpLayersLikeAnotherComponent();

    bystander.stop();
    fresh.stop();
    await settleRecheck();

    expect(globalThis.fetch).toBe(baseFetch);
    expect(http.request.name).not.toContain("patched");
  });

  it("another component wraps only fetch while the older holder still holds the transport: a copy that never held it stops, and the new copy does not take over early", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const bystander = olderBuildCopy(PORT + 5);
    bystander.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    wrapFetchLikeAnotherComponent();

    bystander.stop();

    expect(fresh.describeLayers().fetch).toBe(false);
    expect((globalThis as Record<symbol, { installed: boolean }>)[STATE_KEY].installed).toBe(true);
    holder.stop();
    expect(fresh.describeLayers().fetch).toBe(true);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("benign twin: a copy of the older build stops with nothing else changed, the patch is left alone", async () => {
    const holder = olderBuildCopy(PORT);
    holder.start();
    const { createFetchInterceptor } = await loadCopy();
    const fresh = createFetchInterceptor(PORT + 1);
    fresh.start();
    holder.stop();
    const patched = globalThis.fetch;
    const httpRequest = http.request;

    olderBuildCopy(PORT + 5).stop();

    expect(globalThis.fetch).toBe(patched);
    expect(http.request).toBe(httpRequest);
    fresh.stop();
    expect(globalThis.fetch).toBe(baseFetch);
  });

  it("repeated reloads: every new copy hands to the next, ending at the native transport", async () => {
    const older = olderBuildCopy(PORT);
    older.start();
    const { createFetchInterceptor } = await loadCopy();
    const copies = [1, 2, 3].map((n) => createFetchInterceptor(PORT + n));
    for (const copy of copies) copy.start();
    older.stop();
    for (const [index, copy] of copies.entries()) {
      expect(copy.describeLayers().fetch).toBe(true);
      expect(copies.filter((_, other) => other > index).every((later) => !later.describeLayers().fetch)).toBe(true);
      copy.stop();
    }
    expect(globalThis.fetch).toBe(baseFetch);
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
