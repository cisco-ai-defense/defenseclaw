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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createFetchInterceptor } from "../fetch-interceptor.js";

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
