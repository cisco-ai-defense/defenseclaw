/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Tests for the Layer 4 provider overlay bootstrap.
 *
 * The fetch interceptor starts with the providers.json baked into
 * the plugin bundle and then, on startup, fetches the Go sidecar's
 * merged view (built-ins + ~/.defenseclaw/custom-providers.json)
 * so a brand-new provider added after deploy time is honored
 * without rebuilding the plugin.
 *
 * What we lock in here:
 *   - A working sidecar call MUST merge new domains into LLM_DOMAINS
 *     (and therefore flip `isLLMUrl` true for those hosts).
 *   - A sidecar returning a non-200 or unreachable MUST NOT throw
 *     (best-effort, overlay is additive).
 *   - A malformed JSON body MUST NOT throw.
 *   - Duplicate entries from the overlay MUST NOT grow the domain
 *     list unbounded — deduping is the guardrail against a hostile
 *     overlay.
 */

import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import {
  applyProviderRegistry,
  bootstrapProviderOverlay,
  createFetchInterceptor,
  isLLMUrl,
} from "../fetch-interceptor.js";
import { _resetSidecarConfigCache } from "../sidecar-config.js";

function makeFetchOK(body: unknown): typeof fetch {
  return (async () => {
    return {
      ok: true,
      status: 200,
      json: async () => body,
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

function makeFetchNotOK(status: number): typeof fetch {
  return (async () => {
    return {
      ok: false,
      status,
      json: async () => ({}),
    } as unknown as Response;
  }) as unknown as typeof fetch;
}

function makeFetchThrows(): typeof fetch {
  return (async () => {
    throw new Error("sidecar unreachable");
  }) as unknown as typeof fetch;
}

describe("applyProviderRegistry", () => {
  it("adds new provider domains so isLLMUrl recognises them", () => {
    const host = "llm-" + Math.random().toString(36).slice(2) + ".internal.test";
    expect(isLLMUrl(`https://${host}/chat/completions`, 4000)).toBe(false);
    applyProviderRegistry({
      providers: [{ domains: [host] }],
    });
    expect(isLLMUrl(`https://${host}/chat/completions`, 4000)).toBe(true);
  });

  it("dedupes duplicate entries", () => {
    const host = "dedupe-" + Math.random().toString(36).slice(2) + ".test";
    applyProviderRegistry({ providers: [{ domains: [host] }] });
    applyProviderRegistry({ providers: [{ domains: [host] }] });
    // A second call with the same host MUST NOT grow the matcher
    // (we rely on deduping to keep the per-request loop cheap).
    // Probing by URL is a behavioral, not structural, test.
    expect(isLLMUrl(`https://${host}/chat/completions`, 4000)).toBe(true);
  });

  it("tolerates null/undefined fields", () => {
    expect(() =>
      applyProviderRegistry({
        providers: [{ domains: null }, {}],
        ollama_ports: null,
      }),
    ).not.toThrow();
  });

  it("normalizes mixed-case domains so lowercase traffic matches", () => {
    const host = "CaseTest-" + Math.random().toString(36).slice(2) + ".Internal.TEST";
    applyProviderRegistry({ providers: [{ domains: [host] }] });
    // isLLMUrl lower-cases the request URL; the stored entry must
    // also be lower so a hand-edited "My.Internal.LLM.COM" overlay
    // doesn't silently become a dead entry.
    expect(isLLMUrl(`https://${host.toLowerCase()}/chat/completions`, 4000)).toBe(true);
  });

  it("rejects malformed domain entries (whitespace, scheme, slash)", () => {
    // Silently drop the bad ones — never throw, so a buggy sidecar
    // can't take the interceptor out.
    expect(() =>
      applyProviderRegistry({
        providers: [
          { domains: ["evil host.com"] },
          { domains: ["https://evil.com"] },
          { domains: ["evil.com/path"] },
          { domains: [""] },
          { domains: [42 as unknown as string] },
        ],
      }),
    ).not.toThrow();
    // None of those should have become matchers.
    expect(isLLMUrl("https://evil host.com", 4000)).toBe(false);
    expect(isLLMUrl("https://evil.com/path", 4000)).toBe(false);
  });

  it("rejects invalid ollama ports silently", () => {
    expect(() =>
      applyProviderRegistry({
        ollama_ports: [0, -1, 99999, 3.14, "42" as unknown as number],
      }),
    ).not.toThrow();
  });

  it("tolerates a completely malformed registry", () => {
    expect(() =>
      applyProviderRegistry(null as unknown as { providers: never[] }),
    ).not.toThrow();
    expect(() =>
      applyProviderRegistry("nope" as unknown as { providers: never[] }),
    ).not.toThrow();
  });
});

describe("bootstrapProviderOverlay", () => {
  beforeEach(() => {
    // Nothing to reset — merges are additive, so each test uses a
    // fresh random hostname to avoid coupling across tests.
  });

  it("applies a well-formed sidecar registry", async () => {
    const host = "bootstrap-" + Math.random().toString(36).slice(2) + ".test";
    await bootstrapProviderOverlay(4000, {
      fetchImpl: makeFetchOK({
        providers: [{ domains: [host] }],
        ollama_ports: [],
      }),
    });
    expect(isLLMUrl(`https://${host}/v1/chat/completions`, 4000)).toBe(true);
  });

  it("authenticates the compatibility proxy endpoint", async () => {
    let seenInit: RequestInit | undefined;
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      seenInit = init;
      return {
        ok: true,
        status: 200,
        json: async () => ({ providers: [], ollama_ports: [] }),
      } as unknown as Response;
    }) as typeof fetch;

    await bootstrapProviderOverlay(4000, { fetchImpl, token: "sidecar-token" });

    expect(seenInit?.headers).toEqual({ "X-DC-Auth": "Bearer sidecar-token" });
  });

  it("does NOT throw when the sidecar is unreachable", async () => {
    await expect(
      bootstrapProviderOverlay(4000, { fetchImpl: makeFetchThrows() }),
    ).resolves.toBeUndefined();
  });

  it("does NOT throw when the sidecar returns a non-200", async () => {
    await expect(
      bootstrapProviderOverlay(4000, { fetchImpl: makeFetchNotOK(500) }),
    ).resolves.toBeUndefined();
  });

  it("does NOT throw when the sidecar returns an unparseable body", async () => {
    const badFetch = (async () => {
      return {
        ok: true,
        status: 200,
        json: async () => {
          throw new Error("not json");
        },
      } as unknown as Response;
    }) as unknown as typeof fetch;
    await expect(
      bootstrapProviderOverlay(4000, { fetchImpl: badFetch }),
    ).resolves.toBeUndefined();
  });
});

describe("provider overlay bootstrap across module instances", () => {
  const savedFetch = globalThis.fetch;
  const savedHome = process.env.DEFENSECLAW_HOME;
  const savedToken = process.env.DEFENSECLAW_GATEWAY_TOKEN;

  afterEach(() => {
    globalThis.fetch = savedFetch;
    if (savedHome === undefined) delete process.env.DEFENSECLAW_HOME;
    else process.env.DEFENSECLAW_HOME = savedHome;
    if (savedToken === undefined) delete process.env.DEFENSECLAW_GATEWAY_TOKEN;
    else process.env.DEFENSECLAW_GATEWAY_TOKEN = savedToken;
    _resetSidecarConfigCache();
  });

  // GAP-2223: OpenClaw evaluates the plugin more than once; the later
  // instances must not call the authenticated endpoint without a token.
  it("sends the sidecar token from every instance", async () => {
    process.env.DEFENSECLAW_HOME = mkdtempSync(join(tmpdir(), "dc-overlay-"));
    process.env.DEFENSECLAW_GATEWAY_TOKEN = "sidecar-token";
    _resetSidecarConfigCache();
    const auth: Array<string | undefined> = [];
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      if (String(input).endsWith("/v1/config/providers")) {
        auth.push((init?.headers as Record<string, string> | undefined)?.["X-DC-Auth"]);
      }
      return new Response(JSON.stringify({ providers: [], ollama_ports: [] }));
    }) as typeof fetch;

    const first = createFetchInterceptor(4000);
    const second = createFetchInterceptor(4000);
    first.start();
    second.start();
    await new Promise((r) => setTimeout(r, 0));
    second.stop();
    first.stop();

    expect(auth).toEqual(["Bearer sidecar-token", "Bearer sidecar-token"]);
  });
});
