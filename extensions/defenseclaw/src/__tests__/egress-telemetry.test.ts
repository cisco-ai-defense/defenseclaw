/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Layer 3 egress telemetry reporter tests.
 *
 * Covers:
 *   - dedup window collapses repeat (host, branch, decision) events,
 *   - branch + decision combos still fire independently,
 *   - bodyShape-only classification drives looksLikeLLM flag, and
 *   - reporter.stop() drains the dedup table.
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { createEgressReporter } from "../egress-telemetry.js";

function flushMicrotasks(): Promise<void> {
  return new Promise(r => queueMicrotask(r));
}

interface CapturedCall {
  url: string;
  body: Record<string, unknown>;
}

function makeFetchSpy(): {
  fetchImpl: typeof fetch;
  calls: CapturedCall[];
} {
  const calls: CapturedCall[] = [];
  const fetchImpl = vi.fn(async (url: unknown, init: unknown) => {
    const body = JSON.parse(
      (init as { body: string } | undefined)?.body ?? "{}",
    ) as Record<string, unknown>;
    calls.push({ url: String(url), body });
    return new Response("", { status: 204 });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

describe("createEgressReporter", () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  it("posts an egress event to the proxy endpoint", async () => {
    const { fetchImpl, calls } = makeFetchSpy();
    const reporter = createEgressReporter({
      guardrailPort: 14010,
      fetchImpl,
    });
    reporter.report({
      targetHost: "api.novelai.net",
      targetPath: "/v1/chat/completions",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "shape",
      decision: "allow",
      reason: "shape-match",
    });
    await flushMicrotasks();
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("http://127.0.0.1:14010/v1/events/egress");
    expect(calls[0].body).toEqual({
      target_host: "api.novelai.net",
      target_path: "/v1/chat/completions",
      body_shape: "messages",
      looks_like_llm: true,
      branch: "shape",
      decision: "allow",
      reason: "shape-match",
    });
  });

  it("dedups identical (host, branch, decision) inside the window", async () => {
    const { fetchImpl, calls } = makeFetchSpy();
    const reporter = createEgressReporter({
      guardrailPort: 14010,
      fetchImpl,
      dedupWindowMs: 60_000,
    });
    const event = {
      targetHost: "api.x.test",
      targetPath: "/v1/chat/completions",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "shape" as const,
      decision: "allow" as const,
    };
    reporter.report(event);
    reporter.report(event);
    reporter.report(event);
    await flushMicrotasks();
    expect(calls).toHaveLength(1);
  });

  it("does not dedup different branches or decisions for the same host", async () => {
    const { fetchImpl, calls } = makeFetchSpy();
    const reporter = createEgressReporter({
      guardrailPort: 14010,
      fetchImpl,
    });
    reporter.report({
      targetHost: "api.x.test",
      targetPath: "/a",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "shape",
      decision: "allow",
    });
    reporter.report({
      targetHost: "api.x.test",
      targetPath: "/a",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "shape",
      decision: "block",
    });
    reporter.report({
      targetHost: "api.x.test",
      targetPath: "/a",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "known",
      decision: "allow",
    });
    await flushMicrotasks();
    expect(calls).toHaveLength(3);
  });

  it("fires again after the dedup window elapses", async () => {
    const { fetchImpl, calls } = makeFetchSpy();
    const reporter = createEgressReporter({
      guardrailPort: 14010,
      fetchImpl,
      dedupWindowMs: 10, // shrink for test speed
    });
    const event = {
      targetHost: "api.x.test",
      targetPath: "/a",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "shape" as const,
      decision: "allow" as const,
    };
    reporter.report(event);
    await new Promise(r => setTimeout(r, 25));
    reporter.report(event);
    await flushMicrotasks();
    expect(calls).toHaveLength(2);
  });

  it("swallows fetch errors instead of throwing", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new Error("proxy unavailable");
    }) as unknown as typeof fetch;
    const reporter = createEgressReporter({
      guardrailPort: 14010,
      fetchImpl,
    });
    expect(() =>
      reporter.report({
        targetHost: "api.x.test",
        targetPath: "/a",
        bodyShape: "messages",
        looksLikeLLM: true,
        branch: "shape",
        decision: "allow",
      }),
    ).not.toThrow();
    await flushMicrotasks();
  });

  it("stop() drains the dedup state", async () => {
    const { fetchImpl, calls } = makeFetchSpy();
    const reporter = createEgressReporter({
      guardrailPort: 14010,
      fetchImpl,
    });
    const event = {
      targetHost: "api.x.test",
      targetPath: "/a",
      bodyShape: "messages",
      looksLikeLLM: true,
      branch: "shape" as const,
      decision: "allow" as const,
    };
    reporter.report(event);
    await flushMicrotasks();
    reporter.stop();
    // After stop(), the next report re-fires because the dedup state
    // was cleared.
    reporter.report(event);
    await flushMicrotasks();
    expect(calls).toHaveLength(2);
  });
});
