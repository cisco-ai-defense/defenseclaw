/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Layer 1 shape-detection unit tests.
 *
 * The providers.json hostname allowlist is the first rail. These tests pin
 * the second rail — request shape — so that an LLM call to a host we have
 * never seen still ends up routed through the guardrail proxy instead of
 * leaking out as plain egress.
 */

import { describe, it, expect } from "vitest";

import {
  classifyBodyShape,
  hasLLMPathSuffix,
  isKnownSafeDomain,
  isLLMShapedRequest,
  peekBodyForShape,
  resolveEffectiveFetchInit,
} from "../fetch-interceptor.js";

describe("classifyBodyShape", () => {
  it("classifies OpenAI-style messages[]", () => {
    expect(classifyBodyShape({ messages: [{ role: "user", content: "hi" }] })).toBe(
      "messages",
    );
  });

  it("classifies Gemini-style contents[]", () => {
    expect(
      classifyBodyShape({ contents: [{ parts: [{ text: "hi" }] }] }),
    ).toBe("contents");
  });

  it("classifies Responses-style input string", () => {
    expect(classifyBodyShape({ input: "hello" })).toBe("input");
  });

  it("classifies Responses-style input array", () => {
    expect(classifyBodyShape({ input: [{ role: "user" }] })).toBe("input");
  });

  it("classifies Hugging Face-style inputs array", () => {
    expect(classifyBodyShape({ inputs: ["hello"] })).toBe("input");
  });

  it("classifies legacy prompt string", () => {
    expect(classifyBodyShape({ prompt: "hi" })).toBe("prompt");
  });

  it("returns none for non-LLM JSON", () => {
    expect(classifyBodyShape({ foo: "bar", count: 3 })).toBe("none");
  });

  it("returns none for null / primitive / array roots", () => {
    expect(classifyBodyShape(null)).toBe("none");
    expect(classifyBodyShape(42)).toBe("none");
    expect(classifyBodyShape([1, 2])).toBe("none");
  });
});

describe("hasLLMPathSuffix", () => {
  it("matches OpenAI Chat Completions", () => {
    expect(hasLLMPathSuffix("https://api.foo.test/v1/chat/completions")).toBe(true);
  });

  it("matches Anthropic /messages", () => {
    expect(hasLLMPathSuffix("https://api.foo.test/v1/messages")).toBe(true);
  });

  it("matches Gemini :generateContent", () => {
    expect(
      hasLLMPathSuffix(
        "https://api.foo.test/v1beta/models/gemini-pro:generateContent",
      ),
    ).toBe(true);
  });

  it("matches Bedrock Converse", () => {
    expect(
      hasLLMPathSuffix(
        "https://runtime.foo.test/model/anthropic.claude/converse",
      ),
    ).toBe(true);
  });

  it("matches Ollama /api/chat", () => {
    expect(hasLLMPathSuffix("http://ollama.internal:11434/api/chat")).toBe(true);
  });

  it("does not match package registries / non-LLM paths", () => {
    expect(hasLLMPathSuffix("https://registry.npmjs.org/some-pkg")).toBe(false);
    expect(hasLLMPathSuffix("https://github.com/foo/bar")).toBe(false);
    expect(hasLLMPathSuffix("https://api.foo.test/v1/users")).toBe(false);
  });
});

describe("isKnownSafeDomain", () => {
  it("allowlists npm / pypi / github / telemetry exact matches", () => {
    expect(isKnownSafeDomain("https://registry.npmjs.org/foo")).toBe(true);
    expect(isKnownSafeDomain("https://pypi.org/simple/foo")).toBe(true);
    expect(isKnownSafeDomain("https://github.com/foo")).toBe(true);
    expect(isKnownSafeDomain("https://sentry.io/api")).toBe(true);
  });

  it("allowlists subdomains of safe roots", () => {
    expect(isKnownSafeDomain("https://files.pythonhosted.org/packages/x")).toBe(
      true,
    );
    expect(isKnownSafeDomain("https://raw.githubusercontent.com/x")).toBe(true);
  });

  it("does not confuse lookalike hosts", () => {
    expect(isKnownSafeDomain("https://npmjs.org.attacker.test/")).toBe(false);
    expect(isKnownSafeDomain("https://fakegithub.com/")).toBe(false);
  });

  it("returns false on unparseable URLs", () => {
    expect(isKnownSafeDomain("not a url")).toBe(false);
    expect(isKnownSafeDomain("")).toBe(false);
  });
});

describe("isLLMShapedRequest", () => {
  const guardrailPort = 14010;

  it("flags LLM-shaped calls to unknown hosts", () => {
    expect(
      isLLMShapedRequest(
        "https://unknown.example.test/v1/chat/completions",
        "POST",
        "messages",
        guardrailPort,
      ),
    ).toBe(true);
  });

  it("flags shape-only match (LLM body, non-LLM-looking path)", () => {
    expect(
      isLLMShapedRequest(
        "https://unknown.example.test/v1/inference",
        "POST",
        "messages",
        guardrailPort,
      ),
    ).toBe(true);
  });

  it("flags path-only match (LLM path, body could not be peeked)", () => {
    expect(
      isLLMShapedRequest(
        "https://unknown.example.test/v1/messages",
        "POST",
        "none",
        guardrailPort,
      ),
    ).toBe(true);
  });

  it("ignores GET / HEAD / OPTIONS regardless of path", () => {
    expect(
      isLLMShapedRequest(
        "https://unknown.example.test/v1/chat/completions",
        "GET",
        "none",
        guardrailPort,
      ),
    ).toBe(false);
    expect(
      isLLMShapedRequest(
        "https://unknown.example.test/v1/messages",
        "HEAD",
        "none",
        guardrailPort,
      ),
    ).toBe(false);
  });

  it("ignores known-safe domains even with LLM paths", () => {
    expect(
      isLLMShapedRequest(
        "https://github.com/v1/messages",
        "POST",
        "messages",
        guardrailPort,
      ),
    ).toBe(false);
    expect(
      isLLMShapedRequest(
        "https://registry.npmjs.org/v1/chat/completions",
        "POST",
        "messages",
        guardrailPort,
      ),
    ).toBe(false);
  });

  it("ignores the guardrail self-address to avoid loops", () => {
    expect(
      isLLMShapedRequest(
        `http://127.0.0.1:${guardrailPort}/v1/messages`,
        "POST",
        "messages",
        guardrailPort,
      ),
    ).toBe(false);
    expect(
      isLLMShapedRequest(
        `http://localhost:${guardrailPort}/v1/chat/completions`,
        "POST",
        "messages",
        guardrailPort,
      ),
    ).toBe(false);
  });

  it("returns false when nothing matches", () => {
    expect(
      isLLMShapedRequest(
        "https://unknown.example.test/v1/users",
        "POST",
        "none",
        guardrailPort,
      ),
    ).toBe(false);
  });
});

describe("peekBodyForShape", () => {
  it("peeks a string JSON body", async () => {
    const body = JSON.stringify({ messages: [{ role: "user", content: "hi" }] });
    const shape = await peekBodyForShape("https://x.test/foo", {
      method: "POST",
      body,
    });
    expect(shape).toBe("messages");
  });

  it("peeks a Uint8Array JSON body", async () => {
    const body = new TextEncoder().encode(
      JSON.stringify({ contents: [{ parts: [{ text: "hi" }] }] }),
    );
    const shape = await peekBodyForShape("https://x.test/foo", {
      method: "POST",
      body,
    });
    expect(shape).toBe("contents");
  });

  it("peeks an ArrayBuffer JSON body", async () => {
    const bytes = new TextEncoder().encode(JSON.stringify({ prompt: "hi" }));
    const shape = await peekBodyForShape("https://x.test/foo", {
      method: "POST",
      body: bytes.buffer,
    });
    expect(shape).toBe("prompt");
  });

  it("peeks a Request body via clone()", async () => {
    const req = new Request("https://x.test/foo", {
      method: "POST",
      body: JSON.stringify({ input: "hi" }),
    });
    const shape = await peekBodyForShape(req);
    expect(shape).toBe("input");
  });

  it("returns none for non-JSON string bodies", async () => {
    const shape = await peekBodyForShape("https://x.test/foo", {
      method: "POST",
      body: "not json at all",
    });
    expect(shape).toBe("none");
  });

  it("returns none when body is absent", async () => {
    expect(
      await peekBodyForShape("https://x.test/foo", { method: "POST" }),
    ).toBe("none");
  });

  it("returns none for unknown body types (FormData, Blob, ReadableStream) without consuming them", async () => {
    const fd = new FormData();
    fd.append("foo", "bar");
    expect(
      await peekBodyForShape("https://x.test/foo", {
        method: "POST",
        body: fd,
      }),
    ).toBe("none");
  });

  it("prefers init.body over a non-LLM Request body", async () => {
    const req = new Request("https://custom-provider.test/v1/inference", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event: "not-an-llm" }),
    });
    expect(
      await peekBodyForShape(req, {
        method: "PUT",
        body: JSON.stringify({
          messages: [{ role: "user", content: "override-llm-body" }],
        }),
      }),
    ).toBe("messages");
  });

  it("does not hang peeking a Request body larger than 64 KiB", async () => {
    const request = new Request("https://custom-provider.test/v1/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "custom",
        messages: [{ role: "user", content: "x".repeat(70_000) }],
      }),
    });
    const shape = await Promise.race([
      peekBodyForShape(request),
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error("peek hung")), 1000);
      }),
    ]);
    expect(shape).toBe("messages");
  });

  it("completes a large Request peek after the caller aborts", async () => {
    const controller = new AbortController();
    const request = new Request("https://custom-provider.test/v1/chat", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model: "custom",
        messages: [{ role: "user", content: "x".repeat(70_000) }],
      }),
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(), 5);
    await expect(
      Promise.race([
        peekBodyForShape(request),
        new Promise<never>((_, reject) => {
          setTimeout(() => reject(new Error("peek hung after abort")), 1000);
        }),
      ]),
    ).resolves.toBe("messages");
  });
});

describe("resolveEffectiveFetchInit", () => {
  it("lets init override Request method, headers, body, and signal", () => {
    const requestController = new AbortController();
    const initController = new AbortController();
    const req = new Request("https://custom-provider.test/v1/inference", {
      method: "POST",
      headers: { "content-type": "application/json", "x-from-request": "1" },
      body: JSON.stringify({ event: "not-an-llm" }),
      signal: requestController.signal,
      redirect: "follow",
      credentials: "omit",
    });
    const effective = resolveEffectiveFetchInit(req, {
      method: "PUT",
      headers: { "x-from-init": "yes" },
      body: JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
      signal: initController.signal,
      redirect: "manual",
      credentials: "include",
      cache: "no-store",
      integrity: "sha256-abc",
      keepalive: true,
      mode: "cors",
      referrer: "https://app.example.test/",
      referrerPolicy: "no-referrer",
    });
    expect(effective.method).toBe("PUT");
    expect(effective.headers.get("x-from-request")).toBe("1");
    expect(effective.headers.get("x-from-init")).toBe("yes");
    expect(effective.body).toBe(
      JSON.stringify({ messages: [{ role: "user", content: "hi" }] }),
    );
    expect(effective.redirect).toBe("manual");
    expect(effective.credentials).toBe("include");
    expect(effective.cache).toBe("no-store");
    expect(effective.integrity).toBe("sha256-abc");
    expect(effective.keepalive).toBe(true);
    expect(effective.mode).toBe("cors");
    expect(effective.referrer).toBe("https://app.example.test/");
    expect(effective.referrerPolicy).toBe("no-referrer");
    expect(effective.signal).toBeDefined();
    initController.abort();
    expect(effective.signal?.aborted).toBe(true);
  });

  it("keeps Request metadata when init is omitted", () => {
    const req = new Request("https://api.openai.com/v1/chat/completions", {
      method: "POST",
      body: JSON.stringify({ messages: [] }),
      redirect: "error",
      credentials: "same-origin",
    });
    const effective = resolveEffectiveFetchInit(req);
    expect(effective.method).toBe("POST");
    expect(effective.redirect).toBe("error");
    expect(effective.credentials).toBe("same-origin");
    expect(effective.body).toBe(req.body);
  });
});
