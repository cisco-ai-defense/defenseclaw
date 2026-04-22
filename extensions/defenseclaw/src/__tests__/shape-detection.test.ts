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
});
