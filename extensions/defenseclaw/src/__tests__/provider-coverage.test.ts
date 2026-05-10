/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * TS side of the shared provider-coverage contract.
 *
 * Each row in test/testdata/llm-endpoints.json must produce the same
 * branch classification on both the Go passthrough and the TS fetch
 * interceptor. A drift between the two implementations — e.g. a new
 * provider added to providers.json but not yet hooked in the Go
 * corpus — is exactly the failure mode Layer 4 of the plan sets out
 * to prevent.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import providersConfig from "../providers.json" with { type: "json" };
import {
  classifyBodyShape,
  hasLLMPathSuffix,
  isKnownSafeDomain,
  LLMBodyShape,
} from "../fetch-interceptor.js";

interface Row {
  name: string;
  url: string;
  method: string;
  body: unknown;
  expected_branch: "known" | "shape" | "passthrough";
  notes?: string;
}

interface Corpus {
  positive: Row[];
  negative: Row[];
}

function loadCorpus(): Corpus {
  // Walk up from cwd to find the repo root (contains test/testdata).
  // Tests may run from different cwd (repo root vs. extensions/defenseclaw).
  const here = resolve(process.cwd());
  const candidates = [
    resolve(here, "test/testdata/llm-endpoints.json"),
    resolve(here, "..", "..", "test/testdata/llm-endpoints.json"),
    resolve(here, "..", "test/testdata/llm-endpoints.json"),
  ];
  for (const p of candidates) {
    try {
      const raw = readFileSync(p, "utf-8");
      return JSON.parse(raw) as Corpus;
    } catch {
      // try next
    }
  }
  throw new Error(
    `llm-endpoints.json not found relative to ${here} (tried: ${candidates.join(", ")})`,
  );
}

const LLM_DOMAINS: string[] = providersConfig.providers.flatMap(
  (p: { domains: string[] }) => p.domains,
);
const OLLAMA_PORTS: string[] = (providersConfig.ollama_ports as number[]).map(
  String,
);

// Mirrors fetch-interceptor.ts::isLLMUrl (but parameterless: the
// classifier doesn't need a guardrail port — the corpus only covers
// URLs that would not collide with the proxy).
//
// The substring `url.includes(domain)` fallback used to be enough,
// but the SSRF hardening replaced the legacy trailing-dot prefix
// entry "bedrock-runtime." with the wildcard pattern
// "bedrock-runtime.*.amazonaws.com". A literal substring match never
// satisfies a "*", so the corpus mirror now parses the URL's
// hostname and applies the same matcher semantics that
// matchesLLMDomain in fetch-interceptor uses.
function matchWildcardDomain(host: string, pattern: string): boolean {
  const parts = pattern.split("*");
  if (parts.length !== 2) return false;
  const [prefix, suffix] = parts;
  if (!prefix || !suffix) return false;
  if (host.length < prefix.length + suffix.length) return false;
  if (!host.startsWith(prefix) || !host.endsWith(suffix)) return false;
  const middle = host.slice(prefix.length, host.length - suffix.length);
  if (middle.length === 0 || middle.includes(".")) return false;
  return true;
}

function isKnownProvider(url: string): boolean {
  let host = "";
  let port = "";
  let pathname = "";
  try {
    const u = new URL(url);
    host = u.hostname.toLowerCase();
    port = u.port;
    pathname = u.pathname;
  } catch {
    return false;
  }
  if (host === "") return false;
  for (const domain of LLM_DOMAINS) {
    const slash = domain.indexOf("/");
    const bare = (slash >= 0 ? domain.slice(0, slash) : domain).toLowerCase();
    const pathPrefix = slash >= 0 ? domain.slice(slash) : "";
    if (!bare) continue;
    // Legacy trailing-dot syntax has been retired.
    if (bare.endsWith(".")) continue;
    let hostMatch = false;
    if (bare.includes("*")) {
      hostMatch = matchWildcardDomain(host, bare);
    } else {
      hostMatch = host === bare || host.endsWith("." + bare);
    }
    if (!hostMatch) continue;
    if (pathPrefix === "") return true;
    if (pathname.startsWith(pathPrefix)) return true;
  }
  return OLLAMA_PORTS.some(
    p => (host === "localhost" || host === "127.0.0.1") && port === p,
  );
}

function classifyRow(row: Row): "known" | "shape" | "passthrough" {
  if (isKnownProvider(row.url)) return "known";
  const m = (row.method || "GET").toUpperCase();
  if (m === "GET" || m === "HEAD" || m === "OPTIONS") return "passthrough";
  if (isKnownSafeDomain(row.url)) return "passthrough";
  if (hasLLMPathSuffix(row.url)) return "shape";
  const shape: LLMBodyShape = classifyBodyShape(row.body);
  if (shape !== "none") return "shape";
  return "passthrough";
}

describe("provider coverage corpus", () => {
  const corpus = loadCorpus();

  describe("positive rows must intercept (known or shape)", () => {
    it.each(corpus.positive.map(r => [r.name, r] as const))(
      "%s",
      (_name, row) => {
        const got = classifyRow(row);
        expect(got, `${row.url} (${row.notes ?? ""})`).not.toBe("passthrough");
        if (row.expected_branch) {
          expect(got, `${row.url}`).toBe(row.expected_branch);
        }
      },
    );
  });

  describe("negative rows must never intercept", () => {
    it.each(corpus.negative.map(r => [r.name, r] as const))(
      "%s",
      (_name, row) => {
        const got = classifyRow(row);
        expect(got, `${row.url} (${row.notes ?? ""})`).toBe("passthrough");
      },
    );
  });
});
