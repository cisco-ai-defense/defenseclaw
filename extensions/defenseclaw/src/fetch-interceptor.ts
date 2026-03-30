/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * LLM Fetch Interceptor
 *
 * Patches globalThis.fetch to redirect outbound LLM API calls through the
 * DefenseClaw guardrail proxy at localhost:{guardrailPort}, regardless of
 * which provider or model the user selected in OpenClaw.
 *
 * The original upstream URL is preserved in the X-DC-Target-URL header so
 * the proxy can route to the correct upstream after inspection.
 */

import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { createRequire } from "node:module";
const _require = createRequire(import.meta.url);
// Use CommonJS require() for https/http — ESM module objects are frozen and
// cannot have properties reassigned, but the CJS exports object is mutable.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const https = _require("https") as typeof import("https");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const http = _require("http") as typeof import("http");

/** Domains that should be intercepted and routed through the guardrail. */
const LLM_DOMAINS = [
  "api.anthropic.com",
  "openrouter.ai",
  "api.openai.com",
  "openai.azure.com",       // Azure OpenAI — customer-specific subdomain
  "generativelanguage.googleapis.com", // Gemini (Google AI Studio)
  "googleapis.com/v1/projects", // Vertex AI Gemini
  "amazonaws.com",          // Bedrock: bedrock-runtime.*.amazonaws.com
];

/**
 * Ollama runs locally — intercept by matching its default port.
 * We cannot list "localhost" broadly because that would also match
 * the proxy itself (localhost:4000).
 */
const OLLAMA_PORTS = ["11434"];

/** Header name the proxy reads to determine the real upstream URL. */
export const TARGET_URL_HEADER = "X-DC-Target-URL";

/**
 * Header carrying the real LLM provider key to the proxy.
 * Kept separate from Authorization so the original OpenClaw→DefenseClaw
 * connection auth (sk-dc-* master key) is preserved for gateway auth,
 * including future remote DefenseClaw gateway deployments.
 */
export const AI_AUTH_HEADER = "X-AI-Auth";

function isLLMUrl(url: string, guardrailPort: number): boolean {
  if (LLM_DOMAINS.some(domain => url.includes(domain))) return true;
  // Ollama: localhost or 127.0.0.1 on known Ollama ports, but NOT the proxy port.
  return OLLAMA_PORTS.some(
    port =>
      (url.includes(`localhost:${port}`) || url.includes(`127.0.0.1:${port}`)) &&
      !url.includes(`:${guardrailPort}`)
  );
}

function isAlreadyProxied(url: string, guardrailPort: number): boolean {
  // Only skip requests already targeting the guardrail proxy itself.
  return (
    url.includes(`127.0.0.1:${guardrailPort}`) ||
    url.includes(`localhost:${guardrailPort}`)
  );
}

/**
 * Domain substring → auth-profiles.json profile id mapping.
 * OpenClaw stores one profile per provider under agents/main/agent/auth-profiles.json.
 * Keys are read once at interceptor start and cached for the process lifetime.
 */
const DOMAIN_TO_PROFILE: Record<string, string> = {
  "api.anthropic.com":               "anthropic:default",
  "openrouter.ai":                   "openrouter:default",
  "api.openai.com":                  "openai:default",
  "openai.azure.com":                "azure:default",
  "generativelanguage.googleapis.com": "google:default",
  "googleapis.com/v1/projects":      "google:default", // Vertex AI
};

// Key cache with TTL — refreshed every 30 seconds so key changes in
// OpenClaw are picked up without needing to restart.
const KEY_CACHE_TTL_MS = 30_000;
let providerKeyCache: Record<string, string> = {};
let providerKeyCacheTs = 0;

function loadProviderKeys(): void {
  const now = Date.now();
  if (now - providerKeyCacheTs < KEY_CACHE_TTL_MS && providerKeyCacheTs > 0) {
    return; // still fresh
  }

  try {
    const profilesPath = join(
      homedir(), ".openclaw", "agents", "main", "agent", "auth-profiles.json"
    );
    const data = JSON.parse(readFileSync(profilesPath, "utf8"));
    const profiles = data?.profiles ?? {};

    const fresh: Record<string, string> = {};
    for (const [domain, profileId] of Object.entries(DOMAIN_TO_PROFILE)) {
      const key = profiles[profileId]?.key;
      if (key) fresh[domain] = key;
    }
    providerKeyCache = fresh;
    providerKeyCacheTs = now;
  } catch (err) {
    // auth-profiles.json not found or unreadable — log so it's diagnosable
    console.log(`[defenseclaw] could not load provider keys: ${err}`);
    providerKeyCacheTs = now; // avoid hammering on every request
  }
}

/** Return the real provider key for a URL if we have it, else empty string. */
function getRealKeyForUrl(urlStr: string): string {
  for (const [domain, key] of Object.entries(providerKeyCache)) {
    if (urlStr.includes(domain)) return key;
  }
  return "";
}

/**
 * Creates an interceptor that, when started, patches globalThis.fetch to
 * redirect LLM API calls through the guardrail proxy.
 * Call stop() to restore the original fetch.
 */
export function createFetchInterceptor(guardrailPort: number) {
  const proxyBase = `http://127.0.0.1:${guardrailPort}`;
  let originalFetch: typeof globalThis.fetch | null = null;
  let originalHttpsRequest: typeof https.request | null = null;

  function start(): void {
    if (originalFetch) return; // already started
    originalFetch = globalThis.fetch;

    // Load real provider keys from OpenClaw's auth-profiles.json so we can
    // inject them when OpenClaw sends requests via the defenseclaw provider
    // (which uses sk-dc-* master key as Bearer, not the real provider key).
    loadProviderKeys();

    globalThis.fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const urlStr = String(input instanceof Request ? input.url : input);

      // Pass through non-LLM calls and calls already going to the proxy.
      if (!isLLMUrl(urlStr, guardrailPort) || isAlreadyProxied(urlStr, guardrailPort)) {
        return originalFetch!(input, init);
      }

      // Refresh key cache if stale — picks up key changes made in OpenClaw
      // without requiring a restart.
      loadProviderKeys();

      let original: URL;
      try {
        original = new URL(urlStr);
      } catch {
        return originalFetch!(input, init);
      }

      // Rewrite: keep path + query, replace scheme://host with proxy.
      const proxied = `${proxyBase}${original.pathname}${original.search}`;

      // Merge all original headers and add X-DC-Target-URL.
      const headers = new Headers(
        input instanceof Request ? input.headers : (init?.headers as HeadersInit | undefined),
      );
      headers.set(TARGET_URL_HEADER, original.origin);

      // Inject the real LLM provider key as X-AI-Auth — a dedicated header
      // separate from Authorization. This preserves the original sk-dc-* master
      // key in Authorization for OpenClaw→DefenseClaw connection auth (including
      // future remote gateway deployments), while giving the proxy the actual
      // provider key it needs to call the upstream LLM.
      const realKey = getRealKeyForUrl(urlStr);
      if (realKey) {
        headers.set(AI_AUTH_HEADER, `Bearer ${realKey}`);
      } else {
        // No cached key — forward original Authorization as X-AI-Auth so the
        // proxy has it available (e.g. when OpenClaw sends the real key directly).
        const existingAuth = headers.get("Authorization") ?? "";
        if (existingAuth && !existingAuth.startsWith("Bearer sk-dc-")) {
          headers.set(AI_AUTH_HEADER, existingAuth);
        }
      }

      // Build new init, preserving all original properties.
      const newInit: RequestInit =
        input instanceof Request
          ? { method: input.method, body: input.body, headers }
          : { ...(init ?? {}), headers };

      console.log(
        `[defenseclaw] intercepted LLM call → ${urlStr} proxied via ${proxyBase}`,
      );

      return originalFetch!(proxied, newInit);
    };

    // Also patch https.request so axios, undici, and other non-fetch HTTP
    // clients are intercepted. All of them ultimately use node:https.request.
    originalHttpsRequest = https.request.bind(https);
    const originalHttpRequest = http.request.bind(http);

    type NodeRequestOptions = Record<string, unknown>;
    type NodeIncomingMessage = unknown;
    type NodeClientRequest = ReturnType<typeof http.request>;

    function patchedHttpsRequest(
      urlOrOptions: string | URL | NodeRequestOptions,
      optionsOrCallback?: NodeRequestOptions | ((res: NodeIncomingMessage) => void),
      callback?: (res: NodeIncomingMessage) => void,
    ): NodeClientRequest {
      const urlStr = typeof urlOrOptions === "string"
        ? urlOrOptions
        : urlOrOptions instanceof URL
          ? urlOrOptions.toString()
          : ((urlOrOptions as NodeRequestOptions).hostname as string ?? "");

      if (isLLMUrl(urlStr, guardrailPort) && !isAlreadyProxied(urlStr, guardrailPort)) {
        loadProviderKeys();
        let opts: NodeRequestOptions = {};
        let cb = callback;

        if (typeof optionsOrCallback === "function") {
          cb = optionsOrCallback;
          opts = typeof urlOrOptions === "string" || urlOrOptions instanceof URL
            ? {} : urlOrOptions as NodeRequestOptions;
        } else if (optionsOrCallback && typeof optionsOrCallback === "object") {
          opts = optionsOrCallback as NodeRequestOptions;
        }

        // Parse original URL to get host, path, protocol
        let originalUrl: URL;
        try {
          const optsAs = opts as { hostname?: string; path?: string };
          originalUrl = new URL(typeof urlOrOptions === "string" ? urlOrOptions
            : urlOrOptions instanceof URL ? urlOrOptions.toString()
            : `https://${optsAs.hostname ?? ""}${optsAs.path ?? ""}`);
        } catch {
          return originalHttpsRequest!(urlOrOptions as string, optionsOrCallback as NodeRequestOptions, callback);
        }

        const realKey = getRealKeyForUrl(urlStr);
        const hdrs = opts.headers as Record<string, string> ?? {};
        const existingAuth = hdrs["authorization"] ?? hdrs["Authorization"] ?? "";
        const aiAuth = realKey ? `Bearer ${realKey}`
          : (existingAuth && !existingAuth.startsWith("Bearer sk-dc-") ? existingAuth : "");

        const newOpts: NodeRequestOptions = {
          ...opts,
          hostname: "127.0.0.1",
          port: guardrailPort,
          protocol: "http:",
          path: `${originalUrl.pathname}${originalUrl.search}`,
          headers: {
            ...hdrs,
            "X-DC-Target-URL": originalUrl.origin,
            ...(aiAuth ? { "X-AI-Auth": aiAuth } : {}),
          },
        };

        console.log(`[defenseclaw] intercepted LLM call (https.request) → ${urlStr} proxied via ${proxyBase}`);
        return http.request(newOpts as unknown as Parameters<typeof http.request>[0], cb as Parameters<typeof http.request>[1]);
      }

      return originalHttpsRequest!(urlOrOptions as string, optionsOrCallback as NodeRequestOptions, callback);
    }

    https.request = patchedHttpsRequest as typeof https.request;

    console.log(
      `[defenseclaw] LLM fetch interceptor active (proxy: ${proxyBase})`,
    );
  }

  function stop(): void {
    if (originalFetch) {
      globalThis.fetch = originalFetch;
      originalFetch = null;
    }
    // Restore https.request (safe because we used CJS require, not frozen ESM)
    if (originalHttpsRequest) {
      https.request = originalHttpsRequest;
    }
    console.log("[defenseclaw] LLM fetch interceptor stopped");
  }

  return { start, stop };
}
