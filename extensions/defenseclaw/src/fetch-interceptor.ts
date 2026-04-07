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

import { createRequire } from "node:module";
import { loadSidecarConfig } from "./sidecar-config.js";
// Canonical provider config — single source of truth shared with the Go proxy.
// Copied from internal/configs/providers.json by `make plugin`.
import providersConfig from "./providers.json" with { type: "json" };
const _require = createRequire(import.meta.url);
// Use CommonJS require() for https/http — ESM module objects are frozen and
// cannot have properties reassigned, but the CJS exports object is mutable.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const https = _require("https") as typeof import("https");
// eslint-disable-next-line @typescript-eslint/no-var-requires
const http = _require("http") as typeof import("http");

/** Domains that should be intercepted, built from providers.json. */
const LLM_DOMAINS: string[] = providersConfig.providers.flatMap(
  (p: { domains: string[] }) => p.domains,
);

/**
 * Ollama runs locally — intercept by matching its default port.
 * We cannot list "localhost" broadly because that would also match
 * the proxy itself (localhost:4000).
 */
const OLLAMA_PORTS: string[] = providersConfig.ollama_ports.map(String);

/** Header name the proxy reads to determine the real upstream URL. */
export const TARGET_URL_HEADER = "X-DC-Target-URL";

/**
 * Header carrying the real LLM provider key to the proxy.
 * Kept separate from Authorization so the original Authorization header
 * (which may carry a different token) is preserved verbatim.
 */
export const AI_AUTH_HEADER = "X-AI-Auth";

/**
 * Header carrying the defenseclaw proxy authentication token (the openclaw
 * gateway token from OPENCLAW_GATEWAY_TOKEN / gateway.token in config.yaml).
 * The proxy validates this for non-loopback connections; loopback connections
 * are trusted by network topology alone.
 */
export const DC_AUTH_HEADER = "X-DC-Auth";

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
 * Build the proxy-hop headers (X-DC-Target-URL, X-AI-Auth, X-DC-Auth) that
 * the guardrail proxy expects. Used by both the fetch and https.request
 * interceptors so the logic lives in one place.
 *
 * OpenClaw already resolves the real provider API key (from auth-profiles.json
 * or env vars) and sets it as the Authorization header on outgoing requests.
 * We simply forward that as X-AI-Auth, filtering out sk-dc-* master keys.
 */
function buildProxyHeaders(
  targetOrigin: string,
  existingAuth: string,
): Record<string, string> {
  const hdrs: Record<string, string> = {
    [TARGET_URL_HEADER]: targetOrigin,
  };

  // Forward the real provider key from Authorization as X-AI-Auth.
  // Skip sk-dc-* master keys — the proxy resolves those itself.
  if (existingAuth && !existingAuth.startsWith("Bearer sk-dc-")) {
    hdrs[AI_AUTH_HEADER] = existingAuth;
  }

  // X-DC-Auth: proxy authentication token for remote deployments.
  const sidecarToken = loadSidecarConfig().token;
  if (sidecarToken) {
    hdrs[DC_AUTH_HEADER] = `Bearer ${sidecarToken}`;
  }

  return hdrs;
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

    globalThis.fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const urlStr = String(input instanceof Request ? input.url : input);

      // Pass through non-LLM calls and calls already going to the proxy.
      if (!isLLMUrl(urlStr, guardrailPort) || isAlreadyProxied(urlStr, guardrailPort)) {
        return originalFetch!(input, init);
      }

      let original: URL;
      try {
        original = new URL(urlStr);
      } catch {
        return originalFetch!(input, init);
      }

      // Rewrite: keep path + query, replace scheme://host with proxy.
      const proxied = `${proxyBase}${original.pathname}${original.search}`;

      // Merge all original headers and add proxy-hop headers.
      const headers = new Headers(
        input instanceof Request ? input.headers : (init?.headers as HeadersInit | undefined),
      );
      const existingAuth = headers.get("Authorization") ?? "";
      const proxyHdrs = buildProxyHeaders(original.origin, existingAuth);
      for (const [k, v] of Object.entries(proxyHdrs)) {
        headers.set(k, v);
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

        const hdrs = opts.headers as Record<string, string> ?? {};
        const existingAuth = hdrs["authorization"] ?? hdrs["Authorization"] ?? "";
        const proxyHdrs = buildProxyHeaders(originalUrl.origin, existingAuth);

        const newOpts: NodeRequestOptions = {
          ...opts,
          hostname: "127.0.0.1",
          port: guardrailPort,
          protocol: "http:",
          path: `${originalUrl.pathname}${originalUrl.search}`,
          headers: { ...hdrs, ...proxyHdrs },
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
