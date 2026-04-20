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
 * Extract the provider API key from whichever header the provider SDK uses.
 * Different providers use different auth mechanisms:
 *   - OpenAI / OpenRouter / Gemini compat: Authorization: Bearer <key>
 *   - Anthropic: x-api-key: <key>
 *   - Azure OpenAI: api-key: <key>
 *   - Gemini native: ?key= query param (handled separately, not in headers)
 *   - Bedrock: AWS SigV4 (multiple headers, not a simple key)
 *   - Ollama: no auth
 *
 * Returns the key prefixed with "Bearer " for consistency, or empty string.
 */
function extractProviderKey(headers: Headers): string {
  // Authorization: Bearer <key> — most providers
  const auth = headers.get("Authorization") ?? "";
  if (auth && !auth.startsWith("Bearer sk-dc-")) {
    return auth;
  }
  // x-api-key — Anthropic
  const xApiKey = headers.get("x-api-key") ?? "";
  if (xApiKey) {
    return `Bearer ${xApiKey}`;
  }
  // api-key — Azure OpenAI
  const apiKey = headers.get("api-key") ?? "";
  if (apiKey) {
    return `Bearer ${apiKey}`;
  }
  return "";
}

/**
 * Same as extractProviderKey but for Node http.request headers (plain object,
 * case-sensitive keys).
 */
function extractProviderKeyFromRecord(hdrs: Record<string, string>): string {
  const auth = hdrs["Authorization"] ?? hdrs["authorization"] ?? "";
  if (auth && !auth.startsWith("Bearer sk-dc-")) {
    return auth;
  }
  const xApiKey = hdrs["x-api-key"] ?? hdrs["X-Api-Key"] ?? "";
  if (xApiKey) {
    return `Bearer ${xApiKey}`;
  }
  const apiKey = hdrs["api-key"] ?? hdrs["Api-Key"] ?? "";
  if (apiKey) {
    return `Bearer ${apiKey}`;
  }
  return "";
}

/**
 * Build the proxy-hop headers (X-DC-Target-URL, X-AI-Auth, X-DC-Auth) that
 * the guardrail proxy expects. Used by both the fetch and https.request
 * interceptors so the logic lives in one place.
 *
 * OpenClaw already resolves the real provider API key and sets it in the
 * appropriate header for each provider SDK. We extract it from whichever
 * header is used and forward it as X-AI-Auth for uniform proxy handling.
 */
function buildProxyHeaders(
  targetOrigin: string,
  providerKey: string,
): Record<string, string> {
  const hdrs: Record<string, string> = {
    [TARGET_URL_HEADER]: targetOrigin,
  };

  // Forward the real provider key as X-AI-Auth so the proxy has a single
  // unified header to read for all providers.
  if (providerKey) {
    hdrs[AI_AUTH_HEADER] = providerKey;
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
      const providerKey = extractProviderKey(headers);
      const proxyHdrs = buildProxyHeaders(original.origin, providerKey);
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

      const response = await originalFetch!(proxied, newInit);

      if (response.headers.get("x-defenseclaw-blocked") === "true") {
        console.warn(
          "[defenseclaw] REQUEST BLOCKED by guardrail policy",
        );
      }

      return response;
    };

    // Also patch https.request so axios, undici, and other non-fetch HTTP
    // clients are intercepted. All of them ultimately use node:https.request.
    originalHttpsRequest = https.request.bind(https);
    const originalHttpRequest = http.request.bind(http);

    type NodeRequestOptions = Record<string, unknown>;
    type NodeIncomingMessage = unknown;
    type NodeClientRequest = ReturnType<typeof http.request>;

    /**
     * Normalize the varied `https.request` call shapes into a single URL string
     * we can match against LLM provider domains. Callers may pass:
     *   - request(url: string)
     *   - request(url: URL)
     *   - request(options)                   // { host|hostname, port, path, protocol }
     *   - request(url, options)              // URL first, then extra options
     * @smithy/node-http-handler v4 passes an options object with `host` (NOT
     * `hostname`), separate `port`, and separate `path`, so we must read both
     * `host` and `hostname` and fold `path` back in to match on domain + path.
     */
    function buildUrlStringFromArgs(
      urlOrOptions: string | URL | NodeRequestOptions,
      secondArg: NodeRequestOptions | ((res: NodeIncomingMessage) => void) | undefined,
    ): string {
      if (typeof urlOrOptions === "string") return urlOrOptions;
      if (urlOrOptions instanceof URL) return urlOrOptions.toString();

      const opts = urlOrOptions as {
        host?: unknown;
        hostname?: unknown;
        port?: unknown;
        path?: unknown;
        protocol?: unknown;
      };
      const overlay = (typeof secondArg === "object" && secondArg !== null
        ? (secondArg as typeof opts)
        : {});

      const host =
        (typeof overlay.hostname === "string" && overlay.hostname) ||
        (typeof overlay.host === "string" && overlay.host) ||
        (typeof opts.hostname === "string" && opts.hostname) ||
        (typeof opts.host === "string" && opts.host) ||
        "";
      const port =
        (overlay.port !== undefined ? String(overlay.port) : "") ||
        (opts.port !== undefined ? String(opts.port) : "");
      const path =
        (typeof overlay.path === "string" && overlay.path) ||
        (typeof opts.path === "string" && opts.path) ||
        "/";
      const proto =
        (typeof overlay.protocol === "string" && overlay.protocol) ||
        (typeof opts.protocol === "string" && opts.protocol) ||
        "https:";

      if (!host) return "";
      const hostPart = port ? `${host}:${port}` : host;
      return `${proto}//${hostPart}${path}`;
    }

    function patchedHttpsRequest(
      urlOrOptions: string | URL | NodeRequestOptions,
      optionsOrCallback?: NodeRequestOptions | ((res: NodeIncomingMessage) => void),
      callback?: (res: NodeIncomingMessage) => void,
    ): NodeClientRequest {
      const urlStr = buildUrlStringFromArgs(urlOrOptions, optionsOrCallback);

      if (urlStr && isLLMUrl(urlStr, guardrailPort) && !isAlreadyProxied(urlStr, guardrailPort)) {
        let opts: NodeRequestOptions = {};
        let cb = callback;

        if (typeof optionsOrCallback === "function") {
          cb = optionsOrCallback;
          opts = typeof urlOrOptions === "string" || urlOrOptions instanceof URL
            ? {} : urlOrOptions as NodeRequestOptions;
        } else if (optionsOrCallback && typeof optionsOrCallback === "object") {
          opts = optionsOrCallback as NodeRequestOptions;
        }

        let originalUrl: URL;
        try {
          originalUrl = new URL(urlStr);
        } catch {
          return originalHttpsRequest!(urlOrOptions as string, optionsOrCallback as NodeRequestOptions, callback);
        }

        const hdrs = opts.headers as Record<string, string> ?? {};
        const providerKey = extractProviderKeyFromRecord(hdrs);
        const proxyHdrs = buildProxyHeaders(originalUrl.origin, providerKey);

        // Spread `opts` first, then overwrite target fields. Crucially, drop:
        //
        //  - `host` (smithy passes `host` not `hostname`; Node's `host` wins
        //    over `hostname` in some paths, which would send traffic to the
        //    original LLM domain instead of the proxy);
        //  - `agent` (callers like @smithy/node-http-handler pass an
        //    `https.Agent`. Node's `http.request` rejects an agent whose
        //    `protocol === "https:"` with `ERR_INVALID_PROTOCOL`: "Protocol
        //    'http:' not supported. Expected 'https:'". We want Node to use
        //    the default http agent for the proxy hop, so set `agent: false`);
        //  - TLS-only options (`ca`, `cert`, `key`, ...) which have no meaning
        //    on a plain http.request and could still drag protocol checks in.
        const {
          host: _legacyHost,
          agent: _legacyAgent,
          ca: _ca,
          cert: _cert,
          key: _key,
          pfx: _pfx,
          passphrase: _passphrase,
          servername: _servername,
          ciphers: _ciphers,
          ecdhCurve: _ecdhCurve,
          secureProtocol: _secureProtocol,
          minVersion: _minVersion,
          maxVersion: _maxVersion,
          sigalgs: _sigalgs,
          crl: _crl,
          dhparam: _dhparam,
          rejectUnauthorized: _rejectUnauthorized,
          checkServerIdentity: _checkServerIdentity,
          session: _session,
          allowPartialTrustChain: _allowPartialTrustChain,
          ...restOpts
        } = opts as { host?: unknown; agent?: unknown } & Record<string, unknown>;
        void _legacyHost;
        void _legacyAgent;
        void _ca;
        void _cert;
        void _key;
        void _pfx;
        void _passphrase;
        void _servername;
        void _ciphers;
        void _ecdhCurve;
        void _secureProtocol;
        void _minVersion;
        void _maxVersion;
        void _sigalgs;
        void _crl;
        void _dhparam;
        void _rejectUnauthorized;
        void _checkServerIdentity;
        void _session;
        void _allowPartialTrustChain;
        const newOpts: NodeRequestOptions = {
          ...restOpts,
          hostname: "127.0.0.1",
          port: guardrailPort,
          protocol: "http:",
          path: `${originalUrl.pathname}${originalUrl.search}`,
          headers: { ...hdrs, ...proxyHdrs },
          // Force Node to pick a default http.Agent for this request. Leaving
          // the caller's https.Agent in place would throw at socket allocation.
          agent: false,
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
