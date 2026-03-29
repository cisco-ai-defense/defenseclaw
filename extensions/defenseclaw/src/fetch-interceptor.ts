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

/** Domains that should be intercepted and routed through the guardrail. */
const LLM_DOMAINS = [
  "api.anthropic.com",
  "openrouter.ai",
  "api.openai.com",
  "generativelanguage.googleapis.com",
  "amazonaws.com",          // covers bedrock-runtime.*.amazonaws.com
];

/** Header name the proxy reads to determine the real upstream URL. */
export const TARGET_URL_HEADER = "X-DC-Target-URL";

function isLLMUrl(url: string): boolean {
  return LLM_DOMAINS.some(domain => url.includes(domain));
}

function isAlreadyProxied(url: string): boolean {
  return url.includes("127.0.0.1") || url.includes("localhost");
}

/**
 * Creates an interceptor that, when started, patches globalThis.fetch to
 * redirect LLM API calls through the guardrail proxy.
 * Call stop() to restore the original fetch.
 */
export function createFetchInterceptor(guardrailPort: number) {
  const proxyBase = `http://127.0.0.1:${guardrailPort}`;
  let originalFetch: typeof globalThis.fetch | null = null;

  function start(): void {
    if (originalFetch) return; // already started
    originalFetch = globalThis.fetch;

    globalThis.fetch = async (
      input: RequestInfo | URL,
      init?: RequestInit,
    ): Promise<Response> => {
      const urlStr = String(input instanceof Request ? input.url : input);

      // Pass through non-LLM calls and calls already going to the proxy.
      if (!isLLMUrl(urlStr) || isAlreadyProxied(urlStr)) {
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

      // Merge all original headers and add X-DC-Target-URL.
      const headers = new Headers(
        input instanceof Request ? input.headers : (init?.headers as HeadersInit | undefined),
      );
      headers.set(TARGET_URL_HEADER, original.origin);

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

    console.log(
      `[defenseclaw] LLM fetch interceptor active (proxy: ${proxyBase})`,
    );
  }

  function stop(): void {
    if (originalFetch) {
      globalThis.fetch = originalFetch;
      originalFetch = null;
      console.log("[defenseclaw] LLM fetch interceptor stopped");
    }
  }

  return { start, stop };
}
