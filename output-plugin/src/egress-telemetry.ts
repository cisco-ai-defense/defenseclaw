/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Layer 3 egress telemetry for the TS fetch interceptor.
 *
 * Every intercepted fetch (known-provider, shape-matched, or left to
 * bypass after classification) reports a single {@link EgressEvent} to
 * the guardrail proxy via POST /v1/events/egress. The proxy
 * re-emits the event through the shared gatewaylog.Writer so SIEM,
 * OTel, and the TUI Alerts panel all see the same silent-bypass /
 * shape-match signal the Go side already reports.
 *
 * Design goals:
 *   - Cheap and non-blocking: we never await on telemetry — a slow or
 *     missing proxy must not stall or block the underlying LLM call.
 *   - Resilient: errors are swallowed; telemetry is best-effort.
 *   - Low cardinality: 60s per-(host,branch,decision) dedup window so
 *     a chatty SDK cannot flood gateway.jsonl at request rates.
 *   - Read-once safe: the caller already peeked the body for shape
 *     classification, so we accept the shape as a parameter rather
 *     than re-reading anything.
 */

import { loadSidecarConfig } from "./sidecar-config.js";

// Kept in sync with fetch-interceptor.ts::DC_AUTH_HEADER. Inlined to
// avoid an import cycle between the reporter and its consumer.
const DC_AUTH_HEADER = "X-DC-Auth";

/** Branch labels mirror the Go-side emitter in internal/gateway/events.go. */
export type EgressBranch = "known" | "shape" | "passthrough";

/** Allow/block decision at the guardrail edge. */
export type EgressDecision = "allow" | "block";

export interface EgressEvent {
  /** Origin host of the outbound request (never the proxy itself). */
  targetHost: string;
  /** Request path — capped to 256 chars by the Go emitter. */
  targetPath: string;
  /**
   * Classified LLM body shape ("messages" | "prompt" | "input" |
   * "contents" | "none"). Pass the same value the interceptor already
   * computed; don't re-peek.
   */
  bodyShape: string;
  /**
   * Whether either the path or body looked like an LLM call. A true
   * value with decision="allow" + branch="passthrough" is the exact
   * silent-bypass failure we want to catch.
   */
  looksLikeLLM: boolean;
  /** Which rail fired: known-provider, shape-detected, or passthrough. */
  branch: EgressBranch;
  /** Operational outcome — allow (forwarded) or block (rejected). */
  decision: EgressDecision;
  /** Human-readable reason (optional). */
  reason?: string;
}

/** Tunable — 60s is a balance between signal freshness and noise. */
const DEFAULT_DEDUP_WINDOW_MS = 60_000;

/**
 * Dedup key shape mirrors the Go emitter so a single (host, branch,
 * decision) triple maps to one event per minute per emitter. We don't
 * dedup on body shape or reason on purpose — a host flipping from
 * "passthrough" to "shape" is exactly the signal we want to see.
 */
function dedupKey(e: EgressEvent): string {
  return `${e.targetHost}::${e.branch}::${e.decision}`;
}

export interface EgressReporter {
  report(e: EgressEvent): void;
  stop(): void;
}

export interface CreateEgressReporterOptions {
  /** Guardrail proxy port — typically cfg.gateway.port. */
  guardrailPort: number;
  /** Override fetch for tests; defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Override dedup window (ms). Default 60s. */
  dedupWindowMs?: number;
}

/**
 * Build a bounded-memory reporter. Each call to report() is:
 *  - deduped against the last `dedupWindowMs` of events,
 *  - scheduled with queueMicrotask so the caller's fetch resumes
 *    immediately,
 *  - wrapped in a try/catch + AbortSignal.timeout so a stuck proxy
 *    never holds on to memory.
 */
export function createEgressReporter(
  opts: CreateEgressReporterOptions,
): EgressReporter {
  const fetchImpl = opts.fetchImpl ?? globalThis.fetch;
  const dedupWindow = opts.dedupWindowMs ?? DEFAULT_DEDUP_WINDOW_MS;
  const lastSeen = new Map<string, number>();
  const endpoint = `http://127.0.0.1:${opts.guardrailPort}/v1/events/egress`;

  function report(e: EgressEvent): void {
    try {
      const key = dedupKey(e);
      const now = Date.now();
      const seen = lastSeen.get(key) ?? 0;
      if (now - seen < dedupWindow) return;
      lastSeen.set(key, now);

      // Periodically trim dead entries so a pathological long-running
      // agent process that has touched thousands of unique (host,
      // branch, decision) triples doesn't grow unbounded.
      //
      // Two-stage cleanup: first expire anything older than the
      // dedup window; if that is still not enough (constant churn
      // within the window), hard-cap at 4096 by deleting the oldest
      // entries. Without the hard cap, a pathological agent that
      // repeatedly hits 50k unique hosts inside a 60s window would
      // grow the map without bound even after "periodic cleanup."
      if (lastSeen.size > 4096) {
        for (const [k, ts] of lastSeen) {
          if (now - ts >= dedupWindow) lastSeen.delete(k);
        }
        if (lastSeen.size > 4096) {
          // Map iteration order is insertion order, so the first N
          // entries are the oldest. Evict until we're back under
          // the cap.
          const toEvict = lastSeen.size - 4096;
          let evicted = 0;
          for (const k of lastSeen.keys()) {
            if (evicted >= toEvict) break;
            lastSeen.delete(k);
            evicted++;
          }
        }
      }

      // Truncate target_path to the same 256-byte ceiling the Go
      // emitter enforces. Keeping the TS side within the same cap
      // prevents a single pathological long URL from bloating the
      // POST body (and therefore the gateway.jsonl row) when we
      // could just as usefully truncate upstream. target_host is
      // already bounded by DNS (253 chars) so we only cap the path.
      const truncatedPath = e.targetPath.length > 256
        ? e.targetPath.slice(0, 256)
        : e.targetPath;
      const payload = {
        target_host: e.targetHost,
        target_path: truncatedPath,
        body_shape: e.bodyShape,
        looks_like_llm: e.looksLikeLLM,
        branch: e.branch,
        decision: e.decision,
        reason: e.reason ?? "",
      };

      queueMicrotask(() => {
        const headers: Record<string, string> = {
          "Content-Type": "application/json",
        };
        const token = loadSidecarConfig().token;
        if (token) headers[DC_AUTH_HEADER] = `Bearer ${token}`;

        // 2s ceiling — egress telemetry is disposable by design.
        // Prefer AbortSignal.timeout when available; fall back to a
        // plain AbortController + setTimeout so older runtimes still
        // get a hard cap on the telemetry fetch (otherwise a hung
        // sidecar leaks an unresolved fetch).
        let signal: AbortSignal | undefined;
        let fallbackTimer: ReturnType<typeof setTimeout> | undefined;
        if (typeof AbortSignal !== "undefined" && "timeout" in AbortSignal) {
          signal = (AbortSignal as unknown as { timeout(ms: number): AbortSignal }).timeout(2_000);
        } else if (typeof AbortController !== "undefined") {
          const ctrl = new AbortController();
          signal = ctrl.signal;
          fallbackTimer = setTimeout(() => ctrl.abort(), 2_000);
        }

        fetchImpl(endpoint, {
          method: "POST",
          headers,
          body: JSON.stringify(payload),
          signal,
        })
          .catch(() => {
            // Telemetry is best-effort. Errors here never propagate.
          })
          .finally(() => {
            if (fallbackTimer !== undefined) clearTimeout(fallbackTimer);
          });
      });
    } catch {
      // Belt-and-braces: the whole telemetry path is a no-op on any
      // error so a telemetry bug cannot break LLM traffic.
    }
  }

  function stop(): void {
    lastSeen.clear();
  }

  return { report, stop };
}
