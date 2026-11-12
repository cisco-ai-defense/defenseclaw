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

import { randomUUID } from "node:crypto";
import { request as httpRequest, type RequestOptions } from "node:http";
import { URL } from "node:url";
import {
  HEADER_DEFENSECLAW_CLIENT,
  buildSidecarCorrelationHeaders,
  parseStickyHeadersFromNode,
  parseStickyHeadersFromWebHeaders,
} from "./correlation-headers.js";
import type {
  ScanResult,
  BlockEntry,
  AllowEntry,
  CorrelationContext,
  OutboundSidecarRequestLog,
} from "./types.js";
import { loadSidecarConfig } from "./sidecar-config.js";
import { ListenerProofError, proveListener, provenCreateConnection } from "./listener-proof.js";

const REQUEST_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 10 * 1024 * 1024;
type RequestImpl = typeof httpRequest;

export interface DaemonClientOptions {
  baseUrl?: string;
  token?: string;
  timeoutMs?: number;
  requestImpl?: RequestImpl;
  /**
   * Base correlation for every request; may be sync or async.
   * Per-request overrides are merged in {@link buildOutboundHeaders}.
   */
  getCorrelation?: () => CorrelationContext | Promise<CorrelationContext>;
  /** Optional per-request correlation merged on top of {@link getCorrelation}. */
  correlationOverride?: Partial<CorrelationContext>;
  identityReady?: Promise<unknown>;
  logOutboundRequest?: (entry: OutboundSidecarRequestLog) => void;
  onCorrelationContext?: (ctx: CorrelationContext) => void;
}

interface ApiResponse<T> {
  ok: boolean;
  data?: T;
  error?: string;
  status: number;
}

export class DaemonClient {
  private readonly baseUrl: string;
  /** Explicit token; without one, each request reads the current sidecar token. */
  private readonly tokenOverride?: string;
  private readonly timeoutMs: number;
  private readonly requestImpl: RequestImpl;
  private readonly getCorrelation: () => CorrelationContext | Promise<CorrelationContext>;
  private readonly correlationOverride: Partial<CorrelationContext>;
  private readonly identityReady: Promise<unknown>;
  private readonly logOutboundRequest?: (entry: OutboundSidecarRequestLog) => void;
  private readonly onCorrelationContext?: (ctx: CorrelationContext) => void;

  /** First sidecar echo wins for the session (sticky). */
  private stickyOutboundAgentInstanceId?: string;
  private sidecarInstanceIdEcho?: string;

  constructor(opts?: DaemonClientOptions) {
    const cfg = loadSidecarConfig();
    this.baseUrl = opts?.baseUrl ?? cfg.baseUrl;
    this.tokenOverride = opts?.token;
    this.timeoutMs = opts?.timeoutMs ?? REQUEST_TIMEOUT_MS;
    this.requestImpl = opts?.requestImpl ?? httpRequest;
    this.getCorrelation = opts?.getCorrelation ?? defaultCorrelation;
    this.correlationOverride = opts?.correlationOverride ?? {};
    this.identityReady = opts?.identityReady ?? Promise.resolve();
    this.logOutboundRequest = opts?.logOutboundRequest;
    this.onCorrelationContext = opts?.onCorrelationContext;
  }

  /**
   * The sidecar token, read per request so a token that `setup openclaw`
   * rewrites in ~/.defenseclaw/.env is picked up without restarting
   * OpenClaw (GAP-2286).
   */
  private get token(): string {
    return this.tokenOverride ?? loadSidecarConfig().token;
  }

  /**
   * Sticky agent instance id from the sidecar (if any), else undefined.
   */
  getStickyAgentInstanceId(): string | undefined {
    return this.stickyOutboundAgentInstanceId;
  }

  getEchoedSidecarInstanceId(): string | undefined {
    return this.sidecarInstanceIdEcho;
  }

  /**
   * Updates sticky correlation from a `fetch` Response (inspect, code scan, health poll, etc.).
   */
  applyStickyFromHttpResponse(res: { headers: Headers }): void {
    const sticky = parseStickyHeadersFromWebHeaders(res.headers);
    if (sticky.agentInstanceId) {
      this.stickyOutboundAgentInstanceId = sticky.agentInstanceId;
    }
    if (sticky.sidecarInstanceId) {
      this.sidecarInstanceIdEcho = sticky.sidecarInstanceId;
    }
    void Promise.resolve(this.getCorrelation()).then((base) => {
      this.onCorrelationContext?.(this.mergeObservedContext(base));
    });
  }

  private async resolveCorrelation(
    partial?: Partial<CorrelationContext>,
  ): Promise<CorrelationContext> {
    await this.identityReady;
    const base = await Promise.resolve(this.getCorrelation());
    const merged: CorrelationContext = {
      ...base,
      ...this.correlationOverride,
      ...partial,
      agentId: partial?.agentId ?? this.correlationOverride.agentId ?? base.agentId,
    };
    if (!merged.traceId) merged.traceId = randomUUID();
    return merged;
  }

  /**
   * Headers for outbound sidecar HTTP requests (node `http` or `fetch`).
   */
  async buildOutboundHeaders(
    partial?: Partial<CorrelationContext>,
  ): Promise<Record<string, string>> {
    const ctx = await this.resolveCorrelation(partial);
    const outboundInstance =
      this.stickyOutboundAgentInstanceId ?? ctx.agentInstanceId ?? "";
    const corr = this.mergeObservedContext(ctx);
    const h = buildSidecarCorrelationHeaders(corr, {
      outboundAgentInstanceId: outboundInstance,
    });
    h[HEADER_DEFENSECLAW_CLIENT] = "openclaw-plugin";
    // The plugin credential is the openclaw connector-scoped token; the
    // gateway accepts it on /api/v1/inspect/* only with this header.
    h["X-DefenseClaw-Connector"] = "openclaw";
    const token = this.token;
    if (token) {
      // The listener proves it is this account's gateway before a caller
      // sends it the token (GAP-0594). Throws ListenerProofError.
      const target = new URL(this.baseUrl);
      await proveListener(target.hostname, Number(target.port) || 80, token);
      h.Authorization = `Bearer ${token}`;
    }
    return h;
  }

  private mergeObservedContext(base: CorrelationContext): CorrelationContext {
    return {
      ...base,
      agentInstanceId:
        this.stickyOutboundAgentInstanceId ?? base.agentInstanceId,
      sidecarInstanceId:
        this.sidecarInstanceIdEcho ?? base.sidecarInstanceId,
    };
  }

  async submitScanResult(result: ScanResult): Promise<ApiResponse<void>> {
    return this.post<void>("/scan/result", result);
  }

  /** Guardrail settings for the separate-user layout (GET /api/v1/openclaw/runtime). */
  async runtime(): Promise<ApiResponse<Record<string, unknown>>> {
    return this.get<Record<string, unknown>>("/api/v1/openclaw/runtime");
  }

  async listBlocked(): Promise<ApiResponse<BlockEntry[]>> {
    return this.get<BlockEntry[]>("/enforce/blocked");
  }

  async listAllowed(): Promise<ApiResponse<AllowEntry[]>> {
    return this.get<AllowEntry[]>("/enforce/allowed");
  }

  async logEvent(event: Record<string, unknown>): Promise<ApiResponse<void>> {
    return this.post<void>("/audit/event", event);
  }

  async evaluatePolicy(
    domain: string,
    input: Record<string, unknown>,
  ): Promise<ApiResponse<Record<string, unknown>>> {
    return this.post<Record<string, unknown>>("/policy/evaluate", {
      domain,
      input,
    });
  }

  private get<T>(path: string): Promise<ApiResponse<T>> {
    return this.doRequest<T>("GET", path);
  }

  private post<T>(path: string, body: unknown): Promise<ApiResponse<T>> {
    return this.doRequest<T>("POST", path, body);
  }

  /**
   * POST body to path and return the raw answer, over a connection that
   * proved it is this account's gateway. The tool check uses it: its verdict
   * is enforced, so the connection that carries the token also carries the
   * verdict back (GAP-0594). timeoutMs counts from the proven connection;
   * the proof has its own short bound, so it does not use up the budget.
   * status 0 means no answer, and error says why.
   */
  async postRaw(
    path: string,
    body: unknown,
    opts: { timeoutMs?: number; correlation?: Partial<CorrelationContext> } = {},
  ): Promise<RawResponse> {
    return this.sendRaw("POST", path, body, opts.correlation, opts.timeoutMs ?? this.timeoutMs);
  }

  private async doRequest<T>(
    method: string,
    path: string,
    body?: unknown,
    correlationPartial?: Partial<CorrelationContext>,
  ): Promise<ApiResponse<T>> {
    const res = await this.sendRaw(method, path, body, correlationPartial, this.timeoutMs);
    if (res.status === 0) {
      return { ok: false, error: res.error ?? "request failed", status: 0 };
    }
    if (res.status >= 200 && res.status < 300) {
      try {
        const data = res.body.length > 0 ? (JSON.parse(res.body) as T) : undefined;
        return { ok: true, data, status: res.status };
      } catch {
        return { ok: true, data: undefined, status: res.status };
      }
    }
    return { ok: false, error: res.body || `HTTP ${res.status}`, status: res.status };
  }

  private async sendRaw(
    method: string,
    path: string,
    body: unknown,
    correlationPartial: Partial<CorrelationContext> | undefined,
    timeoutMs: number,
  ): Promise<RawResponse> {
    const started = performance.now();
    const ctx = await this.resolveCorrelation(correlationPartial);
    const outboundInstance =
      this.stickyOutboundAgentInstanceId ?? ctx.agentInstanceId ?? "";
    const corrForHeaders = this.mergeObservedContext(ctx);
    const correlationHeaders = buildSidecarCorrelationHeaders(corrForHeaders, {
      outboundAgentInstanceId: outboundInstance,
    });

    const token = this.token;
    return new Promise((resolve) => {
      const url = new URL(path, this.baseUrl);
      const payload = body !== undefined ? JSON.stringify(body) : undefined;

      const headers: Record<string, string | number> = {
        "Content-Type": "application/json",
        Accept: "application/json",
        [HEADER_DEFENSECLAW_CLIENT]: "openclaw-plugin",
        "X-DefenseClaw-Connector": "openclaw",
        ...correlationHeaders,
      };
      if (token) {
        headers.Authorization = `Bearer ${token}`;
      }
      if (payload !== undefined) {
        headers["Content-Length"] = Buffer.byteLength(payload);
      }

      let settled = false;
      let deadline: ReturnType<typeof setTimeout> | undefined;
      const finish = (out: RawResponse, observed: CorrelationContext) => {
        if (settled) return;
        settled = true;
        if (deadline !== undefined) clearTimeout(deadline);
        this.logOutboundRequest?.({
          runId: observed.runId,
          sessionId: observed.sessionId,
          agentId: observed.agentId,
          status_code: out.status,
          duration_ms: Math.round(performance.now() - started),
        });
        resolve(out);
      };

      const req = this.requestImpl(
        {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname + url.search,
          method,
          timeout: timeoutMs,
          headers,
          // The connection is proven before the request is written on it: a
          // listener of another account gets the proof request only, and a
          // client with no token to prove with sends nothing (GAP-0594).
          // node:http uses createConnection only without an agent.
          agent: undefined,
          createConnection: provenCreateConnection(
            url.hostname,
            Number(url.port) || 80,
            token,
          ) as unknown as RequestOptions["createConnection"],
        },
        (res) => {
          const chunks: Buffer[] = [];
          let totalBytes = 0;

          res.on("data", (chunk: Buffer) => {
            totalBytes += chunk.length;
            if (totalBytes <= MAX_RESPONSE_BYTES) {
              chunks.push(chunk);
            }
          });

          res.on("end", () => {
            const sticky = parseStickyHeadersFromNode(res.headers);
            if (sticky.agentInstanceId) {
              this.stickyOutboundAgentInstanceId = sticky.agentInstanceId;
            }
            if (sticky.sidecarInstanceId) {
              this.sidecarInstanceIdEcho = sticky.sidecarInstanceId;
            }
            const observed = this.mergeObservedContext(ctx);
            this.onCorrelationContext?.(observed);
            finish(
              { status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf-8") },
              observed,
            );
          });

          res.on("error", (err) =>
            finish({ status: 0, body: "", error: err.message, outage: gatewayDidNotAnswer(err) }, ctx));
          // A body cut off mid-response is no answer, not a short 2xx.
          res.on("close", () => {
            if (!res.complete) finish({ status: 0, body: "", error: "response body cut off", outage: true }, ctx);
          });
        },
      );

      // The budget starts once the connection has proven itself (N9).
      req.once("socket", () => {
        deadline = setTimeout(() => {
          req.destroy();
          finish({ status: 0, body: "", error: "request timed out", outage: true }, ctx);
        }, timeoutMs);
      });
      req.on("error", (err) =>
        finish({ status: 0, body: "", error: err.message, outage: gatewayDidNotAnswer(err) }, ctx));
      req.on("timeout", () => {
        req.destroy();
        finish({ status: 0, body: "", error: "request timed out", outage: true }, ctx);
      });

      if (payload !== undefined) {
        req.write(payload);
      }
      req.end();
    });
  }
}

/** The raw answer of a DaemonClient request: status 0 when there was none. */
export interface RawResponse {
  status: number;
  body: string;
  error?: string;
  /**
   * With status 0, true when the gateway did not answer: nothing listens on
   * its port, the connection, its proof or the request timed out, or a proven
   * connection broke off. False for a listener that did not prove it is this
   * account's gateway and for a request that was never sent (GAP-0594).
   */
  outage?: boolean;
}

// A proven gateway connection that broke off before the answer. An error
// before the proof is a ListenerProofError, which says whether anything
// answered.
const BROKEN_CONNECTION_CODES = new Set([
  "ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EPIPE", "EHOSTUNREACH", "ENETUNREACH",
]);

function gatewayDidNotAnswer(err: unknown): boolean {
  if (err instanceof ListenerProofError) return err.unreachable;
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === "string" && BROKEN_CONNECTION_CODES.has(code);
}

function defaultCorrelation(): CorrelationContext {
  return { agentId: "unknown", traceId: randomUUID() };
}
