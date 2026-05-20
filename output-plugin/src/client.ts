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
import { request as httpRequest } from "node:http";
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
  DaemonStatus,
  AdmissionResult,
  CorrelationContext,
  OutboundSidecarRequestLog,
} from "./types.js";
import { loadSidecarConfig } from "./sidecar-config.js";

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
  private readonly token: string;
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
    this.token = opts?.token ?? cfg.token;
    this.timeoutMs = opts?.timeoutMs ?? REQUEST_TIMEOUT_MS;
    this.requestImpl = opts?.requestImpl ?? httpRequest;
    this.getCorrelation = opts?.getCorrelation ?? defaultCorrelation;
    this.correlationOverride = opts?.correlationOverride ?? {};
    this.identityReady = opts?.identityReady ?? Promise.resolve();
    this.logOutboundRequest = opts?.logOutboundRequest;
    this.onCorrelationContext = opts?.onCorrelationContext;
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
    h[HEADER_DEFENSECLAW_CLIENT] = "openclaw-clawhub-plugin";
    if (this.token) {
      h.Authorization = `Bearer ${this.token}`;
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

  async status(): Promise<ApiResponse<DaemonStatus>> {
    return this.get<DaemonStatus>("/status");
  }

  async submitScanResult(result: ScanResult): Promise<ApiResponse<void>> {
    return this.post<void>("/scan/result", result);
  }

  async block(
    targetType: string,
    targetName: string,
    reason: string,
  ): Promise<ApiResponse<void>> {
    return this.post<void>("/enforce/block", {
      target_type: targetType,
      target_name: targetName,
      reason,
    });
  }

  async allow(
    targetType: string,
    targetName: string,
    reason: string,
  ): Promise<ApiResponse<void>> {
    return this.post<void>("/enforce/allow", {
      target_type: targetType,
      target_name: targetName,
      reason,
    });
  }

  async unblock(
    targetType: string,
    targetName: string,
  ): Promise<ApiResponse<void>> {
    return this.delete<void>("/enforce/block", {
      target_type: targetType,
      target_name: targetName,
    });
  }

  async listAlerts(limit = 50): Promise<ApiResponse<AdmissionResult[]>> {
    return this.get<AdmissionResult[]>(`/alerts?limit=${limit}`);
  }

  async listSkills(): Promise<ApiResponse<string[]>> {
    return this.get<string[]>("/skills");
  }

  async listMCPs(): Promise<ApiResponse<string[]>> {
    return this.get<string[]>("/mcps");
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

  private delete<T>(path: string, body: unknown): Promise<ApiResponse<T>> {
    return this.doRequest<T>("DELETE", path, body);
  }

  private async doRequest<T>(
    method: string,
    path: string,
    body?: unknown,
    correlationPartial?: Partial<CorrelationContext>,
  ): Promise<ApiResponse<T>> {
    const started = performance.now();
    const ctx = await this.resolveCorrelation(correlationPartial);
    const outboundInstance =
      this.stickyOutboundAgentInstanceId ?? ctx.agentInstanceId ?? "";
    const corrForHeaders = this.mergeObservedContext(ctx);
    const correlationHeaders = buildSidecarCorrelationHeaders(corrForHeaders, {
      outboundAgentInstanceId: outboundInstance,
    });

    return new Promise((resolve) => {
      const url = new URL(path, this.baseUrl);
      const payload = body !== undefined ? JSON.stringify(body) : undefined;

      const headers: Record<string, string | number> = {
        "Content-Type": "application/json",
        Accept: "application/json",
        [HEADER_DEFENSECLAW_CLIENT]: "openclaw-clawhub-plugin",
        ...correlationHeaders,
      };
      if (this.token) {
        headers.Authorization = `Bearer ${this.token}`;
      }
      if (payload !== undefined) {
        headers["Content-Length"] = Buffer.byteLength(payload);
      }

      const req = this.requestImpl(
        {
          hostname: url.hostname,
          port: url.port,
          path: url.pathname + url.search,
          method,
          timeout: this.timeoutMs,
          headers,
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
            const raw = Buffer.concat(chunks).toString("utf-8");
            const status = res.statusCode ?? 0;
            const durationMs = Math.round(performance.now() - started);

            const sticky = parseStickyHeadersFromNode(res.headers);
            if (sticky.agentInstanceId) {
              this.stickyOutboundAgentInstanceId = sticky.agentInstanceId;
            }
            if (sticky.sidecarInstanceId) {
              this.sidecarInstanceIdEcho = sticky.sidecarInstanceId;
            }

            const observed = this.mergeObservedContext(ctx);
            this.onCorrelationContext?.(observed);

            this.logOutboundRequest?.({
              runId: observed.runId,
              sessionId: observed.sessionId,
              agentId: observed.agentId,
              status_code: status,
              duration_ms: durationMs,
            });

            if (status >= 200 && status < 300) {
              try {
                const data = raw.length > 0 ? (JSON.parse(raw) as T) : undefined;
                resolve({ ok: true, data, status });
              } catch {
                resolve({ ok: true, data: undefined, status });
              }
            } else {
              resolve({ ok: false, error: raw || `HTTP ${status}`, status });
            }
          });

          res.on("error", (err) => {
            const durationMs = Math.round(performance.now() - started);
            this.logOutboundRequest?.({
              runId: ctx.runId,
              sessionId: ctx.sessionId,
              agentId: ctx.agentId,
              status_code: 0,
              duration_ms: durationMs,
            });
            resolve({ ok: false, error: err.message, status: 0 });
          });
        },
      );

      req.on("error", (err) => {
        const durationMs = Math.round(performance.now() - started);
        this.logOutboundRequest?.({
          runId: ctx.runId,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          status_code: 0,
          duration_ms: durationMs,
        });
        resolve({ ok: false, error: err.message, status: 0 });
      });

      req.on("timeout", () => {
        req.destroy();
        const durationMs = Math.round(performance.now() - started);
        this.logOutboundRequest?.({
          runId: ctx.runId,
          sessionId: ctx.sessionId,
          agentId: ctx.agentId,
          status_code: 0,
          duration_ms: durationMs,
        });
        resolve({ ok: false, error: "request timed out", status: 0 });
      });

      if (payload !== undefined) {
        req.write(payload);
      }
      req.end();
    });
  }
}

function defaultCorrelation(): CorrelationContext {
  return { agentId: "unknown", traceId: randomUUID() };
}
