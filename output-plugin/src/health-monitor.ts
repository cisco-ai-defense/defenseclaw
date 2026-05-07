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
 * Health monitor that periodically checks the DefenseClaw sidecar and
 * exposes an `isUnprotected` flag for the fetch interceptor to query.
 *
 * The monitor does NOT block LLM calls — it only warns.
 */

import type { OutboundSidecarRequestLog } from "./types.js";

const POLL_INTERVAL_MS = 60_000;

export interface HealthMonitorOptions {
  statusUrl: string;
  token?: string;
  pollIntervalMs?: number;
  /** Correlation headers for sidecar observability (optional). */
  buildSidecarHeaders?: () => Promise<Record<string, string>>;
  /** Sticky echo headers from the sidecar (optional). */
  onFetchResponse?: (res: Response) => void;
  /** Structured outbound request logging (optional). */
  logOutboundRequest?: (entry: OutboundSidecarRequestLog) => void;
  getLogAgentId?: () => string;
}

export class HealthMonitor {
  private readonly statusUrl: string;
  private readonly token: string;
  private readonly pollIntervalMs: number;
  private readonly buildSidecarHeaders?: () => Promise<Record<string, string>>;
  private readonly onFetchResponse?: (res: Response) => void;
  private readonly logOutboundRequest?: (entry: OutboundSidecarRequestLog) => void;
  private readonly getLogAgentId?: () => string;
  private timer: ReturnType<typeof setInterval> | null = null;
  private _unprotected = false;
  private _wasUnprotected = false;

  constructor(opts: HealthMonitorOptions) {
    this.statusUrl = opts.statusUrl;
    this.token = opts.token ?? "";
    this.pollIntervalMs = opts.pollIntervalMs ?? POLL_INTERVAL_MS;
    this.buildSidecarHeaders = opts.buildSidecarHeaders;
    this.onFetchResponse = opts.onFetchResponse;
    this.logOutboundRequest = opts.logOutboundRequest;
    this.getLogAgentId = opts.getLogAgentId;
  }

  get isUnprotected(): boolean {
    return this._unprotected;
  }

  start(): void {
    if (this.timer) return;

    // Run an initial check immediately.
    void this.check();

    this.timer = setInterval(() => void this.check(), this.pollIntervalMs);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async check(): Promise<void> {
    const started = performance.now();
    try {
      const extra = this.buildSidecarHeaders
        ? await this.buildSidecarHeaders()
        : {};
      const headers: Record<string, string> = { ...extra };
      if (this.token && !headers.Authorization) {
        headers.Authorization = `Bearer ${this.token}`;
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5_000);
      const resp = await fetch(this.statusUrl, {
        signal: controller.signal,
        headers,
      });
      clearTimeout(timeout);

      this.onFetchResponse?.(resp);

      const duration_ms = Math.round(performance.now() - started);
      this.logOutboundRequest?.({
        agentId: this.getLogAgentId?.() ?? "unknown",
        status_code: resp.status,
        duration_ms,
      });

      if (resp.ok) {
        const body = await resp.json();
        const gwState = body?.health?.gateway?.state ?? "";
        if (gwState === "running") {
          if (this._unprotected) {
            console.log("[defenseclaw] Gateway is back online. Protection restored.");
          }
          this._unprotected = false;
          this._wasUnprotected = false;
        } else {
          this.markUnprotected();
        }
      } else {
        this.markUnprotected();
      }
    } catch {
      const duration_ms = Math.round(performance.now() - started);
      this.logOutboundRequest?.({
        agentId: this.getLogAgentId?.() ?? "unknown",
        status_code: 0,
        duration_ms,
      });
      this.markUnprotected();
    }
  }

  private markUnprotected(): void {
    this._unprotected = true;
    if (!this._wasUnprotected) {
      this._wasUnprotected = true;
      console.warn(
        "[defenseclaw] WARNING: The DefenseClaw security gateway is not running. " +
          "Your prompts and responses are NOT being scanned for security threats. " +
          "Run 'defenseclaw-gateway start' to restore protection.",
      );
    }
  }

  /**
   * Returns a warning message if the sidecar is unreachable, or null if healthy.
   * The fetch interceptor can prepend this to LLM requests as a system message.
   */
  getWarningMessage(): string | null {
    if (!this._unprotected) return null;
    return (
      "[DEFENSECLAW WARNING] The DefenseClaw security gateway is not running. " +
      "Your prompts and responses are NOT being scanned for security threats. " +
      "Run 'defenseclaw-gateway start' to restore protection."
    );
  }
}
