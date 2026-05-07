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

import type { IncomingHttpHeaders } from "node:http";
import type { CorrelationContext } from "./types.js";

/** Single module for DefenseClaw↔sidecar HTTP header names (no raw strings at call sites). */
export const HEADER_HTTP_CONTENT_TYPE = "Content-Type";
export const HEADER_DEFENSECLAW_RUN_ID = "X-DefenseClaw-Run-Id";
export const HEADER_DEFENSECLAW_SESSION_ID = "X-DefenseClaw-Session-Id";
export const HEADER_DEFENSECLAW_TRACE_ID = "X-DefenseClaw-Trace-Id";
export const HEADER_DEFENSECLAW_AGENT_ID = "X-DefenseClaw-Agent-Id";
export const HEADER_DEFENSECLAW_AGENT_INSTANCE_ID = "X-DefenseClaw-Agent-Instance-Id";
export const HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID = "X-DefenseClaw-Sidecar-Instance-Id";
export const HEADER_DEFENSECLAW_AGENT_NAME = "X-DefenseClaw-Agent-Name";
export const HEADER_DEFENSECLAW_POLICY_ID = "X-DefenseClaw-Policy-Id";
export const HEADER_DEFENSECLAW_CLIENT = "X-DefenseClaw-Client";

export interface BuildCorrelationHeadersOptions {
  /**
   * Outbound value for {@link HEADER_DEFENSECLAW_AGENT_INSTANCE_ID}.
   * Prefer the sidecar-echoed id when present so both ends converge.
   */
  outboundAgentInstanceId: string;
}

function setIfPresent(
  out: Record<string, string>,
  headerName: string,
  value: string | undefined,
): void {
  if (value === undefined || value === "") return;
  out[headerName] = value;
}

/**
 * Builds correlation headers for outbound sidecar HTTP requests.
 */
export function buildSidecarCorrelationHeaders(
  ctx: CorrelationContext,
  opts: BuildCorrelationHeadersOptions,
): Record<string, string> {
  const out: Record<string, string> = {};
  setIfPresent(out, HEADER_DEFENSECLAW_RUN_ID, ctx.runId);
  setIfPresent(out, HEADER_DEFENSECLAW_SESSION_ID, ctx.sessionId);
  setIfPresent(out, HEADER_DEFENSECLAW_TRACE_ID, ctx.traceId);
  setIfPresent(out, HEADER_DEFENSECLAW_AGENT_ID, ctx.agentId);
  setIfPresent(out, HEADER_DEFENSECLAW_AGENT_NAME, ctx.agentName);
  setIfPresent(out, HEADER_DEFENSECLAW_POLICY_ID, ctx.policyId);
  setIfPresent(
    out,
    HEADER_DEFENSECLAW_AGENT_INSTANCE_ID,
    opts.outboundAgentInstanceId,
  );
  setIfPresent(out, HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID, ctx.sidecarInstanceId);
  return out;
}

export interface ParsedStickyResponseHeaders {
  agentInstanceId?: string;
  sidecarInstanceId?: string;
}

function normalizeHeaderValue(
  value: IncomingHttpHeaders[string],
): string | undefined {
  if (value === undefined) return undefined;
  if (Array.isArray(value)) return value[0];
  return value;
}

/**
 * Reads sticky / echo headers from a sidecar response (Node or Fetch).
 */
export function parseStickyHeadersFromNode(
  headers: IncomingHttpHeaders,
): ParsedStickyResponseHeaders {
  return {
    agentInstanceId: normalizeHeaderValue(
      headers[HEADER_DEFENSECLAW_AGENT_INSTANCE_ID.toLowerCase()],
    ),
    sidecarInstanceId: normalizeHeaderValue(
      headers[HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID.toLowerCase()],
    ),
  };
}

/** Fetch `Headers` / `Headers`-like (get is case-insensitive). */
export function parseStickyHeadersFromWebHeaders(headers: {
  get(name: string): string | null;
}): ParsedStickyResponseHeaders {
  return {
    agentInstanceId: headers.get(HEADER_DEFENSECLAW_AGENT_INSTANCE_ID) ?? undefined,
    sidecarInstanceId:
      headers.get(HEADER_DEFENSECLAW_SIDECAR_INSTANCE_ID) ?? undefined,
  };
}
