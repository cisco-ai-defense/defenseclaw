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

import { describe, it, expect, vi, beforeEach } from "vitest";

// The session header is the plugin's last-seen tool context. Only the one
// model request that follows a tool call is marked as having observed it; the
// gateway shows a tool block notice only to such a request (GAP-0644).

const { mockDaemonClient, interceptorOpts } = vi.hoisted(() => ({
  mockDaemonClient: {
    buildOutboundHeaders: vi.fn(async () => ({})),
    postRaw: vi.fn(),
    applyStickyFromHttpResponse: vi.fn(),
    getStickyAgentInstanceId: vi.fn(() => undefined),
    getEchoedSidecarInstanceId: vi.fn(() => undefined),
  },
  interceptorOpts: { getCorrelationHeaders: undefined as undefined | (() => Record<string, string>) },
}));

vi.mock("@openclaw/plugin-sdk", () => ({ definePluginEntry: (fn: unknown) => fn }));
vi.mock("../client.js", () => ({ DaemonClient: vi.fn(() => mockDaemonClient) }));
vi.mock("../policy/enforcer.js", () => ({
  PolicyEnforcer: vi.fn(() => ({
    syncFromDaemon: vi.fn(),
    evaluateSkill: vi.fn(),
    evaluateMCPServer: vi.fn(),
    block: vi.fn(),
    allow: vi.fn(),
  })),
  runSkillScan: vi.fn(),
  runPluginScan: vi.fn(),
  runCodeScan: vi.fn(),
}));
vi.mock("../scanners/mcp-scanner.js", () => ({ scanMCPServer: vi.fn() }));
vi.mock("../fetch-interceptor.js", () => ({
  createFetchInterceptor: vi.fn((opts: { getCorrelationHeaders: () => Record<string, string> }) => {
    interceptorOpts.getCorrelationHeaders = opts.getCorrelationHeaders;
    return { start: vi.fn(), stop: vi.fn() };
  }),
}));

import pluginSetup from "../index.js";

type Handler = (...args: unknown[]) => Promise<unknown> | unknown;

describe("session-bound marker on intercepted model requests (GAP-0644)", () => {
  let beforeToolCall: Handler;
  const stamp = (): Record<string, string> => interceptorOpts.getCorrelationHeaders!();

  beforeEach(() => {
    vi.clearAllMocks();
    const listeners: Record<string, Handler> = {};
    pluginSetup({
      config: { agents: { defaults: { model: { primary: "openai/gpt-4o" } } } },
      pluginConfig: {},
      on: vi.fn((event: string, handler: Handler) => {
        listeners[event] = handler;
      }),
      registerService: vi.fn(),
      registerCommand: vi.fn(),
    } as never);
    beforeToolCall = listeners.before_tool_call;
    mockDaemonClient.postRaw.mockResolvedValue({
      status: 200,
      body: JSON.stringify({ action: "allow", raw_action: "allow", severity: "NONE", reason: "", mode: "action" }),
    });
  });

  it("marks only the first model request after a tool call", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      // No tool call yet: no session, no marker.
      expect(stamp()["X-DefenseClaw-Session-Bound"]).toBeUndefined();

      await beforeToolCall({ toolName: "exec", toolCallId: "call_1", params: { command: "x" } }, { sessionKey: "sess-a", runId: "run-1" });
      const first = stamp();
      expect(first["X-DefenseClaw-Session-Id"]).toBe("sess-a");
      expect(first["X-DefenseClaw-Session-Bound"]).toBe("1");

      // A later request still names the last-seen session for correlation, but
      // the plugin has not observed it for this request.
      const later = stamp();
      expect(later["X-DefenseClaw-Session-Id"]).toBe("sess-a");
      expect(later["X-DefenseClaw-Session-Bound"]).toBeUndefined();

      // A new tool call arms the marker again.
      await beforeToolCall({ toolName: "exec", toolCallId: "call_2", params: { command: "x" } }, { sessionKey: "sess-b", runId: "run-2" });
      const second = stamp();
      expect(second["X-DefenseClaw-Session-Id"]).toBe("sess-b");
      expect(second["X-DefenseClaw-Session-Bound"]).toBe("1");
    } finally {
      log.mockRestore();
    }
  });

  it("never marks a request that has no session", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    try {
      await beforeToolCall({ toolName: "exec", toolCallId: "call_1", params: { command: "x" } }, { runId: "run-1" });
      const h = stamp();
      expect(h["X-DefenseClaw-Session-Id"]).toBeUndefined();
      expect(h["X-DefenseClaw-Session-Bound"]).toBeUndefined();
    } finally {
      log.mockRestore();
    }
  });
});
