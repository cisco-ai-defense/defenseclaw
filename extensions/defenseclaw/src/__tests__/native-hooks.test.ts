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

const { mockDaemonClient, mockOutageMode } = vi.hoisted(() => ({
  mockDaemonClient: {
    buildOutboundHeaders: vi.fn(async () => ({})),
    postRaw: vi.fn(),
    runtime: vi.fn(async () => ({ ok: true, status: 200, data: {} })),
    applyStickyFromHttpResponse: vi.fn(),
    getStickyAgentInstanceId: vi.fn(() => undefined),
    getEchoedSidecarInstanceId: vi.fn(() => undefined),
  },
  mockOutageMode: vi.fn(() => "closed"),
}));

vi.mock("../sidecar-config.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../sidecar-config.js")>()),
  loadOpenClawOutageMode: mockOutageMode,
}));
vi.mock("@openclaw/plugin-sdk", () => ({ definePluginEntry: (fn: unknown) => fn }));
vi.mock("../client.js", () => ({ DaemonClient: vi.fn(() => mockDaemonClient) }));
vi.mock("../policy/enforcer.js", () => ({
  PolicyEnforcer: vi.fn(() => ({ syncFromDaemon: vi.fn(async () => undefined) })),
  runSkillScan: vi.fn(),
  runPluginScan: vi.fn(),
  runCodeScan: vi.fn(),
}));
vi.mock("../scanners/mcp-scanner.js", () => ({ scanMCPServer: vi.fn() }));

import pluginSetup from "../index.js";
import { setRuntimeSettings } from "../sidecar-config.js";

type Handler = (...args: unknown[]) => unknown;

function setup(hookMode?: string) {
  const listeners: Record<string, Handler> = {};
  const options: Record<string, unknown> = {};
  const api = {
    config: {},
    pluginConfig: hookMode ? { hookMode } : {},
    on: vi.fn((event: string, handler: Handler, opts?: unknown) => {
      listeners[event] = handler;
      options[event] = opts;
    }),
    registerService: vi.fn(),
    registerCommand: vi.fn(),
  };
  (pluginSetup as (api: unknown) => void)(api);
  return { listeners, options };
}

const answer = (body: Record<string, unknown>) => ({ status: 200, body: JSON.stringify(body) });

describe("native hooks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockOutageMode.mockReturnValue("closed");
    setRuntimeSettings({ prompt_gate: true, inspect_timeout_ms: 5000 });
  });

  it("registers only the proxy hooks without hookMode (OpenClaw before 2026.8.35)", () => {
    const { listeners } = setup();
    expect(listeners["before_tool_call"]).toBeDefined();
    expect(listeners["before_agent_run"]).toBeUndefined();
    expect(listeners["after_tool_call"]).toBeUndefined();
  });

  it("gives the gate hooks a host budget above the verdict wait", () => {
    const { options } = setup("hybrid");
    const budget = (options["before_tool_call"] as { timeoutMs: number }).timeoutMs;
    expect(budget).toBeGreaterThanOrEqual(30_000);
    expect((options["before_agent_run"] as { timeoutMs: number }).timeoutMs).toBe(budget);
  });

  it("blocks a prompt the gateway blocks in action mode", async () => {
    const { listeners } = setup("hybrid");
    mockDaemonClient.postRaw.mockResolvedValueOnce(answer({ action: "block", severity: "HIGH", reason: "secret in prompt", mode: "action" }));
    const result = await listeners["before_agent_run"]({ prompt: "dccert-block-marker", messages: [] }, { runId: "r1", sessionKey: "s1" });
    expect(result).toMatchObject({ outcome: "block", message: expect.stringContaining("secret in prompt") });
    expect(mockDaemonClient.postRaw.mock.calls[0][0]).toBe("/api/v1/inspect/request");
    expect(mockDaemonClient.postRaw.mock.calls[0][1]).toMatchObject({ content: "dccert-block-marker", session_id: "s1" });
  });

  it("passes an observed finding and a clean prompt", async () => {
    const { listeners } = setup("hybrid");
    mockDaemonClient.postRaw.mockResolvedValueOnce(answer({ action: "allow", raw_action: "block", would_block: true, severity: "HIGH", reason: "x", mode: "observe" }));
    expect(await listeners["before_agent_run"]({ prompt: "hi", messages: [] }, {})).toBeUndefined();
    mockDaemonClient.postRaw.mockResolvedValueOnce(answer({ action: "allow", severity: "NONE", reason: "", mode: "action" }));
    expect(await listeners["before_agent_run"]({ prompt: "hi", messages: [] }, {})).toBeUndefined();
  });

  it("does nothing when the prompt gate is off", async () => {
    setRuntimeSettings({ prompt_gate: false });
    const { listeners } = setup("hybrid");
    expect(await listeners["before_agent_run"]({ prompt: "hi", messages: [] }, {})).toBeUndefined();
    expect(mockDaemonClient.postRaw).not.toHaveBeenCalled();
  });

  it("follows the outage mode only when the gateway did not answer", async () => {
    const { listeners } = setup("hybrid");
    const outage = { status: 0, body: "", error: "connect ECONNREFUSED", outage: true };
    mockOutageMode.mockReturnValue("open");
    mockDaemonClient.postRaw.mockResolvedValueOnce(outage);
    expect(await listeners["before_agent_run"]({ prompt: "hi", messages: [] }, {})).toBeUndefined();
    mockOutageMode.mockReturnValue("closed");
    mockDaemonClient.postRaw.mockResolvedValueOnce(outage);
    expect(await listeners["before_agent_run"]({ prompt: "hi", messages: [] }, {})).toMatchObject({ outcome: "block" });
    // An unproven listener stays closed even in an open tier.
    mockOutageMode.mockReturnValue("open");
    mockDaemonClient.postRaw.mockResolvedValueOnce({ status: 0, body: "", error: "listener not proven", outage: false });
    expect(await listeners["before_agent_run"]({ prompt: "hi", messages: [] }, {})).toMatchObject({ outcome: "block" });
  });

  it("feeds tool results and model output to the scans only in native mode", () => {
    const hybrid = setup("hybrid");
    expect(hybrid.listeners["after_tool_call"]).toBeUndefined();
    expect(hybrid.listeners["llm_output"]).toBeUndefined();
    const native = setup("native");
    mockDaemonClient.postRaw.mockResolvedValue(answer({ action: "allow", severity: "NONE", reason: "", mode: "observe" }));
    native.listeners["after_tool_call"]({ toolName: "exec", params: {}, result: { stdout: "ok" } }, { sessionKey: "s" });
    native.listeners["llm_output"]({ runId: "r", sessionId: "s", provider: "p", model: "m", assistantTexts: ["a", "b"] }, {});
    const paths = mockDaemonClient.postRaw.mock.calls.map((c) => c[0]);
    expect(paths).toEqual(["/api/v1/inspect/tool-response", "/api/v1/inspect/response"]);
    expect(mockDaemonClient.postRaw.mock.calls[1][1]).toMatchObject({ content: "a\nb", model: "m" });
  });
});
