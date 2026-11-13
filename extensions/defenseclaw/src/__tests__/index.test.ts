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

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { readFileSync } from "node:fs";
import type { ScanResult } from "../types.js";
import { HealthMonitor } from "../health-monitor.js";
import { MODEL_OUTAGE_WARNING } from "../fetch-interceptor.js";

// --- Hoisted mocks (available before module-level vi.mock factories) ---

const { mockDaemonClient, mockEnforcer, mockRunSkillScan, mockRunPluginScan, mockRunCodeScan, mockScanMCPServer, mockOutageMode } =
  vi.hoisted(() => ({
    mockDaemonClient: {
      buildOutboundHeaders: vi.fn(async () => ({})),
      postRaw: vi.fn(),
      applyStickyFromHttpResponse: vi.fn(),
      getStickyAgentInstanceId: vi.fn(() => undefined),
      getEchoedSidecarInstanceId: vi.fn(() => undefined),
    },
    mockEnforcer: {
      syncFromDaemon: vi.fn(),
      evaluateSkill: vi.fn(),
      evaluateMCPServer: vi.fn(),
      block: vi.fn(),
      allow: vi.fn(),
    },
    mockRunSkillScan: vi.fn(),
    mockRunPluginScan: vi.fn(),
    mockRunCodeScan: vi.fn(),
    mockScanMCPServer: vi.fn(),
    mockOutageMode: vi.fn((_tool?: { args?: Record<string, unknown>; cwd?: string }) => "closed"),
  }));

vi.mock("../sidecar-config.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../sidecar-config.js")>()),
  loadOpenClawOutageMode: mockOutageMode,
}));

vi.mock("@openclaw/plugin-sdk", () => ({
  definePluginEntry: (fn: unknown) => fn,
}));

vi.mock("../client.js", () => ({
  DaemonClient: vi.fn(() => mockDaemonClient),
}));

vi.mock("../policy/enforcer.js", () => ({
  PolicyEnforcer: vi.fn(() => mockEnforcer),
  runSkillScan: mockRunSkillScan,
  runPluginScan: mockRunPluginScan,
  runCodeScan: mockRunCodeScan,
}));

vi.mock("../scanners/mcp-scanner.js", () => ({
  scanMCPServer: mockScanMCPServer,
}));

// --- Helpers ---

/** A DaemonClient.postRaw answer: the tool check runs over its proven connection (GAP-0594). */
function rawAnswer(body: string, init?: { status?: number; headers?: unknown }): { status: number; body: string } {
  return { status: init?.status ?? 200, body };
}

type EventHandler = (...args: unknown[]) => Promise<unknown> | unknown;

function createMockContext() {
  const listeners: Record<string, EventHandler> = {};
  const commands: Record<string, { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }> = {};

  const api = {
    config: {
      agents: {
        defaults: {
          model: { primary: "openai/gpt-4o" },
        },
      },
    },
    pluginConfig: {},
    on: vi.fn((event: string, handler: EventHandler) => {
      listeners[event] = handler;
    }),
    registerService: vi.fn(),
    registerCommand: vi.fn((def: { name: string; handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }) => {
      commands[def.name] = def;
    }),
  };

  return {
    ctx: { api },
    listeners,
    commands,
  };
}

function makeScanResult(overrides?: Partial<ScanResult>): ScanResult {
  return {
    scanner: "test-scanner",
    target: "/test",
    timestamp: new Date().toISOString(),
    findings: [],
    ...overrides,
  };
}

// --- Import the plugin (mock of definePluginEntry returns the raw callback) ---

import pluginSetup from "../index.js";
import { DaemonClient } from "../client.js";

// --- Tests ---

describe("DefenseClaw OpenClaw Plugin", () => {
  let listeners: Record<string, EventHandler>;
  let commands: Record<string, { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }>;
  let hostApi: ReturnType<typeof createMockContext>["ctx"]["api"];

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN;
    mockOutageMode.mockReturnValue("closed");
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1GuardrailPatch;
    mockEnforcer.syncFromDaemon.mockResolvedValue(undefined);
    mockEnforcer.block.mockResolvedValue(undefined);
    mockEnforcer.allow.mockResolvedValue(undefined);
    mockDaemonClient.buildOutboundHeaders.mockResolvedValue({});
    mockDaemonClient.applyStickyFromHttpResponse.mockReturnValue(undefined);
    mockDaemonClient.getStickyAgentInstanceId.mockReturnValue(undefined);
    mockDaemonClient.getEchoedSidecarInstanceId.mockReturnValue(undefined);

    const mock = createMockContext();
    hostApi = mock.ctx.api;
    listeners = mock.listeners;
    commands = mock.commands;
    (pluginSetup as (api: unknown) => void)(mock.ctx.api);
  });

  // ─── Registration ───

  describe("registration", () => {
    it("registers before_tool_call as event listener", () => {
      expect(listeners.before_tool_call).toBeTypeOf("function");
    });

    it("registers scan, block, allow commands", () => {
      expect(commands["scan"]).toBeDefined();
      expect(commands["block"]).toBeDefined();
      expect(commands["allow"]).toBeDefined();
    });

    it("puts the saved open outage warning in the agent prompt", async () => {
      const down = vi.spyOn(HealthMonitor.prototype, "isGatewayDown", "get").mockReturnValue(true);
      const refresh = vi.spyOn(HealthMonitor.prototype, "refresh").mockResolvedValue();
      const warning = vi.spyOn(HealthMonitor.prototype, "getWarningMessage")
        .mockReturnValue("[DEFENSECLAW WARNING] Model calls continue without inspection.");
      try {
        mockOutageMode.mockReturnValue("open");
        await expect(listeners.before_prompt_build()).resolves.toEqual({
          prependContext: expect.stringContaining("continue without inspection"),
        });
        mockOutageMode.mockReturnValue("closed");
        await expect(listeners.before_prompt_build()).resolves.toBeUndefined();
      } finally {
        down.mockRestore();
        refresh.mockRestore();
        warning.mockRestore();
      }
    });
  });

  // GAP-0177: the text of a message call can sit in any string field.
  describe("before_tool_call message text", () => {
    const ctx = { sessionKey: "agent:main:main", runId: "run-1", toolName: "message" };
    const allow = () => rawAnswer(JSON.stringify({ action: "allow", severity: "NONE", reason: "", mode: "action" }));
    const sent = (): Record<string, unknown> => mockDaemonClient.postRaw.mock.calls[0][1] as Record<string, unknown>;

    it.each([
      ["content", { to: "+1", content: "hello one" }],
      ["body", { to: "+1", body: "hello one" }],
      ["text", { to: "+1", text: "hello one" }],
      ["message", { to: "+1", message: "hello one" }],
      ["nested blocks", { to: "+1", blocks: [{ type: "text", text: "hello one" }] }],
    ])("inspects the text in %s as an outbound message", async (_name, params) => {
      mockDaemonClient.postRaw.mockResolvedValue(allow());
      await listeners.before_tool_call({ toolName: "message", params }, ctx);
      expect(mockDaemonClient.postRaw).toHaveBeenCalledTimes(1);
      expect(sent()).toMatchObject({ tool: "message", content: "hello one", direction: "outbound", args: params });
    });

    it("blocks an outbound message whose secret is not in content or body", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer(JSON.stringify({ action: "block", severity: "HIGH", reason: "secret", mode: "action" })),
      );
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        const result = await listeners.before_tool_call(
          { toolName: "message", params: { to: "+1", text: "token for the demo account" } },
          ctx,
        );
        expect(result).toMatchObject({ block: true, blockReason: expect.stringContaining("outbound blocked") });
      } finally {
        log.mockRestore();
      }
    });

    it("sends a call with no text to the generic inspection instead of skipping it", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(allow());
      const params = { action: "send", to: "+1", silent: true, count: null };
      await listeners.before_tool_call({ toolName: "message", toolCallId: "call_9", params }, ctx);
      expect(mockDaemonClient.postRaw).toHaveBeenCalledTimes(1);
      const body = sent();
      expect(body).toMatchObject({ tool: "message", args: params, tool_call_id: "call_9" });
      expect(body).not.toHaveProperty("content");
      expect(body).not.toHaveProperty("direction");
    });

    it("cuts an attachment over the body limit down to its descriptor and says the call is partial (GAP-0356)", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(allow());
      const params = { to: "+1", message: "photo", buffer: "AAEC".repeat((4 << 20) / 4) };
      await listeners.before_tool_call({ toolName: "message", params }, ctx);
      expect(mockDaemonClient.postRaw).toHaveBeenCalledTimes(1);
      const body = sent();
      expect(Buffer.byteLength(JSON.stringify(body))).toBeLessThan(1 << 20);
      expect(body).toMatchObject({ tool: "message", content: expect.stringContaining("photo"), args_partial: true });
      expect((body.args as Record<string, string>).buffer).toMatch(/^\[attachment bytes not sent: 4194304 characters/);
    });

    it("sends a message call with no params at all", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(allow());
      await listeners.before_tool_call({ toolName: "message" }, ctx);
      expect(mockDaemonClient.postRaw).toHaveBeenCalledTimes(1);
    });
  });

  describe("before_tool_call approvals", () => {
    it("uses the shared inspect contract for every known action and severity (GAP-0609)", async () => {
      const contract = JSON.parse(readFileSync(
        new URL("../../../../schemas/inspect-tool-verdict.json", import.meta.url), "utf8",
      )) as {
        properties: { action: { enum: string[] }; mode: { enum: string[] } };
        $defs: { knownSeverity: { enum: string[] } };
      };
      expect(contract.properties.mode.enum).toEqual(["action", "observe"]);
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        for (const action of contract.properties.action.enum) {
          for (const rawAction of contract.properties.action.enum) {
            for (const severity of contract.$defs.knownSeverity.enum) {
              mockDaemonClient.postRaw.mockResolvedValueOnce(rawAnswer(JSON.stringify({
                action, raw_action: rawAction, severity, reason: "contract sample", mode: "action",
              })));
              const result = await listeners.before_tool_call(
                { toolName: "exec", params: { command: "echo ok" } },
                { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
              );
              if (action === "block") expect(result).toMatchObject({ block: true });
              else if (action === "confirm") expect(result).toHaveProperty("requireApproval");
              else expect(result).toBeUndefined();
            }
          }
        }
      } finally {
        warn.mockRestore();
        log.mockRestore();
      }
    });

    it("keeps a future informational severity from changing an explicit allow", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(rawAnswer(JSON.stringify({
        action: "allow", raw_action: "future-decision", severity: "FUTURE_LABEL",
        reason: "new informational label", mode: "action",
      })));
      await expect(listeners.before_tool_call(
        { toolName: "exec", params: { command: "echo ok" } },
        { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
      )).resolves.toBeUndefined();
    });

    it("honors the gateway's degraded-audit allow and shows its warning (GAP-0609)", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer(JSON.stringify({
          action: "allow",
          raw_action: "alert",
          severity: "WARN",
          reason: "DefenseClaw audit is degraded: the record could not be written.",
          mode: "action",
        })),
      );
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        const result = await listeners.before_tool_call(
          { toolName: "exec", params: { command: "echo ok" } },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
        );
        expect(result).toBeUndefined();
        expect(warn).toHaveBeenCalledWith(expect.stringContaining("audit is degraded"));
      } finally {
        warn.mockRestore();
      }
    });

    it("keeps the healthy allow and the strict audit block", async () => {
      const call = () => listeners.before_tool_call(
        { toolName: "exec", params: { command: "echo ok" } },
        { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
      );
      mockDaemonClient.postRaw.mockResolvedValueOnce(rawAnswer(JSON.stringify({
        action: "allow", raw_action: "allow", severity: "NONE", reason: "", mode: "action",
      })));
      await expect(call()).resolves.toBeUndefined();

      mockDaemonClient.postRaw.mockResolvedValueOnce(rawAnswer(JSON.stringify({
        action: "block", raw_action: "block", severity: "HIGH",
        reason: "DefenseClaw could not write the audit record.", mode: "action",
      })));
      await expect(call()).resolves.toMatchObject({
        block: true,
        blockReason: expect.stringContaining("could not write the audit record"),
      });
    });

    it("shows the degraded-audit warning for an allowed message tool", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(rawAnswer(JSON.stringify({
        action: "allow", raw_action: "alert", severity: "WARN",
        reason: "DefenseClaw audit is degraded: the record could not be written.", mode: "action",
      })));
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      try {
        await expect(listeners.before_tool_call(
          { toolName: "message", params: { to: "team@example.test", content: "status update" } },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "message" },
        )).resolves.toBeUndefined();
        expect(warn).toHaveBeenCalledWith(expect.stringContaining("audit is degraded"));
      } finally {
        warn.mockRestore();
      }
    });

    it("sends the call id with the check and leaves the block reason as it was (GAP-0644)", async () => {
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        const ctx = { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" };
        const block = rawAnswer(JSON.stringify({
          action: "block", raw_action: "block", severity: "HIGH", reason: "protected write", mode: "action",
        }));
        const sentBody = () => mockDaemonClient.postRaw.mock.calls.at(-1)![1] as Record<string, unknown>;

        // The reason the model sees carries nothing the gateway added.
        mockDaemonClient.postRaw.mockResolvedValue(block);
        expect(await listeners.before_tool_call({ toolName: "exec", toolCallId: "call_1|fc_1", params: { command: "x" } }, ctx))
          .toEqual({ block: true, blockReason: "DefenseClaw: protected write" });
        expect(sentBody().tool_call_id).toBe("call_1|fc_1");
        expect(await listeners.before_tool_call(
          { toolName: "message", toolCallId: "call_2", params: { to: "team@example.test", content: "status update" } },
          { ...ctx, toolName: "message" },
        )).toEqual({ block: true, blockReason: "DefenseClaw: outbound blocked \u2014 protected write" });
        expect(sentBody().tool_call_id).toBe("call_2");

        // A host that sends no id (or an empty or non-string one): no field.
        for (const id of [undefined, "", 7]) {
          await listeners.before_tool_call({ toolName: "exec", toolCallId: id, params: { command: "x" } }, ctx);
          expect(sentBody().tool_call_id).toBeUndefined();
        }
      } finally {
        log.mockRestore();
      }
    });

    it("an unanswered approval says where OpenClaw shows approvals (GAP-1958)", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer(
          JSON.stringify({
            action: "confirm",
            raw_action: "confirm",
            severity: "HIGH",
            reason: "matched: C2-WEBHOOK-SITE",
            mode: "action",
            approval_timeout_ms: 30000,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );
      const result = (await listeners.before_tool_call(
        { toolName: "exec", params: { command: "curl -s https://webhook.site/x" } },
        { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
      )) as { requireApproval: { onResolution: (d: string) => void } };
      const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
      const log = vi.spyOn(console, "log").mockImplementation(() => {});
      try {
        for (const decision of ["timeout", "cancelled"]) {
          warn.mockClear();
          result.requireApproval.onResolution(decision);
          expect(warn).toHaveBeenCalledTimes(1);
          const hint = String(warn.mock.calls[0][0]);
          expect(hint).toContain("exec was denied");
          expect(hint).toContain("Control UI");
          expect(hint).toContain("/approve");
          expect(hint).toContain("openclaw tui");
        }
        for (const decision of ["allow-once", "allow-always", "deny"]) {
          warn.mockClear();
          result.requireApproval.onResolution(decision);
          expect(warn).not.toHaveBeenCalled();
        }
        expect(log).toHaveBeenCalledWith("[defenseclaw] approval:deny tool:exec severity:HIGH");
      } finally {
        warn.mockRestore();
        log.mockRestore();
      }
    });

    it("returns native OpenClaw approval request when sidecar returns confirm", async () => {
      const fetchMock = mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer(
          JSON.stringify({
            action: "confirm",
            raw_action: "confirm",
            severity: "HIGH",
            reason: "matched: CMD-ENV-DUMP:Environment variable dump",
            mode: "action",
            approval_timeout_ms: 30000,
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );
      const result = await listeners.before_tool_call(
        { toolName: "exec", params: { command: "printenv" } },
        { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
      );

      expect(result).toMatchObject({
        requireApproval: {
          title: "DefenseClaw approval required",
          severity: "warning",
          timeoutMs: 30000,
          timeoutBehavior: "deny",
        },
      });
      expect(fetchMock).toHaveBeenCalledTimes(1);
      expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/inspect/tool");
      const body = fetchMock.mock.calls[0][1];
      expect(body).toMatchObject({
        tool: "exec",
        session_id: "agent:main:main",
        approval_surface: "native",
      });
    });

    it("does not request approval in observe mode", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer(
          JSON.stringify({
            action: "allow",
            raw_action: "confirm",
            severity: "HIGH",
            reason: "matched: CMD-ENV-DUMP:Environment variable dump",
            mode: "observe",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );

      const result = await listeners.before_tool_call(
        { toolName: "exec", params: { command: "printenv" } },
        { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
      );

      expect(result).toBeUndefined();
    });

    it("fails closed on structurally invalid allow JSON", async () => {
      mockDaemonClient.postRaw.mockImplementation(async () =>
        rawAnswer(JSON.stringify({ action: "allow" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );

      await expect(
        listeners.before_tool_call(
          { toolName: "exec", params: { command: "printenv" } },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
        ),
      ).resolves.toMatchObject({
        block: true,
        blockReason: expect.stringContaining("sidecar returned invalid verdict"),
      });

      await expect(
        listeners.before_tool_call(
          {
            toolName: "message",
            params: { to: "security@example.test", content: "status update" },
          },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
        ),
      ).resolves.toMatchObject({
        block: true,
        blockReason: expect.stringContaining("sidecar returned invalid verdict"),
      });
    });

    it("fails closed on malformed JSON even when the saved outage mode is open", async () => {
      mockOutageMode.mockReturnValue("open");
      mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer("{not-json", {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );

      await expect(
        listeners.before_tool_call(
          { toolName: "exec", params: { command: "printenv" } },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
        ),
      ).resolves.toMatchObject({
        block: true,
        blockReason: expect.stringContaining("sidecar returned malformed verdict"),
      });
    });

    it("the saved open mode allows a timed-out verdict body with a warning", async () => {
      mockOutageMode.mockReturnValue("open");
      // DaemonClient reports a timeout on the proven connection as an outage
      // (listener-proof.test.ts covers the transport).
      mockDaemonClient.postRaw.mockResolvedValue({ status: 0, body: "", error: "request timed out", outage: true });

      await expect(
        listeners.before_tool_call(
          { toolName: "exec", params: { command: "printenv" } },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
        ),
      ).resolves.toBeUndefined();
    });

    it("runs an ordinary tool during a default-tier outage and adds the warning to its result", async () => {
      mockOutageMode.mockReturnValue("open");
      // Nothing listens on the gateway port: DaemonClient reports an outage.
      mockDaemonClient.postRaw.mockResolvedValue({
        status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
      });
      const event = { toolName: "exec", toolCallId: "call-outage", params: { command: "date" } };
      const ctx = { sessionKey: "agent:main:main", runId: "run-outage", toolName: "exec", toolCallId: "call-outage" };

      await expect(listeners.before_tool_call(event, ctx)).resolves.toBeUndefined();
      const result = listeners.tool_result_persist(
        { toolName: "exec", toolCallId: "call-outage", message: { role: "toolResult", content: [{ type: "text", text: "today" }] } },
        { sessionKey: ctx.sessionKey, toolCallId: "call-outage" },
      ) as { message: { content: Array<{ text: string }> } };
      expect(result.message.content[0].text).toBe("today");
      expect(result.message.content[1].text).toContain("DefenseClaw warning:");
      expect(result.message.content[1].text).toContain("without inspection");
    });

    it("resolves outage targets from the agent workspace and relative tool workdir", async () => {
      (hostApi.config.agents.defaults as Record<string, unknown>).workspace = "/tmp/openclaw-agent-workspace";
      mockOutageMode.mockImplementation((tool) =>
        tool?.cwd === "/tmp/openclaw-agent-workspace" ? "protected" : "open");
      mockDaemonClient.postRaw.mockResolvedValue({
        status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
      });
      for (const workdir of [undefined, "../.defenseclaw"]) {
        const params = { command: "printf x >> config.yaml", ...(workdir ? { workdir } : {}) };
        await expect(listeners.before_tool_call(
          { toolName: "exec", params },
          { agentId: "main", sessionKey: "agent:main:main", toolName: "exec" },
        )).resolves.toMatchObject({ block: true });
        expect(mockOutageMode).toHaveBeenLastCalledWith({ name: "exec", args: params, cwd: "/tmp/openclaw-agent-workspace" });
      }

      mockOutageMode.mockImplementation((tool) =>
        tool?.cwd === "/tmp/openclaw-agent-workspace" ? "open" : "protected");
      await expect(listeners.before_tool_call(
        { toolName: "exec", params: { command: "printf x >> notes.txt" } },
        { agentId: "main", toolName: "exec" },
      )).resolves.toBeUndefined();
    });

    it("uses the selected agent's configured workspace during an outage", async () => {
      (hostApi.config.agents as Record<string, unknown>).list = [
        { id: "main", default: true, workspace: "/tmp/openclaw-main" },
        { id: "research", workspace: "/tmp/openclaw-research" },
      ];
      mockOutageMode.mockReturnValue("open");
      mockDaemonClient.postRaw.mockResolvedValue({
        status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
      });
      await listeners.before_tool_call(
        { toolName: "exec", params: { command: "date" } },
        { agentId: "research", sessionKey: "agent:research:main", toolName: "exec" },
      );
      expect(mockOutageMode).toHaveBeenLastCalledWith({
        name: "exec", args: { command: "date" }, cwd: "/tmp/openclaw-research",
      });
    });

    it("uses OpenClaw's normalized agent id and home-relative workspace", async () => {
      vi.stubEnv("OPENCLAW_HOME", "~/openclaw-home");
      try {
        (hostApi.config.agents as Record<string, unknown>).list = [
          { id: "Research Team", workspace: "~/agent-workspace" },
        ];
        mockOutageMode.mockReturnValue("open");
        mockDaemonClient.postRaw.mockResolvedValue({
          status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
        });
        await listeners.before_tool_call(
          { toolName: "exec", params: { command: "date" } },
          { agentId: "research-team", toolName: "exec" },
        );
        const osHome = process.env.HOME?.trim() || process.env.USERPROFILE?.trim() || homedir();
        expect(mockOutageMode).toHaveBeenLastCalledWith({
          name: "exec", args: { command: "date" },
          cwd: resolve(osHome, "openclaw-home", "agent-workspace"),
        });
      } finally {
        vi.unstubAllEnvs();
      }
    });

    it("uses the legacy state directory for an unconfigured secondary agent", async () => {
      const home = mkdtempSync(join(tmpdir(), "openclaw-workspace-"));
      mkdirSync(join(home, ".clawdbot"));
      vi.stubEnv("OPENCLAW_HOME", home);
      vi.stubEnv("OPENCLAW_STATE_DIR", "");
      try {
        mockOutageMode.mockReturnValue("open");
        mockDaemonClient.postRaw.mockResolvedValue({
          status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
        });
        await listeners.before_tool_call(
          { toolName: "exec", params: { command: "date" } },
          { agentId: "research", toolName: "exec" },
        );
        expect(mockOutageMode).toHaveBeenLastCalledWith({
          name: "exec", args: { command: "date" },
          cwd: join(home, ".clawdbot", "workspace-research"),
        });
      } finally {
        vi.unstubAllEnvs();
        rmSync(home, { recursive: true, force: true });
      }
    });

    it.each([
      "printf x >> ~/.defenseclaw/config.yaml",
      `printf x >> "$HOME/.defenseclaw/config.yaml"`,
    ])("keeps a protected target closed during an open outage: %s", async (command) => {
      mockOutageMode.mockImplementation((tool) =>
        tool?.args?.command === command ? "protected" : "open");
      mockDaemonClient.postRaw.mockResolvedValue({
        status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
      });
      await expect(listeners.before_tool_call(
        { toolName: "exec", params: { command } },
        { sessionKey: "agent:main:main", toolName: "exec" },
      )).resolves.toMatchObject({ block: true, blockReason: expect.stringContaining("protected state") });
    });

    it("uses the saved open mode when the sidecar connection resets", async () => {
      mockOutageMode.mockReturnValue("open");
      // The proven connection broke off before the verdict.
      mockDaemonClient.postRaw.mockResolvedValue({ status: 0, body: "", error: "socket hang up", outage: true });

      await expect(listeners.before_tool_call(
        { toolName: "exec", params: { command: "date" } },
        { sessionKey: "agent:main:main", toolName: "exec" },
      )).resolves.toBeUndefined();
    });

    it("keeps strict and managed outage mode closed even with the old environment setting", async () => {
      mockOutageMode.mockReturnValue("closed");
      process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN = "1";
      mockDaemonClient.postRaw.mockResolvedValue({
        status: 0, body: "", error: "connect ECONNREFUSED 127.0.0.1:18970", outage: true,
      });
      await expect(listeners.before_tool_call(
        { toolName: "exec", toolCallId: "call-closed", params: { command: "date" } },
        { sessionKey: "agent:main:main", toolName: "exec", toolCallId: "call-closed" },
      )).resolves.toMatchObject({ block: true });
      expect(listeners.tool_result_persist(
        { toolName: "exec", toolCallId: "call-closed", message: { role: "toolResult", content: [] } },
        { toolCallId: "call-closed" },
      )).toBeUndefined();
    });

    it("blocks a check whose listener did not prove it is the gateway, in every saved mode", async () => {
      // A listener answered without a valid proof (or there was no token or a
      // non-loopback gateway.host): that is not an outage (GAP-0594).
      for (const mode of ["open", "closed"]) {
        mockOutageMode.mockReturnValue(mode);
        mockDaemonClient.postRaw.mockResolvedValue({
          status: 0, body: "", outage: false,
          error: "the listener on 127.0.0.1:18970 did not prove it is the DefenseClaw gateway; nothing was sent to it",
        });
        await expect(listeners.before_tool_call(
          { toolName: "exec", toolCallId: `call-unproven-${mode}`, params: { command: "date" } },
          { sessionKey: "agent:main:main", toolName: "exec", toolCallId: `call-unproven-${mode}` },
        )).resolves.toMatchObject({ block: true, blockReason: expect.stringContaining("did not prove") });
        expect(listeners.tool_result_persist(
          { toolName: "exec", toolCallId: `call-unproven-${mode}`, message: { role: "toolResult", content: [] } },
          { toolCallId: `call-unproven-${mode}` },
        )).toBeUndefined();
      }
    });

    it("fails closed on an unknown action enum", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(
        rawAnswer(
          JSON.stringify({
            action: "pass",
            severity: "NONE",
            reason: "",
            mode: "action",
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
      );

      await expect(
        listeners.before_tool_call(
          { toolName: "exec", params: { command: "printenv" } },
          { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
        ),
      ).resolves.toMatchObject({ block: true });
    });

    it("fails closed when the effective action is missing", async () => {
      mockDaemonClient.postRaw.mockResolvedValue(rawAnswer(JSON.stringify({
        raw_action: "allow", severity: "WARN", reason: "", mode: "action",
      })));
      await expect(listeners.before_tool_call(
        { toolName: "exec", params: { command: "echo ok" } },
        { sessionKey: "agent:main:main", runId: "run-1", toolName: "exec" },
      )).resolves.toMatchObject({
        block: true,
        blockReason: expect.stringContaining("sidecar returned invalid verdict"),
      });
    });
  });

  // ─── Command: /scan ───

  describe("command: /scan", () => {
    it("runs skill scan by default", async () => {
      mockRunSkillScan.mockResolvedValue(makeScanResult());

      const result = await commands["scan"].handler({ args: { target: "/skills/test" } });

      expect(result.text).toContain("Skill Scan");
      expect(result.text).toContain("CLEAN");
      expect(mockRunSkillScan).toHaveBeenCalledWith("/skills/test");
    });

    it("runs plugin scan when type=plugin", async () => {
      mockRunPluginScan.mockResolvedValue(makeScanResult());

      const result = await commands["scan"].handler({ args: { target: "/plugins/test", type: "plugin" } });

      expect(result.text).toContain("Plugin Scan");
      expect(mockRunPluginScan).toHaveBeenCalledWith("/plugins/test");
    });

    it("runs mcp scan when type=mcp", async () => {
      mockScanMCPServer.mockResolvedValue(makeScanResult());

      const result = await commands["scan"].handler({ args: { target: "/mcp.json", type: "mcp" } });

      expect(result.text).toContain("MCP Scan");
      expect(mockScanMCPServer).toHaveBeenCalledWith("/mcp.json");
    });

    it("reports findings with severity", async () => {
      mockRunSkillScan.mockResolvedValue(
        makeScanResult({
          findings: [
            {
              id: "f1",
              severity: "HIGH",
              title: "Shell exec detected",
              description: "test",
              scanner: "skill-scanner",
            },
          ],
        }),
      );

      const result = await commands["scan"].handler({ args: { target: "/skills/danger" } });

      expect(result.text).toContain("HIGH");
      expect(result.text).toContain("Shell exec detected");
    });

    it("returns usage when no target provided", async () => {
      const result = await commands["scan"].handler({ args: {} });

      expect(result.text).toContain("Usage");
    });

    it("handles scan failure gracefully", async () => {
      mockRunSkillScan.mockRejectedValue(new Error("scanner not found"));

      const result = await commands["scan"].handler({ args: { target: "/skills/fail" } });

      expect(result.text).toContain("failed");
      expect(result.text).toContain("scanner not found");
    });
  });

  // ─── Command: /block ───

  describe("command: /block", () => {
    it("blocks target via enforcer", async () => {
      const result = await commands["block"].handler({
        args: { type: "skill", name: "bad-skill", reason: "malicious content" },
      });

      expect(mockEnforcer.block).toHaveBeenCalledWith("skill", "bad-skill", "malicious content");
      expect(result.text).toContain("Blocked");
      expect(result.text).toContain("bad-skill");
    });

    it("uses default reason when not provided", async () => {
      await commands["block"].handler({ args: { type: "mcp", name: "some-mcp" } });

      expect(mockEnforcer.block).toHaveBeenCalledWith("mcp", "some-mcp", "Blocked via /block command");
    });

    it("returns usage when type is missing", async () => {
      const result = await commands["block"].handler({ args: { name: "test" } });

      expect(result.text).toContain("Usage");
    });

    it("returns usage when name is missing", async () => {
      const result = await commands["block"].handler({ args: { type: "skill" } });

      expect(result.text).toContain("Usage");
    });
  });

  // ─── Command: /allow ───

  describe("command: /allow", () => {
    it("allow-lists target via enforcer", async () => {
      const result = await commands["allow"].handler({
        args: { type: "skill", name: "safe-skill", reason: "reviewed and approved" },
      });

      expect(mockEnforcer.allow).toHaveBeenCalledWith("skill", "safe-skill", "reviewed and approved");
      expect(result.text).toContain("Allow-listed");
      expect(result.text).toContain("safe-skill");
    });

    it("uses default reason when not provided", async () => {
      await commands["allow"].handler({ args: { type: "plugin", name: "good-plugin" } });

      expect(mockEnforcer.allow).toHaveBeenCalledWith("plugin", "good-plugin", "Allowed via /allow command");
    });

    it("returns usage when type is missing", async () => {
      const result = await commands["allow"].handler({ args: { name: "test" } });

      expect(result.text).toContain("Usage");
    });

    it("returns usage when name is missing", async () => {
      const result = await commands["allow"].handler({ args: { type: "skill" } });

      expect(result.text).toContain("Usage");
    });
  });
});

// OpenClaw gives the plugin its `plugins.entries.defenseclaw.config` as
// `api.pluginConfig` (it has no getPluginConfig()); the `agent` section of that
// object feeds the sidecar correlation identity (GAP-0598).
describe("plugin agent identity from api.pluginConfig", () => {
  type DaemonOpts = {
    identityReady: Promise<unknown>;
    getCorrelation: () => { agentId: string; agentName?: string; policyId?: string };
  };

  async function setupWith(pluginConfig: unknown): Promise<DaemonOpts> {
    vi.clearAllMocks();
    const api = {
      config: {},
      pluginConfig,
      on: vi.fn(),
      registerService: vi.fn(),
      registerCommand: vi.fn(),
    };
    (pluginSetup as (api: unknown) => void)(api);
    const calls = vi.mocked(DaemonClient).mock.calls;
    const opts = calls[calls.length - 1][0] as unknown as DaemonOpts;
    await opts.identityReady;
    return opts;
  }

  beforeEach(() => {
    delete process.env.DEFENSECLAW_AGENT_ID;
    delete process.env.DEFENSECLAW_PLUGIN_AGENT_ID;
  });

  it("uses config.agent id, name and policyId", async () => {
    const opts = await setupWith({
      agent: { id: "  cfg-agent  ", name: "Build agent", policyId: "pol-1" },
    });
    expect(opts.getCorrelation()).toMatchObject({
      agentId: "cfg-agent",
      agentName: "Build agent",
      policyId: "pol-1",
    });
  });

  it("DEFENSECLAW_AGENT_ID still wins over config.agent.id", async () => {
    process.env.DEFENSECLAW_AGENT_ID = "env-agent";
    try {
      const opts = await setupWith({ agent: { id: "cfg-agent" } });
      expect(opts.getCorrelation().agentId).toBe("env-agent");
    } finally {
      delete process.env.DEFENSECLAW_AGENT_ID;
    }
  });

  it("falls back to the stable id when config.agent is absent or not an object", async () => {
    for (const cfg of [{}, undefined, null, { agent: "x" }, { agent: { id: 5, name: 7 } }]) {
      const opts = await setupWith(cfg);
      const c = opts.getCorrelation();
      expect(c.agentId).toBeTruthy();
      expect(c.agentId).not.toBe("cfg-agent");
      expect(c.agentName).toBeUndefined();
      expect(c.policyId).toBeUndefined();
    }
  });
});
