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
import type { ScanResult } from "../types.js";

// --- Hoisted mocks (available before module-level vi.mock factories) ---

const { mockDaemonClient, mockEnforcer, mockRunSkillScan, mockRunPluginScan, mockRunCodeScan, mockScanMCPServer } =
  vi.hoisted(() => ({
    mockDaemonClient: {
      buildOutboundHeaders: vi.fn(async () => ({})),
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

type EventHandler = (...args: unknown[]) => Promise<unknown> | unknown;

type ToolVerdict = {
  action: "allow" | "alert" | "confirm" | "block";
  severity: "NONE" | "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reason: string;
  mode: "action" | "observe";
  raw_action?: "allow" | "alert" | "confirm" | "block";
  approval_timeout_ms?: number;
};

const validToolVerdict = (
  overrides: Partial<ToolVerdict> = {},
): ToolVerdict => ({
  action: "allow",
  severity: "NONE",
  reason: "",
  mode: "action",
  ...overrides,
});

const verdictResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

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

// --- Tests ---

describe("DefenseClaw OpenClaw Plugin", () => {
  let listeners: Record<string, EventHandler>;
  let commands: Record<string, { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }>;

  beforeEach(() => {
    vi.clearAllMocks();
    delete process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN;
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
  });

  describe("before_tool_call verdict handling", () => {
    const genericEvent = {
      toolName: "exec",
      params: { command: "printenv" },
    };
    const genericContext = {
      sessionKey: "agent:main:main",
      runId: "run-1",
      toolName: "exec",
    };

    async function runGeneric(verdict: unknown) {
      globalThis.fetch = vi.fn().mockResolvedValue(verdictResponse(verdict));
      return listeners.before_tool_call(genericEvent, genericContext);
    }

    async function runMessage(verdict: unknown) {
      globalThis.fetch = vi.fn().mockResolvedValue(verdictResponse(verdict));
      return listeners.before_tool_call(
        {
          toolName: "message",
          params: { to: "security@example.test", content: "status update" },
        },
        genericContext,
      );
    }

    it.each([
      ["allow", validToolVerdict({ action: "allow" })],
      [
        "informational",
        validToolVerdict({
          action: "allow",
          severity: "INFO",
          reason: "informational finding",
        }),
      ],
      [
        "alert",
        validToolVerdict({
          action: "alert",
          severity: "LOW",
          reason: "review recommended",
        }),
      ],
      [
        "observe",
        validToolVerdict({
          action: "allow",
          raw_action: "block",
          severity: "HIGH",
          reason: "observed match",
          mode: "observe",
        }),
      ],
    ])("allows valid %s verdict", async (_name, verdict) => {
      await expect(runGeneric(verdict)).resolves.toBeUndefined();
      await expect(runMessage(verdict)).resolves.toBeUndefined();
    });

    it("returns native OpenClaw approval requests for valid confirm verdicts", async () => {
      const verdict = validToolVerdict({
        action: "confirm",
        raw_action: "confirm",
        severity: "HIGH",
        reason: "matched: CMD-ENV-DUMP:Environment variable dump",
        approval_timeout_ms: 30000,
      });
      const fetchMock = vi.fn().mockImplementation(async () =>
        verdictResponse(verdict),
      );
      globalThis.fetch = fetchMock;

      const genericResult = await listeners.before_tool_call(
        genericEvent,
        genericContext,
      );
      const messageResult = await listeners.before_tool_call(
        {
          toolName: "message",
          params: { to: "security@example.test", content: "status update" },
        },
        genericContext,
      );

      expect(genericResult).toMatchObject({
        requireApproval: {
          title: "DefenseClaw approval required",
          severity: "warning",
          timeoutMs: 30000,
          timeoutBehavior: "deny",
        },
      });
      expect(messageResult).toMatchObject({
        requireApproval: {
          title: "DefenseClaw approval required",
          description: expect.stringContaining("outbound message"),
          severity: "warning",
          timeoutBehavior: "deny",
        },
      });
      expect(fetchMock).toHaveBeenCalledTimes(2);
      const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [
        string,
        RequestInit,
      ];
      expect(requestUrl).toMatch(/\/api\/v1\/inspect\/tool$/);
      const body = JSON.parse(requestInit.body as string);
      expect(body).toMatchObject({
        tool: "exec",
        session_id: "agent:main:main",
        approval_surface: "native",
      });
    });

    it("keeps large sidecar bodies on the interceptor's URL/init path", async () => {
      const verdict = validToolVerdict();
      const fetchMock = vi.fn().mockResolvedValue(verdictResponse(verdict));
      globalThis.fetch = fetchMock;
      const command = "x".repeat(70 * 1024);

      await expect(
        listeners.before_tool_call(
          { toolName: "exec", params: { command } },
          genericContext,
        ),
      ).resolves.toBeUndefined();

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [requestUrl, requestInit] = fetchMock.mock.calls[0] as [
        string,
        RequestInit,
      ];
      expect(requestUrl).toBeTypeOf("string");
      expect(requestInit.body).toBeTypeOf("string");
      expect(new TextEncoder().encode(requestInit.body as string).byteLength)
        .toBeGreaterThan(64 * 1024);
      expect(JSON.parse(requestInit.body as string)).toMatchObject({
        tool: "exec",
        args: { command },
      });
    });

    it("blocks generic and outbound message calls for a valid action-mode block", async () => {
      const verdict = validToolVerdict({
        action: "block",
        raw_action: "block",
        severity: "CRITICAL",
        reason: "matched guardrail policy",
      });

      await expect(runGeneric(verdict)).resolves.toEqual({
        block: true,
        blockReason: "DefenseClaw: matched guardrail policy",
      });
      await expect(runMessage(verdict)).resolves.toEqual({
        block: true,
        blockReason:
          "DefenseClaw: outbound blocked — matched guardrail policy",
      });
    });

    it("accepts the gateway's fail-closed unsupported-confirmation verdict", async () => {
      const verdict = validToolVerdict({
        action: "block",
        raw_action: "confirm",
        severity: "HIGH",
        reason: "human approval unsupported; failing closed",
      });

      await expect(runGeneric(verdict)).resolves.toEqual({
        block: true,
        blockReason:
          "DefenseClaw: human approval unsupported; failing closed",
      });
      await expect(runMessage(verdict)).resolves.toEqual({
        block: true,
        blockReason:
          "DefenseClaw: outbound blocked — human approval unsupported; failing closed",
      });
    });

    it("treats a zero approval timeout as an omitted optional timeout", async () => {
      const result = await runGeneric(
        validToolVerdict({
          action: "confirm",
          severity: "HIGH",
          reason: "approval required",
          approval_timeout_ms: 0,
        }),
      );

      expect(result).toMatchObject({
        requireApproval: {
          timeoutBehavior: "deny",
        },
      });
      expect(
        (result as { requireApproval: { timeoutMs?: number } }).requireApproval
          .timeoutMs,
      ).toBeUndefined();
    });

    const invalidVerdicts: Array<[string, unknown]> = [
      ["null", null],
      ["array", []],
      ["empty object", {}],
      ["string", "allow"],
      ["number", 1],
      ["boolean", true],
      ["missing action", { severity: "NONE", reason: "", mode: "action" }],
      ["missing mode", { action: "allow", severity: "NONE", reason: "" }],
      ["missing severity", { action: "allow", reason: "", mode: "action" }],
      ["missing reason", { action: "allow", severity: "NONE", mode: "action" }],
      ["unknown action", { ...validToolVerdict(), action: "pass" }],
      ["unknown mode", { ...validToolVerdict(), mode: "enforce" }],
      ["unknown severity", { ...validToolVerdict(), severity: "WARNING" }],
      ["non-string action", { ...validToolVerdict(), action: true }],
      ["non-string mode", { ...validToolVerdict(), mode: 1 }],
      ["non-string severity", { ...validToolVerdict(), severity: null }],
      ["non-string reason", { ...validToolVerdict(), reason: ["secret"] }],
      ["non-string raw action", { ...validToolVerdict(), raw_action: 1 }],
      ["unknown raw action", { ...validToolVerdict(), raw_action: "pass" }],
      [
        "contradictory action-mode raw action",
        { ...validToolVerdict(), raw_action: "block" },
      ],
      [
        "observe-mode effective block without raw action",
        validToolVerdict({ action: "block", mode: "observe" }),
      ],
      [
        "observe-mode effective block with raw action",
        validToolVerdict({
          action: "block",
          raw_action: "block",
          mode: "observe",
        }),
      ],
      [
        "observe-mode effective confirm without raw action",
        validToolVerdict({ action: "confirm", mode: "observe" }),
      ],
      [
        "observe-mode effective confirm with raw action",
        validToolVerdict({
          action: "confirm",
          raw_action: "confirm",
          mode: "observe",
        }),
      ],
      [
        "observe-mode effective alert",
        validToolVerdict({
          action: "alert",
          raw_action: "alert",
          mode: "observe",
        }),
      ],
      [
        "non-number approval timeout",
        { ...validToolVerdict(), approval_timeout_ms: "30000" },
      ],
      [
        "negative approval timeout",
        { ...validToolVerdict(), approval_timeout_ms: -1 },
      ],
      [
        "fractional approval timeout",
        { ...validToolVerdict(), approval_timeout_ms: 1.5 },
      ],
      [
        "unsafe approval timeout",
        {
          ...validToolVerdict(),
          approval_timeout_ms: Number.MAX_SAFE_INTEGER + 1,
        },
      ],
    ];

    it.each(invalidVerdicts)(
      "fails closed on an invalid %s verdict in generic and message paths",
      async (_name, verdict) => {
        await expect(runGeneric(verdict)).resolves.toMatchObject({
          block: true,
          blockReason: expect.stringContaining(
            "sidecar returned invalid verdict",
          ),
        });
        await expect(runMessage(verdict)).resolves.toMatchObject({
          block: true,
          blockReason: expect.stringContaining(
            "sidecar returned invalid verdict",
          ),
        });
      },
    );

    it("fails closed on a non-finite JSON approval timeout", async () => {
      const responseBody =
        '{"action":"allow","severity":"NONE","reason":"","mode":"action","approval_timeout_ms":1e10000}';
      globalThis.fetch = vi
        .fn()
        .mockImplementation(async () => new Response(responseBody));

      await expect(
        listeners.before_tool_call(genericEvent, genericContext),
      ).resolves.toMatchObject({ block: true });
      await expect(
        listeners.before_tool_call(
          {
            toolName: "message",
            params: {
              to: "security@example.test",
              content: "status update",
            },
          },
          genericContext,
        ),
      ).resolves.toMatchObject({ block: true });
    });

    it("does not expose response, argument, or credential data in diagnostics", async () => {
      const logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
      const warnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
      const errorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
      globalThis.fetch = vi
        .fn()
        .mockResolvedValueOnce(
          verdictResponse({
            ...validToolVerdict(),
            reason: ["sensitive-response-value"],
          }),
        )
        .mockRejectedValueOnce(
          new Error("synthetic-credential-value"),
        );

      try {
        const invalidResponseResult = await listeners.before_tool_call(
          {
            toolName: "exec",
            params: { command: "sensitive-tool-argument" },
          },
          genericContext,
        );
        const transportResult = await listeners.before_tool_call(
          {
            toolName: "exec",
            params: { command: "sensitive-tool-argument" },
          },
          genericContext,
        );
        const visible = JSON.stringify({
          invalidResponseResult,
          transportResult,
          logs: logSpy.mock.calls,
          warnings: warnSpy.mock.calls,
          errors: errorSpy.mock.calls,
        });
        expect(visible).not.toContain("sensitive-response-value");
        expect(visible).not.toContain("sensitive-tool-argument");
        expect(visible).not.toContain("synthetic-credential-value");
      } finally {
        logSpy.mockRestore();
        warnSpy.mockRestore();
        errorSpy.mockRestore();
      }
    });

    it("keeps invalid and malformed HTTP responses fail-closed under the availability override", async () => {
      process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN = "1";
      globalThis.fetch = vi
        .fn()
        .mockResolvedValueOnce(verdictResponse({ action: "allow" }))
        .mockResolvedValueOnce(new Response("not-json", { status: 200 }))
        .mockResolvedValueOnce(new Response("unavailable", { status: 503 }));

      for (let attempt = 0; attempt < 3; attempt += 1) {
        await expect(
          listeners.before_tool_call(genericEvent, genericContext),
        ).resolves.toMatchObject({ block: true });
      }
    });

    it("applies fail-open only to an unavailable transport", async () => {
      process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN = "1";
      globalThis.fetch = vi
        .fn()
        .mockRejectedValue(new Error("sensitive-transport-value"));

      await expect(
        listeners.before_tool_call(genericEvent, genericContext),
      ).resolves.toBeUndefined();
    });

    it("does not expose transport exception text when failing closed", async () => {
      globalThis.fetch = vi
        .fn()
        .mockRejectedValue(new Error("sensitive-transport-value"));

      const result = await listeners.before_tool_call(
        genericEvent,
        genericContext,
      );
      expect(JSON.stringify(result)).not.toContain("sensitive-transport-value");
    });

    it("keeps local request failures closed under the availability override", async () => {
      process.env.DEFENSECLAW_TOOL_INSPECT_FAIL_OPEN = "1";
      const fetchMock = vi.fn();
      globalThis.fetch = fetchMock;
      mockDaemonClient.buildOutboundHeaders.mockRejectedValueOnce(
        new Error("header preparation failed"),
      );

      await expect(
        listeners.before_tool_call(genericEvent, genericContext),
      ).resolves.toMatchObject({ block: true });

      mockDaemonClient.buildOutboundHeaders.mockResolvedValue({});
      await expect(
        listeners.before_tool_call(
          { toolName: "exec", params: { count: 1n } },
          genericContext,
        ),
      ).resolves.toMatchObject({ block: true });

      mockDaemonClient.buildOutboundHeaders.mockResolvedValueOnce({
        "x-invalid-local-header": "value\nsmuggled",
      });
      await expect(
        listeners.before_tool_call(genericEvent, genericContext),
      ).resolves.toMatchObject({ block: true });
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it("fails closed repeatedly when transport is unavailable by default", async () => {
      globalThis.fetch = vi.fn().mockRejectedValue(new Error("offline"));

      for (let attempt = 0; attempt < 3; attempt += 1) {
        await expect(
          listeners.before_tool_call(genericEvent, genericContext),
        ).resolves.toMatchObject({ block: true });
      }
    });

    it("fails closed on an invalid verdict from a legacy host without tool context", async () => {
      globalThis.fetch = vi
        .fn()
        .mockResolvedValue(verdictResponse({ action: "allow" }));

      await expect(listeners.before_tool_call(genericEvent)).resolves.toEqual({
        block: true,
        blockReason:
          "DefenseClaw: defenseclaw failing closed: sidecar returned invalid verdict",
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
