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

const { mockEnforcer, mockRunSkillScan, mockRunPluginScan, mockScanMCPServer } =
  vi.hoisted(() => ({
    mockEnforcer: {
      syncFromDaemon: vi.fn(),
      evaluateSkill: vi.fn(),
      evaluateMCPServer: vi.fn(),
      block: vi.fn(),
      allow: vi.fn(),
    },
    mockRunSkillScan: vi.fn(),
    mockRunPluginScan: vi.fn(),
    mockScanMCPServer: vi.fn(),
  }));

vi.mock("@openclaw/plugin-sdk", () => ({
  definePluginEntry: (fn: unknown) => fn,
}));

vi.mock("../client.js", () => ({
  DaemonClient: vi.fn(() => ({})),
}));

vi.mock("../policy/enforcer.js", () => ({
  PolicyEnforcer: vi.fn(() => mockEnforcer),
  runSkillScan: mockRunSkillScan,
  runPluginScan: mockRunPluginScan,
}));

vi.mock("../scanners/mcp-scanner.js", () => ({
  scanMCPServer: mockScanMCPServer,
}));

// --- Helpers ---

type EventHandler = (...args: unknown[]) => Promise<void>;

function createMockContext() {
  const listeners: Record<string, EventHandler> = {};
  const commands: Record<string, { handler: (ctx: { args: Record<string, unknown> }) => Promise<{ text: string }> }> = {};

  const api = {
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
    mockEnforcer.syncFromDaemon.mockResolvedValue(undefined);
    mockEnforcer.block.mockResolvedValue(undefined);
    mockEnforcer.allow.mockResolvedValue(undefined);

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
