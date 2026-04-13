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

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { DaemonClient } from "../client.js";
import { PolicyEnforcer, type EnforcerConfig } from "../policy/enforcer.js";
import type { ScanResult } from "../types.js";

// Mock runPluginScan — it now shells out to the Python CLI, so we mock it
// to return controlled results for deterministic testing.
const { mockRunPluginScan } = vi.hoisted(() => ({
  mockRunPluginScan: vi.fn<(target: string) => Promise<ScanResult>>(),
}));

vi.mock("../policy/enforcer.js", async (importOriginal) => {
  const mod = await importOriginal<typeof import("../policy/enforcer.js")>();
  return {
    ...mod,
    runPluginScan: mockRunPluginScan,
    PolicyEnforcer: class extends mod.PolicyEnforcer {
      async evaluatePlugin(
        pluginDir: string,
        pluginName: string,
      ) {
        return (this as any).evaluate("plugin", pluginName, pluginDir, () =>
          mockRunPluginScan(pluginDir),
        );
      }
    },
  };
});

let tempDir: string;
const requests: Array<{ method: string; url: string; body: string }> = [];
let mockClient: DaemonClient;

let blockedList: Array<{
  id: string;
  target_type: string;
  target_name: string;
  reason: string;
  updated_at: string;
}> = [];
let allowedList: typeof blockedList = [];

class MockDaemonClient {
  async submitScanResult(result: unknown) {
    requests.push({
      method: "POST",
      url: "/scan/result",
      body: JSON.stringify(result),
    });
    return { ok: true, status: 200 };
  }

  async block(targetType: string, targetName: string, reason: string) {
    requests.push({
      method: "POST",
      url: "/enforce/block",
      body: JSON.stringify({
        target_type: targetType,
        target_name: targetName,
        reason,
      }),
    });
    blockedList.push({
      id: String(blockedList.length + 1),
      target_type: targetType,
      target_name: targetName,
      reason,
      updated_at: new Date().toISOString(),
    });
    allowedList = allowedList.filter(
      (entry) =>
        !(
          entry.target_type === targetType && entry.target_name === targetName
        ),
    );
    return { ok: true, status: 200 };
  }

  async allow(targetType: string, targetName: string, reason: string) {
    requests.push({
      method: "POST",
      url: "/enforce/allow",
      body: JSON.stringify({
        target_type: targetType,
        target_name: targetName,
        reason,
      }),
    });
    allowedList.push({
      id: String(allowedList.length + 1),
      target_type: targetType,
      target_name: targetName,
      reason,
      updated_at: new Date().toISOString(),
    });
    blockedList = blockedList.filter(
      (entry) =>
        !(
          entry.target_type === targetType && entry.target_name === targetName
        ),
    );
    return { ok: true, status: 200 };
  }

  async unblock(targetType: string, targetName: string) {
    requests.push({
      method: "DELETE",
      url: "/enforce/block",
      body: JSON.stringify({
        target_type: targetType,
        target_name: targetName,
      }),
    });
    blockedList = blockedList.filter(
      (entry) =>
        !(
          entry.target_type === targetType && entry.target_name === targetName
        ),
    );
    return { ok: true, status: 200 };
  }

  async listBlocked() {
    requests.push({ method: "GET", url: "/enforce/blocked", body: "" });
    return { ok: true, status: 200, data: blockedList };
  }

  async listAllowed() {
    requests.push({ method: "GET", url: "/enforce/allowed", body: "" });
    return { ok: true, status: 200, data: allowedList };
  }

  async logEvent(event: unknown) {
    requests.push({
      method: "POST",
      url: "/audit/event",
      body: JSON.stringify(event),
    });
    return { ok: true, status: 200 };
  }

  async evaluatePolicy(domain: string, input: Record<string, unknown>) {
    requests.push({
      method: "POST",
      url: "/policy/evaluate",
      body: JSON.stringify({ domain, input }),
    });

    const isBlocked = blockedList.some(
      (entry) =>
        entry.target_type === input.target_type &&
        entry.target_name === input.target_name,
    );
    const isAllowed = allowedList.some(
      (entry) =>
        entry.target_type === input.target_type &&
        entry.target_name === input.target_name,
    );

    let verdict = "scan";
    let reason = "awaiting scan";
    const scanResult = input.scan_result as
      | { max_severity?: string; total_findings?: number }
      | undefined;

    if (isBlocked) {
      verdict = "blocked";
      reason = `${input.target_type as string} '${input.target_name as string}' blocked by daemon policy`;
    } else if (isAllowed) {
      verdict = "allowed";
      reason = "allow-listed";
    } else if (scanResult && scanResult.total_findings === 0) {
      verdict = "clean";
      reason = "scan clean";
    } else if (
      scanResult &&
      ["HIGH", "CRITICAL"].includes(scanResult.max_severity ?? "")
    ) {
      verdict = "rejected";
      reason = `max severity ${scanResult.max_severity} triggers block`;
    } else if ((scanResult?.total_findings ?? 0) > 0) {
      verdict = "warning";
      reason = "findings present — allowed with warning";
    }

    return {
      ok: true,
      status: 200,
      data: {
        ok: true,
        data: { verdict, reason },
      },
    };
  }
}

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "dc-enforcer-test-"));
  requests.length = 0;
  blockedList = [];
  allowedList = [];
  mockClient = new MockDaemonClient() as unknown as DaemonClient;
  mockRunPluginScan.mockReset();
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

function makeEnforcer(overrides?: Partial<EnforcerConfig>) {
  return new PolicyEnforcer(overrides, mockClient);
}

describe("PolicyEnforcer", () => {
  describe("local block/allow lists", () => {
    it("blocks locally and reports to daemon", async () => {
      const enforcer = makeEnforcer();
      await enforcer.block("skill", "evil-skill", "malware detected");

      expect(enforcer.isBlockedLocally("skill", "evil-skill")).toBe(true);
      expect(enforcer.isAllowedLocally("skill", "evil-skill")).toBe(false);
    });

    it("allows locally and removes from block list", async () => {
      const enforcer = makeEnforcer();
      await enforcer.block("skill", "test", "initially blocked");
      await enforcer.allow("skill", "test", "reviewed and safe");

      expect(enforcer.isBlockedLocally("skill", "test")).toBe(false);
      expect(enforcer.isAllowedLocally("skill", "test")).toBe(true);
    });

    it("unblocks locally", async () => {
      const enforcer = makeEnforcer();
      await enforcer.block("mcp", "bad-mcp", "reason");
      await enforcer.unblock("mcp", "bad-mcp");

      expect(enforcer.isBlockedLocally("mcp", "bad-mcp")).toBe(false);
    });

    it("block removes from allow list", async () => {
      const enforcer = makeEnforcer();
      await enforcer.allow("plugin", "p", "trusted");
      await enforcer.block("plugin", "p", "no longer trusted");

      expect(enforcer.isAllowedLocally("plugin", "p")).toBe(false);
      expect(enforcer.isBlockedLocally("plugin", "p")).toBe(true);
    });
  });

  describe("syncFromDaemon", () => {
    it("populates local lists from daemon", async () => {
      blockedList = [
        {
          id: "1",
          target_type: "skill",
          target_name: "blocked-skill",
          reason: "daemon blocked",
          updated_at: new Date().toISOString(),
        },
      ];
      allowedList = [
        {
          id: "2",
          target_type: "mcp",
          target_name: "allowed-mcp",
          reason: "daemon allowed",
          updated_at: new Date().toISOString(),
        },
      ];

      const enforcer = makeEnforcer();
      await enforcer.syncFromDaemon();

      expect(enforcer.isBlockedLocally("skill", "blocked-skill")).toBe(true);
      expect(enforcer.isAllowedLocally("mcp", "allowed-mcp")).toBe(true);
    });

    it("removes stale entries on subsequent sync", async () => {
      blockedList = [
        {
          id: "1",
          target_type: "skill",
          target_name: "skill-a",
          reason: "blocked",
          updated_at: new Date().toISOString(),
        },
        {
          id: "2",
          target_type: "skill",
          target_name: "skill-b",
          reason: "blocked",
          updated_at: new Date().toISOString(),
        },
      ];
      allowedList = [
        {
          id: "3",
          target_type: "mcp",
          target_name: "mcp-a",
          reason: "allowed",
          updated_at: new Date().toISOString(),
        },
      ];

      const enforcer = makeEnforcer();
      await enforcer.syncFromDaemon();

      expect(enforcer.isBlockedLocally("skill", "skill-a")).toBe(true);
      expect(enforcer.isBlockedLocally("skill", "skill-b")).toBe(true);
      expect(enforcer.isAllowedLocally("mcp", "mcp-a")).toBe(true);

      blockedList = [
        {
          id: "2",
          target_type: "skill",
          target_name: "skill-b",
          reason: "blocked",
          updated_at: new Date().toISOString(),
        },
      ];
      allowedList = [];

      await enforcer.syncFromDaemon();

      expect(enforcer.isBlockedLocally("skill", "skill-a")).toBe(false);
      expect(enforcer.isBlockedLocally("skill", "skill-b")).toBe(true);
      expect(enforcer.isAllowedLocally("mcp", "mcp-a")).toBe(false);
    });
  });

  describe("evaluatePlugin - admission gate", () => {
    it("returns 'blocked' for locally blocked plugin", async () => {
      const enforcer = makeEnforcer();
      await enforcer.block("plugin", "bad-plugin", "known malicious");

      const result = await enforcer.evaluatePlugin(tempDir, "bad-plugin");

      expect(result.verdict).toBe("blocked");
      expect(result.reason).toContain("Block list");
      expect(result.type).toBe("plugin");
      expect(result.name).toBe("bad-plugin");
    });

    it("returns 'blocked' for daemon-blocked plugin via OPA", async () => {
      blockedList = [
        {
          id: "1",
          target_type: "plugin",
          target_name: "daemon-blocked",
          reason: "blocked by admin",
          updated_at: new Date().toISOString(),
        },
      ];
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [],
      });

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(tempDir, "daemon-blocked");

      expect(result.verdict).toBe("blocked");
      expect(result.reason).toContain("daemon policy");
    });

    it("returns 'allowed' for locally allowed plugin (skip scan)", async () => {
      const enforcer = makeEnforcer();
      await enforcer.allow("plugin", "trusted", "reviewed");

      const result = await enforcer.evaluatePlugin(tempDir, "trusted");

      expect(result.verdict).toBe("allowed");
      expect(result.reason.toLowerCase()).toContain("allow");
    });

    it("scans and returns 'clean' for safe plugin", async () => {
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [],
      });

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(tempDir, "safe-plugin");

      expect(result.verdict).toBe("clean");
    });

    it("scans and returns 'rejected' for plugin with HIGH findings", async () => {
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [
          {
            id: "plugin-1",
            severity: "HIGH",
            title: "Dangerous permission: fs:*",
            description: "Plugin requests broad filesystem access",
            location: "package.json",
            remediation: "Request specific file paths",
            scanner: "plugin-scanner",
            tags: ["permissions"],
          },
        ],
      });

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(tempDir, "dangerous-plugin");

      expect(result.verdict).toBe("rejected");
      expect(result.reason).toContain("HIGH");
    });

    it("scans and returns 'warning' for plugin with MEDIUM findings only", async () => {
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [
          {
            id: "plugin-1",
            severity: "MEDIUM",
            title: "Medium finding",
            description: "A medium-severity finding",
            location: "package.json",
            remediation: "Review",
            scanner: "plugin-scanner",
            tags: [],
          },
        ],
      });

      const enforcer = makeEnforcer({
        blockOnSeverity: "CRITICAL" as const,
        warnOnSeverity: "MEDIUM" as const,
      });
      const result = await enforcer.evaluatePlugin(tempDir, "medium-plugin");

      expect(result.verdict).toBe("warning");
    });

    it("returns 'scan-error' when scan throws", async () => {
      mockRunPluginScan.mockRejectedValue(new Error("scan failed"));

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(
        "/nonexistent/path/that/cannot/be/scanned",
        "broken",
      );

      expect(result.verdict).toBe("scan-error");
    });

    it("submits scan results to daemon", async () => {
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [
          {
            id: "plugin-1",
            severity: "LOW",
            title: "Info finding",
            description: "A low finding",
            location: "package.json",
            remediation: "Review",
            scanner: "plugin-scanner",
            tags: [],
          },
        ],
      });

      const enforcer = makeEnforcer();
      await enforcer.evaluatePlugin(tempDir, "reported");

      const scanPosts = requests.filter(
        (r) => r.url === "/scan/result" && r.method === "POST",
      );
      expect(scanPosts.length).toBe(1);
    });

    it("logs admission event to daemon", async () => {
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [],
      });

      const enforcer = makeEnforcer();
      await enforcer.evaluatePlugin(tempDir, "logged");

      const auditPosts = requests.filter(
        (r) => r.url === "/audit/event" && r.method === "POST",
      );
      expect(auditPosts.length).toBeGreaterThanOrEqual(1);

      const eventBody = JSON.parse(auditPosts[0].body);
      expect(eventBody.action).toBe("admission");
      expect(eventBody.actor).toBe("defenseclaw-plugin");
    });

    it("uses audit-store severity vocabulary in admission events", async () => {
      const enforcer = makeEnforcer();

      await enforcer.block("plugin", "sev-blocked", "test block");
      await enforcer.evaluatePlugin(tempDir, "sev-blocked");

      const auditPosts = requests.filter(
        (r) => r.url === "/audit/event" && r.method === "POST",
      );
      const blockedEvent = auditPosts.find((r) => {
        const body = JSON.parse(r.body);
        return body.action === "admission" && body.details?.includes('"blocked"');
      });
      expect(blockedEvent).toBeDefined();
      expect(JSON.parse(blockedEvent!.body).severity).toBe("CRITICAL");
    });
  });

  describe("evaluateMCPServer - admission gate", () => {
    it("returns 'blocked' for locally blocked MCP", async () => {
      const enforcer = makeEnforcer();
      await enforcer.block("mcp", "evil-mcp", "malicious server");

      const configFile = join(tempDir, "mcp.json");
      await writeFile(configFile, JSON.stringify({ mcpServers: {} }));

      const result = await enforcer.evaluateMCPServer(configFile, "evil-mcp");

      expect(result.verdict).toBe("blocked");
      expect(result.type).toBe("mcp");
    });

    it("scans MCP config and returns findings-based verdict", async () => {
      const configFile = join(tempDir, "mcp.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            dangerous: {
              command: "bash",
              env: { AWS_SECRET_ACCESS_KEY: "real-key" },
            },
          },
        }),
      );

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluateMCPServer(configFile, "dangerous");

      expect(result.verdict).toBe("rejected");
    });

    it("returns 'clean' for safe MCP config", async () => {
      const configFile = join(tempDir, "safe-mcp.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            safe: {
              command: "node",
              args: ["server.js"],
              url: "https://secure.example.com",
            },
          },
        }),
      );

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluateMCPServer(configFile, "safe");

      expect(result.verdict).toBe("clean");
    });
  });

  describe("admission gate ordering", () => {
    it("block list takes priority over allow list", async () => {
      const enforcer = makeEnforcer();
      await enforcer.allow("plugin", "contested", "was trusted");
      await enforcer.block("plugin", "contested", "now blocked");

      const result = await enforcer.evaluatePlugin(tempDir, "contested");
      expect(result.verdict).toBe("blocked");
    });

    it("allow list skips scanning", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "allowed-but-dangerous",
          permissions: ["shell:*", "fs:*"],
        }),
      );

      const enforcer = makeEnforcer();
      await enforcer.allow("plugin", "allowed-but-dangerous", "trust override");

      const result = await enforcer.evaluatePlugin(
        tempDir,
        "allowed-but-dangerous",
      );
      expect(result.verdict).toBe("allowed");
    });
  });

  describe("result structure", () => {
    it("contains all required fields", async () => {
      mockRunPluginScan.mockResolvedValue({
        scanner: "plugin-scanner",
        target: tempDir,
        timestamp: new Date().toISOString(),
        findings: [],
      });

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(tempDir, "test");

      expect(result.type).toBe("plugin");
      expect(result.name).toBe("test");
      expect(result.path).toBe(tempDir);
      expect(result.verdict).toBeTruthy();
      expect(result.reason).toBeTruthy();
      expect(result.timestamp).toBeTruthy();
      expect(() => new Date(result.timestamp)).not.toThrow();
    });
  });
});
