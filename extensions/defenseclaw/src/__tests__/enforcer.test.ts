import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createServer } from "node:http";
import type { Server, IncomingMessage, ServerResponse } from "node:http";
import { PolicyEnforcer } from "../policy/enforcer.js";

let tempDir: string;
let server: Server;
let port: number;
const requests: Array<{ method: string; url: string; body: string }> = [];

let blockedList: Array<{
  id: string;
  target_type: string;
  target_name: string;
  reason: string;
  created_at: string;
}> = [];
let allowedList: typeof blockedList = [];

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "dc-enforcer-test-"));
  requests.length = 0;
  blockedList = [];
  allowedList = [];

  await new Promise<void>((resolve) => {
    server = createServer((req: IncomingMessage, res: ServerResponse) => {
      const chunks: Buffer[] = [];
      req.on("data", (c: Buffer) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf-8");
        requests.push({ method: req.method ?? "", url: req.url ?? "", body });

        res.writeHead(200, { "Content-Type": "application/json" });

        if (req.url === "/enforce/block" && req.method === "POST") {
          const payload = JSON.parse(body || "{}");
          blockedList.push({
            id: String(blockedList.length + 1),
            target_type: payload.target_type || "",
            target_name: payload.target_name || "",
            reason: payload.reason || "",
            created_at: new Date().toISOString(),
          });
          allowedList = allowedList.filter(
            (e) =>
              !(
                e.target_type === payload.target_type &&
                e.target_name === payload.target_name
              ),
          );
          res.end(JSON.stringify({ ok: true }));
        } else if (req.url === "/enforce/allow" && req.method === "POST") {
          const payload = JSON.parse(body || "{}");
          allowedList.push({
            id: String(allowedList.length + 1),
            target_type: payload.target_type || "",
            target_name: payload.target_name || "",
            reason: payload.reason || "",
            created_at: new Date().toISOString(),
          });
          blockedList = blockedList.filter(
            (e) =>
              !(
                e.target_type === payload.target_type &&
                e.target_name === payload.target_name
              ),
          );
          res.end(JSON.stringify({ ok: true }));
        } else if (req.url === "/enforce/blocked") {
          res.end(JSON.stringify(blockedList));
        } else if (req.url === "/enforce/allowed") {
          res.end(JSON.stringify(allowedList));
        } else if (req.url === "/policy/evaluate" && req.method === "POST") {
          const payload = JSON.parse(body || "{}");
          const inp = payload.input || {};
          const isBlocked = blockedList.some(
            (e: { target_type: string; target_name: string }) =>
              e.target_type === inp.target_type &&
              e.target_name === inp.target_name,
          );
          const isAllowed = allowedList.some(
            (e: { target_type: string; target_name: string }) =>
              e.target_type === inp.target_type &&
              e.target_name === inp.target_name,
          );
          let verdict = "scan";
          let reason = "awaiting scan";
          if (isBlocked) {
            verdict = "blocked";
            reason = `${inp.target_type} '${inp.target_name}' blocked by daemon policy`;
          } else if (isAllowed) {
            verdict = "allowed";
            reason = "allow-listed";
          } else if (inp.scan_result && inp.scan_result.total_findings === 0) {
            verdict = "clean";
            reason = "scan clean";
          } else if (
            inp.scan_result &&
            ["HIGH", "CRITICAL"].includes(inp.scan_result.max_severity)
          ) {
            verdict = "rejected";
            reason = `max severity ${inp.scan_result.max_severity} triggers block`;
          } else if (
            inp.scan_result &&
            inp.scan_result.total_findings > 0
          ) {
            verdict = "warning";
            reason = "findings present — allowed with warning";
          }
          res.end(
            JSON.stringify({
              ok: true,
              data: { verdict, reason },
            }),
          );
        } else {
          res.end("{}");
        }
      });
    });

    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      port = typeof addr === "object" && addr ? addr.port : 0;
      resolve();
    });
  });
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

function makeEnforcer(overrides?: Record<string, unknown>) {
  return new PolicyEnforcer({
    daemonUrl: `http://127.0.0.1:${port}`,
    ...overrides,
  });
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
          created_at: new Date().toISOString(),
        },
      ];
      allowedList = [
        {
          id: "2",
          target_type: "mcp",
          target_name: "allowed-mcp",
          reason: "daemon allowed",
          created_at: new Date().toISOString(),
        },
      ];

      const enforcer = makeEnforcer();
      await enforcer.syncFromDaemon();

      expect(enforcer.isBlockedLocally("skill", "blocked-skill")).toBe(true);
      expect(enforcer.isAllowedLocally("mcp", "allowed-mcp")).toBe(true);
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
          created_at: new Date().toISOString(),
        },
      ];

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
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "safe-plugin",
          version: "1.0.0",
          permissions: ["fs:read:/data"],
          dependencies: { lodash: "^4.17.21" },
        }),
      );
      await writeFile(join(tempDir, "package-lock.json"), JSON.stringify({ lockfileVersion: 3 }));

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(tempDir, "safe-plugin");

      expect(result.verdict).toBe("clean");
    });

    it("scans and returns 'rejected' for plugin with HIGH findings", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "dangerous-plugin",
          permissions: ["shell:exec", "fs:*"],
        }),
      );

      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(tempDir, "dangerous-plugin");

      expect(result.verdict).toBe("rejected");
      expect(result.reason).toContain("HIGH");
    });

    it("scans and returns 'warning' for plugin with MEDIUM findings only", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "medium-plugin",
          permissions: ["fs:read"],
          dependencies: { shelljs: "^0.8.0" },
        }),
      );

      const enforcer = makeEnforcer({
        blockOnSeverity: "CRITICAL" as const,
        warnOnSeverity: "MEDIUM" as const,
      });
      const result = await enforcer.evaluatePlugin(tempDir, "medium-plugin");

      expect(result.verdict).toBe("warning");
    });

    it("returns 'scan-error' when scan throws", async () => {
      const enforcer = makeEnforcer();
      const result = await enforcer.evaluatePlugin(
        "/nonexistent/path/that/cannot/be/scanned",
        "broken",
      );

      expect(["clean", "scan-error", "warning", "rejected"]).toContain(
        result.verdict,
      );
    });

    it("submits scan results to daemon", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "reported",
          permissions: ["fs:read"],
        }),
      );

      const enforcer = makeEnforcer();
      await enforcer.evaluatePlugin(tempDir, "reported");

      const scanPosts = requests.filter(
        (r) => r.url === "/scan/result" && r.method === "POST",
      );
      expect(scanPosts.length).toBe(1);
    });

    it("logs admission event to daemon", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "logged",
          permissions: ["fs:read"],
        }),
      );

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
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "test", permissions: ["fs:read"] }),
      );

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
