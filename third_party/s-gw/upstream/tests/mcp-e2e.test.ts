import { execFileSync } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

let tmpHome = "";
let testEnv: NodeJS.ProcessEnv;

const repoRoot = process.cwd();
const tsxCli = path.join(repoRoot, "node_modules", "tsx", "dist", "cli.mjs");

beforeEach(async () => {
  tmpHome = await mkdtemp(path.join(os.tmpdir(), "sgw-mcp-e2e-"));
  testEnv = {
    ...process.env,
    SGW_HOME: tmpHome,
    SGW_RECOVERY_HOME: `${tmpHome}-recovery`,
    SGW_MASTER_PASSPHRASE: "mcp e2e passphrase",
    SGW_DISABLE_KEYCHAIN: "1"
  };
});

afterEach(async () => {
  if (tmpHome) {
    await rm(tmpHome, { recursive: true, force: true });
    await rm(`${tmpHome}-recovery`, { recursive: true, force: true });
  }
});

describe("MCP end-to-end flow", () => {
  it("starts through the primary CLI", async () => {
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [tsxCli, "src/cli.ts", "mcp"],
      cwd: repoRoot,
      env: testEnv as Record<string, string>,
      stderr: "pipe"
    });
    const client = new Client({ name: "codex-mcp-client", version: "0.0.1" });

    await client.connect(transport);
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name)).toContain("sgw_request_execution");
      expect(tools.tools.map((tool) => tool.name)).toContain("sgw_run_execution");
    } finally {
      await client.close();
    }
  }, 20_000);

  it("denies execution before approval and returns sanitized output after approval", async () => {
    runCli(["init"]);
    const addPayload = JSON.parse(
      runCli(
        [
          "secret",
          "add",
          "--name",
          "mcp-e2e",
          "--type",
          "api-token",
          "--value-stdin",
          "--inject-env",
          "SGW_E2E_TOKEN",
          "--allow-command",
          process.execPath
        ],
        "mcp-e2e-secret-value-1234567890"
      )
    );

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [tsxCli, "src/mcp-server.ts"],
      cwd: repoRoot,
      env: testEnv as Record<string, string>,
      stderr: "pipe"
    });
    const client = new Client({ name: "codex-mcp-client", version: "0.0.1" });

    await client.connect(transport);
    try {
      const tools = await client.listTools();
      expect(tools.tools.map((tool) => tool.name)).toEqual(
        expect.arrayContaining(["sgw_list_handles", "sgw_request_execution", "sgw_run_execution", "sgw_execute_request"])
      );

      const handlesRes = await client.callTool({ name: "sgw_list_handles", arguments: {} });
      const handles = JSON.parse(handlesRes.content[0].text);
      expect(handles.some((handle: { handle: string }) => handle.handle === addPayload.handle)).toBe(true);

      const requestRes = await client.callTool({
        name: "sgw_request_execution",
        arguments: {
          handle: addPayload.handle,
          command: process.execPath,
          args: ["-e", "console.log(process.env.SGW_E2E_TOKEN)"],
          injectEnv: "SGW_E2E_TOKEN",
          reason: "vitest mcp e2e"
        }
      });
      const requestPayload = JSON.parse(requestRes.content[0].text);
      expect(requestPayload.approvalRequired).toBe(true);
      expect(requestPayload.request.id).toMatch(/^req_/);
      expect(requestPayload.request.agentName).toBe("Codex");
      expect(requestPayload.request.agentSource).toBe("mcp-client");

      const early = await client.callTool({
        name: "sgw_execute_request",
        arguments: { requestId: requestPayload.request.id }
      });
      expect(early.isError).toBe(true);
      expect(early.content[0].text).toMatch(/approval|required|approved/i);

      runCli(["approve", requestPayload.request.id]);

      const executed = await client.callTool({
        name: "sgw_execute_request",
        arguments: { requestId: requestPayload.request.id }
      });
      expect(executed.isError).not.toBe(true);

      const summary = JSON.parse(executed.content[0].text);
      expect(summary.exitCode).toBe(0);
      expect(summary.stdout).not.toContain("mcp-e2e-secret-value");
      expect(summary.stdout).toContain(`<<SGW_SECRET:${addPayload.handle}>>`);
      expect(summary.proof).toMatch(/^s-gw-proof:/);
    } finally {
      await client.close();
    }
  }, 20_000);
});

function runCli(args: string[], input?: string): string {
  return execFileSync(process.execPath, [tsxCli, "src/cli.ts", ...args], {
    cwd: repoRoot,
    env: testEnv,
    input,
    encoding: "utf8",
    stdio: ["pipe", "pipe", "pipe"]
  });
}
