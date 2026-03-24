import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanMCPServer } from "../scanners/mcp-scanner.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "dc-mcp-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("scanMCPServer", () => {
  describe("config loading", () => {
    it("reports INFO when no configs found (empty dir)", async () => {
      const result = await scanMCPServer(tempDir);

      expect(result.scanner).toBe("defenseclaw-mcp-scanner");
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].severity).toBe("INFO");
      expect(result.findings[0].title).toContain("No MCP server configurations");
    });

    it("loads configs from a single JSON file", async () => {
      const configFile = join(tempDir, "mcp.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            "safe-server": {
              command: "node",
              args: ["server.js"],
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const noConfig = result.findings.filter(
        (f) => f.title.includes("No MCP server configurations"),
      );
      expect(noConfig.length).toBe(0);
    });

    it("loads configs from a directory of JSON files", async () => {
      await writeFile(
        join(tempDir, "servers.json"),
        JSON.stringify({
          mcpServers: {
            "server-a": { command: "node", args: ["a.js"] },
          },
        }),
      );

      const result = await scanMCPServer(tempDir);
      const noConfig = result.findings.filter(
        (f) => f.title.includes("No MCP server configurations"),
      );
      expect(noConfig.length).toBe(0);
    });

    it("loads configs from a YAML file", async () => {
      const configFile = join(tempDir, "mcp.yaml");
      await writeFile(
        configFile,
        `
mcpServers:
  yaml-server:
    command: node
    args: [serve.js]
`,
        "utf-8",
      );

      const result = await scanMCPServer(configFile);
      expect(
        result.findings.some((f) => f.title.includes("No MCP server configurations")),
      ).toBe(false);
    });

    it("supports mcp_servers key format", async () => {
      const configFile = join(tempDir, "config.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcp_servers: {
            underscored: { command: "python", args: ["serve.py"] },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      expect(
        result.findings.some((f) => f.title.includes("No MCP server configurations")),
      ).toBe(false);
    });

    it("supports standalone command format", async () => {
      const configFile = join(tempDir, "single.json");
      await writeFile(
        configFile,
        JSON.stringify({
          command: "node",
          args: ["server.js"],
        }),
      );

      const result = await scanMCPServer(configFile);
      expect(
        result.findings.some((f) => f.title.includes("No MCP server configurations")),
      ).toBe(false);
    });

    it("handles non-existent path gracefully", async () => {
      const result = await scanMCPServer(join(tempDir, "nonexistent.json"));
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].severity).toBe("INFO");
    });

    it("handles invalid JSON gracefully", async () => {
      const configFile = join(tempDir, "bad.json");
      await writeFile(configFile, "not json {{{");

      const result = await scanMCPServer(configFile);
      expect(result.findings.length).toBe(1);
      expect(result.findings[0].title).toContain("No MCP server configurations");
    });
  });

  describe("command checks", () => {
    it("flags shell commands (bash) as HIGH", async () => {
      const configFile = join(tempDir, "shell.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            "shell-server": { command: "bash", args: ["-c", "echo hi"] },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const shell = result.findings.filter(
        (f) => f.severity === "HIGH" && f.title.includes("uses shell as command"),
      );

      expect(shell.length).toBe(1);
    });

    it("flags full path shell commands", async () => {
      const configFile = join(tempDir, "fullpath.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            binsh: { command: "/bin/sh" },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const shell = result.findings.filter(
        (f) => f.title.includes("uses shell as command"),
      );

      expect(shell.length).toBe(1);
    });

    it("does not flag safe commands", async () => {
      const configFile = join(tempDir, "safe.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            safe: { command: "node", args: ["server.js"] },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const shell = result.findings.filter(
        (f) => f.title.includes("uses shell as command"),
      );

      expect(shell.length).toBe(0);
    });
  });

  describe("argument checks", () => {
    it("flags --no-sandbox as HIGH", async () => {
      const configFile = join(tempDir, "nosandbox.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            insecure: {
              command: "node",
              args: ["server.js", "--no-sandbox"],
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const sandbox = result.findings.filter(
        (f) => f.title.includes("disables sandboxing"),
      );

      expect(sandbox.length).toBe(1);
      expect(sandbox[0].severity).toBe("HIGH");
    });

    it("flags --privileged as HIGH", async () => {
      const configFile = join(tempDir, "priv.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            priv: { command: "node", args: ["--privileged"] },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const priv = result.findings.filter(
        (f) => f.title.includes("elevated privileges"),
      );

      expect(priv.length).toBe(1);
    });
  });

  describe("environment variable checks", () => {
    it("flags hardcoded secrets as CRITICAL", async () => {
      const configFile = join(tempDir, "secrets.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            leaky: {
              command: "node",
              args: ["server.js"],
              env: {
                AWS_SECRET_ACCESS_KEY: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                OPENAI_API_KEY: "sk-proj-abc123",
              },
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const secrets = result.findings.filter(
        (f) =>
          f.severity === "CRITICAL" && f.title.includes("Hardcoded secret"),
      );

      expect(secrets.length).toBe(2);
    });

    it("allows env var references (${...})", async () => {
      const configFile = join(tempDir, "envref.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            safe: {
              command: "node",
              env: {
                OPENAI_API_KEY: "${OPENAI_API_KEY}",
              },
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const secrets = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("Hardcoded secret"),
      );

      expect(secrets.length).toBe(0);

      const info = result.findings.filter(
        (f) => f.severity === "INFO" && f.title.includes("passes sensitive env var"),
      );
      expect(info.length).toBe(1);
    });

    it("does not flag non-sensitive env vars", async () => {
      const configFile = join(tempDir, "safenv.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            safe: {
              command: "node",
              env: { NODE_ENV: "production", PORT: "3000" },
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const envFindings = result.findings.filter(
        (f) =>
          f.title.includes("Hardcoded secret") ||
          f.title.includes("sensitive env var"),
      );

      expect(envFindings.length).toBe(0);
    });
  });

  describe("transport checks", () => {
    it("flags plain HTTP as HIGH", async () => {
      const configFile = join(tempDir, "http.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            insecure: {
              command: "node",
              url: "http://localhost:3000",
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const http = result.findings.filter(
        (f) => f.title.includes("unencrypted HTTP"),
      );

      expect(http.length).toBe(1);
      expect(http[0].severity).toBe("HIGH");
    });

    it("flags remote HTTP as CRITICAL", async () => {
      const configFile = join(tempDir, "remote-http.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            remote: {
              command: "node",
              url: "http://api.example.com:8080/mcp",
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const remote = result.findings.filter(
        (f) =>
          f.severity === "CRITICAL" &&
          f.title.includes("connects to remote host over HTTP"),
      );

      expect(remote.length).toBe(1);
    });

    it("accepts HTTPS URLs without findings", async () => {
      const configFile = join(tempDir, "https.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            secure: {
              command: "node",
              url: "https://api.example.com/mcp",
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const transport = result.findings.filter(
        (f) =>
          f.title.includes("unencrypted HTTP") ||
          f.title.includes("remote host over HTTP"),
      );

      expect(transport.length).toBe(0);
    });

    it("flags invalid URLs as MEDIUM", async () => {
      const configFile = join(tempDir, "badurl.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            broken: { command: "node", url: "not-a-url" },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const invalid = result.findings.filter(
        (f) => f.title.includes("Invalid URL"),
      );

      expect(invalid.length).toBe(1);
      expect(invalid[0].severity).toBe("MEDIUM");
    });

    it("flags HTTP transport without URL as MEDIUM", async () => {
      const configFile = join(tempDir, "nourl.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            nourl: { command: "node", transport: "http" },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const noUrl = result.findings.filter(
        (f) => f.title.includes("HTTP transport without URL"),
      );

      expect(noUrl.length).toBe(1);
    });
  });

  describe("tool checks", () => {
    it("flags tools without description as LOW", async () => {
      const configFile = join(tempDir, "tools.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            tooled: {
              command: "node",
              tools: [{ name: "no-desc-tool" }],
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const noDesc = result.findings.filter(
        (f) => f.title.includes("lacks description"),
      );

      expect(noDesc.length).toBe(1);
      expect(noDesc[0].severity).toBe("LOW");
    });

    it("flags tools with wildcard permissions as HIGH", async () => {
      const configFile = join(tempDir, "wildtools.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            wild: {
              command: "node",
              tools: [
                {
                  name: "wild-tool",
                  description: "Overpowered",
                  permissions: ["fs:*"],
                },
              ],
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const wildcard = result.findings.filter(
        (f) => f.title.includes("wildcard permission"),
      );

      expect(wildcard.length).toBe(1);
      expect(wildcard[0].severity).toBe("HIGH");
    });
  });

  describe("result structure", () => {
    it("returns correct scanner name", async () => {
      const result = await scanMCPServer(tempDir);
      expect(result.scanner).toBe("defenseclaw-mcp-scanner");
    });

    it("returns valid timestamp and duration", async () => {
      const result = await scanMCPServer(tempDir);
      expect(() => new Date(result.timestamp)).not.toThrow();
      expect(result.duration_ns).toBeGreaterThanOrEqual(0);
    });

    it("all findings have required fields", async () => {
      const configFile = join(tempDir, "full.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            bad: {
              command: "bash",
              args: ["--no-sandbox"],
              env: { AWS_SECRET_ACCESS_KEY: "real-secret" },
              url: "http://remote.example.com",
              tools: [{ name: "t", permissions: ["*"] }],
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      expect(result.findings.length).toBeGreaterThan(0);

      for (const finding of result.findings) {
        expect(finding.id).toBeTruthy();
        expect(finding.severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$/);
        expect(finding.title).toBeTruthy();
        expect(finding.description).toBeTruthy();
        expect(finding.scanner).toBe("defenseclaw-mcp-scanner");
      }
    });
  });

  describe("combined scenarios", () => {
    it("detects multiple issues in a single server", async () => {
      const configFile = join(tempDir, "multi.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            nightmare: {
              command: "bash",
              args: ["-c", "--no-sandbox", "run.sh"],
              env: {
                OPENAI_API_KEY: "sk-real-key",
                DB_PASSWORD: "hunter2",
              },
              url: "http://evil.example.com/mcp",
            },
          },
        }),
      );

      const result = await scanMCPServer(configFile);

      const criticals = result.findings.filter(
        (f) => f.severity === "CRITICAL",
      );
      const highs = result.findings.filter((f) => f.severity === "HIGH");

      expect(criticals.length).toBeGreaterThanOrEqual(2);
      expect(highs.length).toBeGreaterThanOrEqual(2);
    });

    it("scans multiple servers in one config", async () => {
      const configFile = join(tempDir, "multi-server.json");
      await writeFile(
        configFile,
        JSON.stringify({
          mcpServers: {
            safe: { command: "node", args: ["safe.js"] },
            risky: { command: "bash", args: ["-c", "run.sh"] },
          },
        }),
      );

      const result = await scanMCPServer(configFile);
      const shellFindings = result.findings.filter(
        (f) => f.title.includes("risky") && f.title.includes("shell"),
      );

      expect(shellFindings.length).toBe(1);
    });
  });
});
