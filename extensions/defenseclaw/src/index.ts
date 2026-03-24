/**
 * DefenseClaw OpenClaw Plugin
 *
 * Integrates DefenseClaw security into the OpenClaw plugin lifecycle:
 *
 * Boot-time:
 *  - Syncs block/allow lists from the Go daemon
 *  - Starts the filesystem watcher as a background service
 *  - On gateway_start: runs native TS scans on all plugins and MCP servers
 *
 * Lifecycle hooks:
 *  - skill_install / skill_uninstall: admission gate for skills
 *  - mcp_connect / mcp_disconnect: admission gate for MCP servers
 *
 * Slash commands:
 *  - /scan <path>: scan a skill directory
 *  - /block <type> <name> [reason]: block a skill, MCP, or plugin
 *  - /allow <type> <name> [reason]: allow-list a skill, MCP, or plugin
 *
 * The plugin uses:
 *  1. Native TS scanners for plugins and MCP configs (in-process, fast)
 *  2. CLI shell-out to `defenseclaw` for skill/code scans (full scanner suite)
 *  3. REST API to the Go daemon for policy state and audit logging
 */

import { definePluginEntry } from "@openclaw/plugin-sdk";
import { spawn, execFile } from "node:child_process";
import type { ChildProcess } from "node:child_process";
import { DaemonClient } from "./client.js";
import { PolicyEnforcer } from "./policy/enforcer.js";
import { scanPlugin } from "./scanners/plugin-scanner.js";
import { scanMCPServer } from "./scanners/mcp-scanner.js";
import type {
  ScanResult,
  ScanReport,
  AdmissionResult,
  Finding,
  InstallType,
} from "./types.js";
import { compareSeverity, maxSeverity } from "./types.js";

function runDefenseClaw(
  args: string[],
  timeoutMs = 300_000,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve) => {
    execFile(
      "defenseclaw",
      args,
      { timeout: timeoutMs, maxBuffer: 10 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error && "code" in error ? (error.code as number) : 0;
        resolve({ stdout: stdout.toString(), stderr: stderr.toString(), code });
      },
    );
  });
}

function formatFindings(findings: Finding[], limit = 15): string[] {
  const lines: string[] = [];
  const sorted = [...findings].sort(
    (a, b) => compareSeverity(b.severity, a.severity),
  );

  for (const f of sorted.slice(0, limit)) {
    const loc = f.location ? ` (${f.location})` : "";
    lines.push(`- **[${f.severity}]** ${f.title}${loc}`);
  }

  if (findings.length > limit) {
    lines.push(`- ... and ${findings.length - limit} more`);
  }

  return lines;
}

function formatAdmissionResult(result: AdmissionResult): string {
  const icon =
    result.verdict === "clean" || result.verdict === "allowed"
      ? "PASS"
      : result.verdict === "warning"
        ? "WARN"
        : "FAIL";

  return `[${icon}] ${result.type} "${result.name}": ${result.verdict} — ${result.reason}`;
}

export default definePluginEntry(({ api, registerService, registerCommand }) => {
  const client = new DaemonClient();
  const enforcer = new PolicyEnforcer();

  let watcherProc: ChildProcess | null = null;

  // ─── Background service: filesystem watcher ───

  registerService("defenseclaw-watcher", {
    start: async () => {
      enforcer.syncFromDaemon().catch(() => {});

      watcherProc = spawn("defenseclaw", ["watch", "--json-events"], {
        stdio: ["ignore", "pipe", "pipe"],
      });

      watcherProc.stdout?.on("data", (chunk: Buffer) => {
        const lines = chunk.toString().split("\n").filter(Boolean);
        for (const line of lines) {
          try {
            const evt: AdmissionResult = JSON.parse(line);
            console.log(`[defenseclaw] ${formatAdmissionResult(evt)}`);
          } catch {
            // non-JSON output from watcher
          }
        }
      });

      watcherProc.stderr?.on("data", (chunk: Buffer) => {
        console.error(`[defenseclaw-watcher] ${chunk.toString().trimEnd()}`);
      });

      watcherProc.on("exit", (code) => {
        console.log(`[defenseclaw-watcher] exited with code ${code}`);
        watcherProc = null;
      });

      return {
        stop: () => {
          watcherProc?.kill("SIGTERM");
          watcherProc = null;
        },
      };
    },
  });

  // ─── Lifecycle: gateway_start ───

  api.on("gateway_start", async () => {
    console.log("[defenseclaw] gateway started — running boot scans...");

    const cliScan = runDefenseClaw(["scan", "--json"]).then(({ stdout, code }) => {
      if (code !== 0) {
        console.error("[defenseclaw] CLI scan failed on boot");
        return;
      }
      try {
        const report: ScanReport = JSON.parse(stdout);
        if (report.clean) {
          console.log("[defenseclaw] CLI scan: all clean");
        } else {
          console.log(
            `[defenseclaw] CLI scan: ${report.total_findings} findings (max: ${report.max_severity})`,
          );
          for (const r of report.results) {
            const critical = r.findings.filter(
              (f) =>
                f.severity === "CRITICAL" || f.severity === "HIGH",
            );
            if (critical.length > 0) {
              console.log(
                `[defenseclaw] ${r.scanner}: ${critical.length} HIGH/CRITICAL in ${r.target}`,
              );
            }
          }
        }
      } catch {
        console.error("[defenseclaw] failed to parse CLI scan report");
      }
    });

    await cliScan;
  });

  // ─── Lifecycle: skill install/uninstall ───

  api.on("skill_install", async (event: { name: string; path: string }) => {
    console.log(`[defenseclaw] skill install detected: ${event.name}`);

    const result = await enforcer.evaluatePlugin(event.path, event.name);
    console.log(`[defenseclaw] ${formatAdmissionResult(result)}`);

    if (result.verdict === "rejected" || result.verdict === "blocked") {
      console.log(
        `[defenseclaw] BLOCKED skill "${event.name}": ${result.reason}`,
      );
    }
  });

  api.on("skill_uninstall", async (event: { name: string; path: string }) => {
    console.log(`[defenseclaw] skill uninstalled: ${event.name}`);
    await client
      .logEvent({
        action: "skill.uninstall",
        target: event.path,
        actor: "openclaw",
        severity: "INFO",
        details: JSON.stringify({ name: event.name }),
      })
      .catch(() => {});
  });

  // ─── Lifecycle: MCP connect/disconnect ───

  api.on("mcp_connect", async (event: { name: string; config_path?: string }) => {
    console.log(`[defenseclaw] MCP server connecting: ${event.name}`);

    if (event.config_path) {
      const result = await enforcer.evaluateMCPServer(
        event.config_path,
        event.name,
      );
      console.log(`[defenseclaw] ${formatAdmissionResult(result)}`);
    } else {
      console.log(
        `[defenseclaw] MCP "${event.name}" connected (no config path — skipping scan)`,
      );
    }
  });

  api.on("mcp_disconnect", async (event: { name: string }) => {
    console.log(`[defenseclaw] MCP server disconnected: ${event.name}`);
    await client
      .logEvent({
        action: "mcp.disconnect",
        target: event.name,
        actor: "openclaw",
        severity: "INFO",
        details: JSON.stringify({ name: event.name }),
      })
      .catch(() => {});
  });

  // ─── Slash command: /scan ───

  registerCommand("/scan", {
    description: "Scan a skill, plugin, or MCP config with DefenseClaw",
    args: [
      { name: "target", description: "Path to skill/plugin directory or MCP config", required: true },
      { name: "type", description: "Scan type: skill (default), plugin, mcp", required: false },
    ],
    handler: async ({ args }) => {
      const target = args.target as string | undefined;
      if (!target) {
        return { text: "Usage: /scan <path> [skill|plugin|mcp]" };
      }

      const scanType = (args.type ?? "skill") as string;

      if (scanType === "plugin") {
        return handlePluginScan(target);
      }

      if (scanType === "mcp") {
        return handleMCPScan(target);
      }

      return handleSkillScan(target);
    },
  });

  // ─── Slash command: /block ───

  registerCommand("/block", {
    description: "Block a skill, MCP server, or plugin",
    args: [
      { name: "type", description: "Target type: skill, mcp, plugin", required: true },
      { name: "name", description: "Name of the target to block", required: true },
      { name: "reason", description: "Reason for blocking", required: false },
    ],
    handler: async ({ args }) => {
      const targetType = args.type as InstallType | undefined;
      const name = args.name as string | undefined;
      if (!targetType || !name) {
        return { text: "Usage: /block <skill|mcp|plugin> <name> [reason]" };
      }

      const reason = (args.reason as string) || "Blocked via /block command";

      await enforcer.block(targetType, name, reason);
      return {
        text: `Blocked ${targetType} **${name}**: ${reason}`,
      };
    },
  });

  // ─── Slash command: /allow ───

  registerCommand("/allow", {
    description: "Allow-list a skill, MCP server, or plugin",
    args: [
      { name: "type", description: "Target type: skill, mcp, plugin", required: true },
      { name: "name", description: "Name of the target to allow", required: true },
      { name: "reason", description: "Reason for allowing", required: false },
    ],
    handler: async ({ args }) => {
      const targetType = args.type as InstallType | undefined;
      const name = args.name as string | undefined;
      if (!targetType || !name) {
        return { text: "Usage: /allow <skill|mcp|plugin> <name> [reason]" };
      }

      const reason = (args.reason as string) || "Allowed via /allow command";

      await enforcer.allow(targetType, name, reason);
      return {
        text: `Allow-listed ${targetType} **${name}**: ${reason}`,
      };
    },
  });
});

// ─── Scan handlers ───

async function handlePluginScan(target: string): Promise<{ text: string }> {
  try {
    const result = await scanPlugin(target);
    return { text: formatScanOutput("Plugin", target, result) };
  } catch (err) {
    return {
      text: `Plugin scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleMCPScan(target: string): Promise<{ text: string }> {
  try {
    const result = await scanMCPServer(target);
    return { text: formatScanOutput("MCP", target, result) };
  } catch (err) {
    return {
      text: `MCP scan failed: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

async function handleSkillScan(target: string): Promise<{ text: string }> {
  const { stdout, stderr, code } = await runDefenseClaw([
    "skill",
    "scan",
    target,
    "--json",
  ]);

  if (code !== 0) {
    return { text: `Scan failed:\n\`\`\`\n${stderr}\n\`\`\`` };
  }

  try {
    const report: ScanReport = JSON.parse(stdout);
    const lines: string[] = [`**DefenseClaw Scan: ${target}**\n`];

    if (report.clean) {
      lines.push("Verdict: **CLEAN**");
    } else {
      lines.push(
        `Verdict: **${report.max_severity}** (${report.total_findings} findings)\n`,
      );

      for (const result of report.results ?? []) {
        if (result.findings.length > 0) {
          lines.push(`\n**${result.scanner}:**`);
          lines.push(...formatFindings(result.findings, 10));
        }
      }
    }

    return { text: lines.join("\n") };
  } catch {
    return { text: `Scan output:\n\`\`\`\n${stdout}\n\`\`\`` };
  }
}

function formatScanOutput(
  scanType: string,
  target: string,
  result: ScanResult,
): string {
  const lines: string[] = [`**DefenseClaw ${scanType} Scan: ${target}**\n`];

  if (result.findings.length === 0) {
    lines.push("Verdict: **CLEAN** — no findings");
    return lines.join("\n");
  }

  const max = maxSeverity(result.findings.map((f) => f.severity));
  lines.push(
    `Verdict: **${max}** (${result.findings.length} finding${result.findings.length === 1 ? "" : "s"})\n`,
  );
  lines.push(...formatFindings(result.findings));

  return lines.join("\n");
}
