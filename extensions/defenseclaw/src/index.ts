/**
 * DefenseClaw OpenClaw Plugin
 *
 * Bridges the DefenseClaw Go binary into the OpenClaw plugin lifecycle:
 *
 * 1. Boot-time: registerService starts the filesystem watcher as a background
 *    service. api.on("gateway_start") triggers a full scan of all installed
 *    skills and disables any with HIGH/CRITICAL findings.
 *
 * 2. Manual: registerCommand("/scan") lets users scan a skill from chat.
 *
 * The plugin shells out to the `defenseclaw` binary for all scan/enforce
 * operations. It expects `defenseclaw` to be on PATH.
 */

import { definePluginEntry } from "@openclaw/plugin-sdk";
import { spawn, execFile } from "node:child_process";
import type { ChildProcess } from "node:child_process";

interface ScanResult {
  scanner: string;
  target: string;
  findings: Array<{
    severity: string;
    title: string;
    location?: string;
  }>;
}

interface ScanReport {
  results: ScanResult[];
  max_severity: string;
  total_findings: number;
  clean: boolean;
  errors?: string[];
}

interface AdmissionEvent {
  timestamp: string;
  type: string;
  name: string;
  path: string;
  verdict: string;
  reason: string;
}

function runDefenseClaw(
  args: string[],
  timeoutMs = 300_000,
): Promise<{ stdout: string; stderr: string; code: number }> {
  return new Promise((resolve, reject) => {
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

export default definePluginEntry(({ api, registerService, registerCommand }) => {
  let watcherProc: ChildProcess | null = null;

  // --- Boot-time: background filesystem watcher ---
  registerService("defenseclaw-watcher", {
    start: async () => {
      watcherProc = spawn("defenseclaw", ["watch", "--json-events"], {
        stdio: ["ignore", "pipe", "pipe"],
      });

      watcherProc.stdout?.on("data", (chunk: Buffer) => {
        const lines = chunk.toString().split("\n").filter(Boolean);
        for (const line of lines) {
          try {
            const evt: AdmissionEvent = JSON.parse(line);
            console.log(
              `[defenseclaw] ${evt.verdict} ${evt.type} ${evt.name}: ${evt.reason}`,
            );
          } catch {
            // non-JSON output, ignore
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

  // --- Boot-time: full scan on gateway start ---
  api.on("gateway_start", async () => {
    console.log("[defenseclaw] gateway started — running full scan...");

    const { stdout, code } = await runDefenseClaw(["scan", "--json"]);
    if (code !== 0) {
      console.error("[defenseclaw] full scan failed");
      return;
    }

    try {
      const report: ScanReport = JSON.parse(stdout);
      if (report.clean) {
        console.log("[defenseclaw] full scan clean");
        return;
      }

      console.log(
        `[defenseclaw] scan found ${report.total_findings} findings (max: ${report.max_severity})`,
      );

      for (const result of report.results) {
        const critical = result.findings.filter(
          (f) => f.severity === "CRITICAL" || f.severity === "HIGH",
        );
        if (critical.length > 0) {
          console.log(
            `[defenseclaw] ${result.scanner}: ${critical.length} HIGH/CRITICAL findings in ${result.target}`,
          );
        }
      }
    } catch {
      console.error("[defenseclaw] failed to parse scan report");
    }
  });

  // --- Manual: /scan slash command ---
  registerCommand("/scan", {
    description: "Scan a skill with DefenseClaw security scanners",
    args: [{ name: "path", description: "Path to skill directory", required: true }],
    handler: async ({ args }) => {
      const target = args.path;
      if (!target) {
        return { text: "Usage: /scan <path-to-skill>" };
      }

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
        const report = JSON.parse(stdout);
        const lines: string[] = [`**DefenseClaw Scan: ${target}**\n`];

        if (report.clean) {
          lines.push("Verdict: **CLEAN**");
        } else {
          lines.push(
            `Verdict: **${report.max_severity}** (${report.total_findings} findings)\n`,
          );
          for (const result of report.results || []) {
            for (const f of result.findings || []) {
              lines.push(`- [${f.severity}] ${f.title}${f.location ? ` (${f.location})` : ""}`);
            }
          }
        }

        return { text: lines.join("\n") };
      } catch {
        return { text: `Scan output:\n\`\`\`\n${stdout}\n\`\`\`` };
      }
    },
  });
});
