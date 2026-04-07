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

import { execFile } from "node:child_process";
import { DaemonClient } from "../client.js";
import { scanPlugin } from "../scanners/plugin_scanner/index.js";
import { scanMCPServer } from "../scanners/mcp-scanner.js";
import {
  SKILL_SCAN_TIMEOUT_MS,
  CODE_SCAN_TIMEOUT_MS,
  MAX_EXEC_BUFFER,
} from "../constants.js";
import type {
  ScanResult,
  Finding,
  Verdict,
  AdmissionResult,
  InstallType,
  Severity,
} from "../types.js";
import { compareSeverity, maxSeverity } from "../types.js";

export function runSkillScan(
  target: string,
  timeoutMs = SKILL_SCAN_TIMEOUT_MS,
): Promise<ScanResult> {
  return new Promise((resolve, reject) => {
    execFile(
      "defenseclaw",
      ["skill", "scan", target, "--json"],
      { timeout: timeoutMs, maxBuffer: MAX_EXEC_BUFFER },
      (error, stdout, stderr) => {
        const code = error && "code" in error ? (error.code as number) : 0;
        if (code !== 0 && !stdout.trim()) {
          reject(
            new Error(
              `defenseclaw skill scan exited ${code}: ${stderr.trim().slice(0, 200)}`,
            ),
          );
          return;
        }
        try {
          const data = JSON.parse(stdout);
          const findings: Finding[] = (data.findings ?? []).map(
            (f: Record<string, unknown>) => ({
              id: (f.id as string) ?? "",
              severity: (f.severity as string) ?? "INFO",
              title: (f.title as string) ?? "",
              description: (f.description as string) ?? "",
              location: (f.location as string) ?? "",
              remediation: (f.remediation as string) ?? "",
              scanner: (f.scanner as string) ?? "skill-scanner",
              tags: (f.tags as string[]) ?? [],
            }),
          );
          resolve({
            scanner: "skill-scanner",
            target,
            timestamp: new Date().toISOString(),
            findings,
          });
        } catch {
          reject(new Error("failed to parse skill scan output"));
        }
      },
    );
  });
}

/**
 * Run a CodeGuard code scan via the Go sidecar API.
 * Unlike skill scans (which shell out), CodeGuard is built into the sidecar binary.
 */
export async function runCodeScan(
  target: string,
  sidecarBaseUrl: string,
  timeoutMs = CODE_SCAN_TIMEOUT_MS,
): Promise<ScanResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(`${sidecarBaseUrl}/api/v1/scan/code`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-DefenseClaw-Client": "openclaw-plugin",
      },
      body: JSON.stringify({ path: target }),
      signal: controller.signal,
    });

    if (!res.ok) {
      const body = await res.text();
      throw new Error(`sidecar returned HTTP ${res.status}: ${body.slice(0, 200)}`);
    }

    const data = (await res.json()) as Record<string, unknown>;
    const findings: Finding[] = (
      (data.findings as Record<string, unknown>[]) ?? []
    ).map((f) => ({
      id: (f.id as string) ?? "",
      severity: ((f.severity as string) ?? "INFO") as Severity,
      title: (f.title as string) ?? "",
      description: (f.description as string) ?? "",
      location: (f.location as string) ?? "",
      remediation: (f.remediation as string) ?? "",
      scanner: (f.scanner as string) ?? "codeguard",
      tags: (f.tags as string[]) ?? [],
    }));

    return {
      scanner: "codeguard",
      target,
      timestamp: new Date().toISOString(),
      findings,
    };
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") {
      throw new Error("code scan timed out");
    }
    throw err;
  } finally {
    clearTimeout(timer);
  }
}

export interface EnforcerConfig {
  blockOnSeverity: Severity;
  warnOnSeverity: Severity;
  daemonUrl?: string;
}

const DEFAULT_CONFIG: EnforcerConfig = {
  blockOnSeverity: "HIGH",
  warnOnSeverity: "MEDIUM",
};

/**
 * PolicyEnforcer delegates admission verdicts to the Go daemon's OPA
 * engine via POST /policy/evaluate. Local block/allow caches provide a
 * fast-path negative check when the daemon is unreachable.
 */
export class PolicyEnforcer {
  private readonly client: DaemonClient;
  private readonly config: EnforcerConfig;

  private readonly localBlockList = new Map<string, string>();
  private readonly localAllowList = new Map<string, string>();

  constructor(config?: Partial<EnforcerConfig>, client?: DaemonClient) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.client =
      client ?? new DaemonClient({ baseUrl: this.config.daemonUrl });
  }

  async evaluatePlugin(
    pluginDir: string,
    pluginName: string,
  ): Promise<AdmissionResult> {
    return this.evaluate("plugin", pluginName, pluginDir, () =>
      scanPlugin(pluginDir),
    );
  }

  async evaluateSkill(
    skillDir: string,
    skillName: string,
  ): Promise<AdmissionResult> {
    return this.evaluate("skill", skillName, skillDir, () =>
      runSkillScan(skillDir),
    );
  }

  async evaluateMCPServer(
    configPath: string,
    serverName: string,
  ): Promise<AdmissionResult> {
    return this.evaluate("mcp", serverName, configPath, () =>
      scanMCPServer(configPath),
    );
  }

  async block(
    targetType: InstallType,
    name: string,
    reason: string,
  ): Promise<void> {
    const key = `${targetType}:${name}`;
    this.localBlockList.set(key, reason);
    this.localAllowList.delete(key);

    await this.client.block(targetType, name, reason).catch(() => {});
  }

  async allow(
    targetType: InstallType,
    name: string,
    reason: string,
  ): Promise<void> {
    const key = `${targetType}:${name}`;
    this.localAllowList.set(key, reason);
    this.localBlockList.delete(key);

    await this.client.allow(targetType, name, reason).catch(() => {});
  }

  async unblock(targetType: InstallType, name: string): Promise<void> {
    const key = `${targetType}:${name}`;
    this.localBlockList.delete(key);

    await this.client.unblock(targetType, name).catch(() => {});
  }

  isBlockedLocally(targetType: InstallType, name: string): boolean {
    return this.localBlockList.has(`${targetType}:${name}`);
  }

  isAllowedLocally(targetType: InstallType, name: string): boolean {
    return this.localAllowList.has(`${targetType}:${name}`);
  }

  async syncFromDaemon(): Promise<void> {
    const [blocked, allowed] = await Promise.all([
      this.client.listBlocked(),
      this.client.listAllowed(),
    ]);

    if (blocked.ok && blocked.data) {
      for (const entry of blocked.data) {
        this.localBlockList.set(
          `${entry.target_type}:${entry.target_name}`,
          entry.reason,
        );
      }
    }

    if (allowed.ok && allowed.data) {
      for (const entry of allowed.data) {
        this.localAllowList.set(
          `${entry.target_type}:${entry.target_name}`,
          entry.reason,
        );
      }
    }
  }

  private async evaluate(
    targetType: InstallType,
    name: string,
    path: string,
    scan: () => Promise<ScanResult>,
  ): Promise<AdmissionResult> {
    const key = `${targetType}:${name}`;
    const now = new Date().toISOString();

    if (this.localBlockList.has(key)) {
      const result: AdmissionResult = {
        type: targetType,
        name,
        path,
        verdict: "blocked",
        reason: `Block list: ${this.localBlockList.get(key)}`,
        timestamp: now,
      };
      await this.reportToDaemon(result);
      return result;
    }

    if (this.localAllowList.has(key)) {
      const result: AdmissionResult = {
        type: targetType,
        name,
        path,
        verdict: "allowed",
        reason: `Allow list: ${this.localAllowList.get(key)}`,
        timestamp: now,
      };
      await this.reportToDaemon(result);
      return result;
    }

    let scanResult: ScanResult | undefined;
    try {
      scanResult = await scan();
    } catch (err) {
      const result: AdmissionResult = {
        type: targetType,
        name,
        path,
        verdict: "scan-error",
        reason: `Scan failed: ${err instanceof Error ? err.message : String(err)}`,
        timestamp: now,
      };
      await this.reportToDaemon(result);
      return result;
    }

    await this.client.submitScanResult(scanResult).catch(() => {});

    const opaResult = await this.evaluateViaOPA(
      targetType,
      name,
      path,
      scanResult,
    );

    if (opaResult) {
      const result: AdmissionResult = {
        type: targetType,
        name,
        path,
        verdict: mapOPAVerdict(opaResult.verdict),
        reason: opaResult.reason || "policy decision",
        timestamp: now,
      };
      await this.reportToDaemon(result);
      return result;
    }

    const verdict = this.localDetermineVerdict(scanResult);
    const result: AdmissionResult = {
      type: targetType,
      name,
      path,
      verdict: verdict.verdict,
      reason: verdict.reason,
      timestamp: now,
    };

    await this.reportToDaemon(result);
    return result;
  }

  private async evaluateViaOPA(
    targetType: InstallType,
    name: string,
    path: string,
    scanResult: ScanResult,
  ): Promise<{ verdict: string; reason: string } | null> {
    try {
      const input: Record<string, unknown> = {
        target_type: targetType,
        target_name: name,
        path,
        scan_result: {
          max_severity: maxSeverity(scanResult.findings.map((f) => f.severity)),
          total_findings: scanResult.findings.length,
          findings: scanResult.findings.map((f) => ({
            severity: f.severity,
            title: f.title,
            scanner: f.scanner,
          })),
        },
      };

      const resp = await this.client.evaluatePolicy("admission", input);

      if (resp.ok && resp.data) {
        const wrapper = resp.data as Record<string, unknown>;
        const inner = (wrapper.data ?? wrapper) as Record<string, unknown>;
        const verdict = typeof inner.verdict === "string" ? inner.verdict : null;
        const reason = typeof inner.reason === "string" ? inner.reason : "";

        if (verdict) {
          return { verdict, reason };
        }
      }
    } catch {
      // Fall through to local evaluation.
    }
    return null;
  }

  /**
   * Local fallback when the daemon is unreachable. Mirrors the hardcoded
   * severity-threshold logic that existed before OPA integration.
   */
  private localDetermineVerdict(scanResult: ScanResult): {
    verdict: Verdict;
    reason: string;
  } {
    if (scanResult.findings.length === 0) {
      return { verdict: "clean", reason: "No findings" };
    }

    const severities = scanResult.findings.map((f) => f.severity);
    const max = maxSeverity(severities);

    if (compareSeverity(max, this.config.blockOnSeverity) >= 0) {
      const count = scanResult.findings.filter(
        (f) => compareSeverity(f.severity, this.config.blockOnSeverity) >= 0,
      ).length;
      return {
        verdict: "rejected",
        reason: `${count} finding(s) at ${this.config.blockOnSeverity} or above (max: ${max})`,
      };
    }

    if (compareSeverity(max, this.config.warnOnSeverity) >= 0) {
      const count = scanResult.findings.filter(
        (f) => compareSeverity(f.severity, this.config.warnOnSeverity) >= 0,
      ).length;
      return {
        verdict: "warning",
        reason: `${count} finding(s) at ${this.config.warnOnSeverity} or above (max: ${max})`,
      };
    }

    return {
      verdict: "clean",
      reason: `${scanResult.findings.length} finding(s), all below ${this.config.warnOnSeverity}`,
    };
  }

  private async reportToDaemon(result: AdmissionResult): Promise<void> {
    await this.client
      .logEvent({
        action: "admission",
        target: result.path,
        actor: "defenseclaw-plugin",
        severity: verdictToSeverity(result.verdict),
        details: JSON.stringify(result),
      })
      .catch(() => {});
  }
}

function mapOPAVerdict(v: string): Verdict {
  switch (v) {
    case "blocked":
      return "blocked";
    case "rejected":
      return "rejected";
    case "warning":
      return "warning";
    case "allowed":
      return "allowed";
    case "clean":
      return "clean";
    default:
      return "scan-error";
  }
}

function verdictToSeverity(verdict: Verdict): string {
  switch (verdict) {
    case "blocked":
      return "CRITICAL";
    case "rejected":
      return "HIGH";
    case "scan-error":
      return "ERROR";
    case "warning":
      return "MEDIUM";
    case "allowed":
    case "clean":
      return "INFO";
  }
}
