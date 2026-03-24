import { DaemonClient } from "../client.js";
import { scanPlugin } from "../scanners/plugin-scanner.js";
import { scanMCPServer } from "../scanners/mcp-scanner.js";
import type {
  ScanResult,
  Verdict,
  AdmissionResult,
  InstallType,
  Severity,
} from "../types.js";
import { compareSeverity, maxSeverity } from "../types.js";

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

  constructor(config?: Partial<EnforcerConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.client = new DaemonClient({ baseUrl: this.config.daemonUrl });
  }

  async evaluatePlugin(
    pluginDir: string,
    pluginName: string,
  ): Promise<AdmissionResult> {
    return this.evaluate("plugin", pluginName, pluginDir, () =>
      scanPlugin(pluginDir),
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
    case "rejected":
      return "ERROR";
    case "scan-error":
      return "WARN";
    case "warning":
      return "WARN";
    case "allowed":
    case "clean":
      return "INFO";
  }
}
