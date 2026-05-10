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

import { readFile, readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import type {
  Finding,
  ScanResult,
  Severity,
  MCPServerConfig,
} from "../types.js";

const SCANNER_NAME = "defenseclaw-mcp-scanner";

// keep this list in lockstep with the cross-runtime
// AI provider credential set (cli/defenseclaw/scanner/_llm_env.py and
// internal/configs/providers.json). Pre-fix the scanner only flagged
// OpenAI/Anthropic/AWS keys, so a malicious MCP config could inline
// a Google/Gemini/Azure/Mistral provider token and still admit cleanly.
const DANGEROUS_ENV_KEYS = new Set([
  // AWS
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "AWS_ACCESS_KEY_ID",
  // AI provider credentials (must mirror Python+Go provider tables)
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GOOGLE_API_KEY",
  "GEMINI_API_KEY",
  "GOOGLE_GENERATIVE_AI_API_KEY",
  "AZURE_OPENAI_API_KEY",
  "AZURE_API_KEY",
  "MISTRAL_API_KEY",
  "COHERE_API_KEY",
  "DEEPSEEK_API_KEY",
  "TOGETHER_API_KEY",
  "GROQ_API_KEY",
  "PERPLEXITY_API_KEY",
  "VOYAGE_API_KEY",
  "FIREWORKS_API_KEY",
  "HUGGINGFACE_TOKEN",
  "HF_TOKEN",
  "REPLICATE_API_TOKEN",
  // Source control / repo tokens
  "GITHUB_TOKEN",
  "GITHUB_PAT",
  "GITLAB_TOKEN",
  // Generic credential-bearing keys
  "DATABASE_URL",
  "DB_PASSWORD",
  "SECRET_KEY",
  "PRIVATE_KEY",
  "API_KEY",
  "API_TOKEN",
  "ACCESS_TOKEN",
  "AUTH_TOKEN",
  "BEARER_TOKEN",
  "CLIENT_SECRET",
]);

const DANGEROUS_COMMANDS = new Set([
  "bash",
  "sh",
  "zsh",
  "cmd",
  "powershell",
  "pwsh",
  "curl",
  "wget",
]);

const SUSPICIOUS_ARG_PATTERNS = [
  { pattern: /--no-sandbox/i, title: "MCP server disables sandboxing" },
  { pattern: /--allow-all/i, title: "MCP server requests unrestricted access" },
  { pattern: /--privileged/i, title: "MCP server runs with elevated privileges" },
  { pattern: /--disable-security/i, title: "MCP server disables security controls" },
];

interface MCPLoadResult {
  configs: MCPServerConfig[];
  parseErrors: { path: string; reason: string }[];
}

export async function scanMCPServer(
  configPathOrDir: string,
): Promise<ScanResult> {
  const start = Date.now();
  const target = resolve(configPathOrDir);
  const findings: Finding[] = [];

  const { configs, parseErrors } = await loadMCPConfigs(target);

  // Every JSON/YAML parse or read failure that previously was
  // swallowed (returned []) MUST now surface as a real scanner
  // finding. Severity HIGH so admission policies that block on
  // HIGH (the default profile and stricter) refuse to admit the
  // install instead of silently classifying the target as clean /
  // "No MCP configurations found". An additional admission-side
  // defence already exists from the Go scanner subprocess path
  // (scanners fail closed on non-zero exit), but TS scanners run
  // inside the Node host and cannot rely on a subprocess exit
  // code, so the parse-error finding IS the signal admission
  // consumes.
  for (const err of parseErrors) {
    findings.push(
      makeFinding(
        findings.length + 1,
        "HIGH",
        `MCP config parse error: ${err.path.split("/").pop() ?? err.path}`,
        {
          description:
            `Failed to read or parse MCP config "${err.path}": ${err.reason}. ` +
            "An unparseable config means the scanner cannot inspect the " +
            "server registration the runtime will actually load. The " +
            "admission policy treats this as a scanner failure and refuses " +
            "to admit the target.",
          location: err.path,
          remediation:
            "Fix the YAML/JSON syntax, repair file permissions, or remove " +
            "the unreadable file from the MCP config directory.",
        },
      ),
    );
  }

  if (configs.length === 0 && parseErrors.length === 0) {
    findings.push(
      makeFinding(findings.length + 1, "INFO", "No MCP server configurations found", {
        description: `No MCP server configs found at "${target}".`,
        location: target,
      }),
    );
    return buildResult(target, findings, start);
  }

  for (const config of configs) {
    checkMCPConfig(config, findings, target);
  }

  return buildResult(target, findings, start);
}

async function loadMCPConfigs(target: string): Promise<MCPLoadResult> {
  const configs: MCPServerConfig[] = [];
  const parseErrors: { path: string; reason: string }[] = [];

  try {
    const info = await stat(target);

    if (info.isFile()) {
      const result = await parseConfigFile(target);
      configs.push(...result.configs);
      if (result.error) parseErrors.push({ path: target, reason: result.error });
    } else if (info.isDirectory()) {
      const entries = await readdir(target);
      for (const entry of entries) {
        if (!entry.endsWith(".json") && !entry.endsWith(".yaml") && !entry.endsWith(".yml"))
          continue;

        const fullPath = join(target, entry);
        const result = await parseConfigFile(fullPath);
        configs.push(...result.configs);
        if (result.error) parseErrors.push({ path: fullPath, reason: result.error });
      }
    }
  } catch (err) {
    // stat / readdir failure on the target itself is itself a
    // scanner failure — record it instead of silently returning an
    // empty config set so admission can fail closed.
    parseErrors.push({
      path: target,
      reason: err instanceof Error ? err.message : String(err),
    });
  }

  return { configs, parseErrors };
}

interface ParseResult {
  configs: MCPServerConfig[];
  error?: string;
}

async function parseConfigFile(filePath: string): Promise<ParseResult> {
  try {
    const raw = await readFile(filePath, "utf-8");
    let parsed: Record<string, unknown>;
    if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
      const yaml = await import("js-yaml");
      const loaded = yaml.load(raw, { schema: yaml.JSON_SCHEMA });
      parsed =
        loaded !== null && typeof loaded === "object" && !Array.isArray(loaded)
          ? (loaded as Record<string, unknown>)
          : {};
    } else {
      parsed = JSON.parse(raw) as Record<string, unknown>;
    }
    return { configs: extractMCPServers(parsed, filePath) };
  } catch (err) {
    return {
      configs: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

function extractMCPServers(
  data: Record<string, unknown>,
  source: string,
): MCPServerConfig[] {
  const servers: MCPServerConfig[] = [];

  const mcpServers =
    (data["mcpServers"] as Record<string, unknown>) ??
    (data["mcp_servers"] as Record<string, unknown>) ??
    (data["mcp-servers"] as Record<string, unknown>);

  if (mcpServers && typeof mcpServers === "object") {
    for (const [name, value] of Object.entries(mcpServers)) {
      if (value && typeof value === "object") {
        const cfg = value as Record<string, unknown>;
        servers.push({
          name,
          command: cfg["command"] as string | undefined,
          args: cfg["args"] as string[] | undefined,
          env: cfg["env"] as Record<string, string> | undefined,
          url: cfg["url"] as string | undefined,
          transport: cfg["transport"] as MCPServerConfig["transport"],
          tools: cfg["tools"] as MCPServerConfig["tools"],
          enabled: cfg["enabled"] !== false,
        });
      }
    }
  }

  if (servers.length === 0 && data["command"]) {
    servers.push({
      name: source.split("/").pop() ?? "unknown",
      command: data["command"] as string,
      args: data["args"] as string[] | undefined,
      env: data["env"] as Record<string, string> | undefined,
      url: data["url"] as string | undefined,
      transport: data["transport"] as MCPServerConfig["transport"],
    });
  }

  return servers;
}

function checkMCPConfig(
  config: MCPServerConfig,
  findings: Finding[],
  target: string,
): void {
  checkCommand(config, findings, target);
  checkArgs(config, findings, target);
  checkEnvVars(config, findings, target);
  checkTransport(config, findings, target);
  checkTools(config, findings, target);
}

function checkCommand(
  config: MCPServerConfig,
  findings: Finding[],
  target: string,
): void {
  if (!config.command) return;

  const cmd = config.command.split("/").pop() ?? config.command;

  if (DANGEROUS_COMMANDS.has(cmd)) {
    findings.push(
      makeFinding(findings.length + 1, "HIGH", `MCP server "${config.name}" uses shell as command`, {
        description:
          `Server "${config.name}" launches "${cmd}" directly. ` +
          "Running a bare shell as an MCP server enables arbitrary command execution.",
        location: `${target} → mcp:${config.name}`,
        remediation:
          "Use a purpose-built MCP server binary instead of a shell. " +
          "If a shell wrapper is required, validate all inputs and restrict available commands.",
      }),
    );
  }
}

function checkArgs(
  config: MCPServerConfig,
  findings: Finding[],
  target: string,
): void {
  if (!config.args) return;

  const argStr = config.args.join(" ");

  for (const { pattern, title } of SUSPICIOUS_ARG_PATTERNS) {
    if (pattern.test(argStr)) {
      findings.push(
        makeFinding(findings.length + 1, "HIGH", `${title} (${config.name})`, {
          description:
            `MCP server "${config.name}" uses argument matching "${pattern.source}" ` +
            "which weakens security controls.",
          location: `${target} → mcp:${config.name}`,
          remediation:
            "Remove security-weakening arguments. Use scoped permissions instead.",
        }),
      );
    }
  }
}

function checkEnvVars(
  config: MCPServerConfig,
  findings: Finding[],
  target: string,
): void {
  if (!config.env) return;

  for (const [key, value] of Object.entries(config.env)) {
    if (DANGEROUS_ENV_KEYS.has(key.toUpperCase())) {
      const hasInlineValue =
        typeof value === "string" && value.length > 0 && !value.startsWith("${");

      if (hasInlineValue) {
        findings.push(
          makeFinding(
            findings.length + 1,
            "CRITICAL",
            `Hardcoded secret in MCP config: ${key}`,
            {
              description:
                `MCP server "${config.name}" has sensitive environment variable "${key}" ` +
                "with a hardcoded value in the configuration file. " +
                "Credentials in config files are considered compromised.",
              location: `${target} → mcp:${config.name} → env.${key}`,
              remediation:
                "Remove the hardcoded value. Use environment variable references " +
                '(e.g., "${ENV_VAR}") or a secrets manager instead.',
            },
          ),
        );
      } else {
        // pre-fix this branch emitted INFO, which the
        // enforcer's severity threshold (default warnOnSeverity=MEDIUM)
        // collapsed to a `clean` verdict. A malicious MCP config could
        // then ask for OPENAI_API_KEY / GITHUB_TOKEN / AWS_SECRET_ACCESS_KEY
        // by reference and still pass admission while receiving the
        // host credential at runtime. Bump to HIGH so admission falls
        // into the warn/block branch — operators that explicitly trust
        // an MCP server with a credential can still allow it via the
        // approval flow.
        findings.push(
          makeFinding(
            findings.length + 1,
            "HIGH",
            `MCP server requests sensitive env var by reference: ${key}`,
            {
              description:
                `MCP server "${config.name}" requests sensitive environment variable "${key}" ` +
                "by reference (e.g. \"${...}\"). Even when the value is not inline in the " +
                "config, exposing this credential to a third-party MCP server may leak it " +
                "to the runtime; admission must require explicit operator approval.",
              location: `${target} → mcp:${config.name} → env.${key}`,
              remediation:
                "Remove the sensitive env reference, or explicitly approve the MCP server " +
                "via `defenseclaw mcp approve` after verifying the credential is required " +
                "and scoped minimally.",
            },
          ),
        );
      }
    }
  }
}

/**
 * Detect IPs / hostnames that point at private, loopback, link-local,
 * or cloud metadata destinations. ("Private and
 * metadata MCP URLs over HTTPS are accepted without findings"): the
 * legacy check only reasoned about `protocol === "https:"`, so any
 * https://10.0.0.5, https://169.254.169.254, etc. slipped through.
 */
function classifyMCPHost(hostname: string): "loopback" | "private" | "metadata" | "public" {
  const host = hostname.toLowerCase();
  if (
    host === "localhost" ||
    host === "ip6-localhost" ||
    host === "ip6-loopback" ||
    host.endsWith(".localhost")
  ) {
    return "loopback";
  }

  // IPv4 metadata endpoints used by AWS / GCP / Azure / Oracle / DO.
  if (
    host === "169.254.169.254" ||
    host === "metadata.google.internal" ||
    host === "fd00:ec2::254"
  ) {
    return "metadata";
  }

  // IPv4 dotted-quad classification.
  const v4 = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const oct = v4.slice(1, 5).map((s) => Number(s));
    if (oct.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return "public";
    const [a, b] = oct;
    if (a === 127) return "loopback";
    if (a === 10) return "private";
    if (a === 172 && b >= 16 && b <= 31) return "private";
    if (a === 192 && b === 168) return "private";
    if (a === 169 && b === 254) return "private"; // link-local
    if (a === 0) return "private"; // unspecified
    return "public";
  }

  // IPv6 literals (RFC3986 bracket-stripped).
  const stripped = host.startsWith("[") && host.endsWith("]")
    ? host.slice(1, -1)
    : host;
  if (stripped === "::1" || stripped === "0:0:0:0:0:0:0:1") return "loopback";
  if (stripped === "::" || stripped === "0:0:0:0:0:0:0:0") return "private";
  if (stripped.startsWith("fc") || stripped.startsWith("fd")) return "private"; // ULA fc00::/7
  if (stripped.startsWith("fe80:")) return "private"; // link-local
  if (stripped.startsWith("::ffff:127.")) return "loopback"; // IPv4-mapped loopback

  return "public";
}

function checkTransport(
  config: MCPServerConfig,
  findings: Finding[],
  target: string,
): void {
  if (config.url) {
    try {
      const url = new URL(config.url);

      if (url.protocol === "http:") {
        findings.push(
          makeFinding(
            findings.length + 1,
            "HIGH",
            `MCP server "${config.name}" uses unencrypted HTTP`,
            {
              description:
                `Server "${config.name}" connects via plain HTTP (${config.url}). ` +
                "MCP traffic may contain sensitive data and tool invocations.",
              location: `${target} → mcp:${config.name}`,
              remediation:
                "Use HTTPS (TLS 1.2+) for all MCP server connections. " +
                "For local development, use stdio transport instead.",
            },
          ),
        );
      }

      // ("Private and metadata MCP URLs over HTTPS
      // are accepted without findings"): classify the host regardless
      // of scheme so https://127.0.0.1, https://10.0.0.5,
      // https://169.254.169.254, etc. are all flagged. The legacy
      // "remote over HTTP" finding stays for plain-http remote
      // endpoints.
      const hostClass = classifyMCPHost(url.hostname);
      if (hostClass === "metadata") {
        findings.push(
          makeFinding(
            findings.length + 1,
            "CRITICAL",
            `MCP server "${config.name}" targets a cloud metadata endpoint`,
            {
              description:
                `Server "${config.name}" points at metadata host "${url.hostname}". ` +
                "Cloud metadata endpoints expose IAM credentials and host " +
                "configuration; an MCP server connecting there can " +
                "exfiltrate cloud secrets through tool calls.",
              location: `${target} → mcp:${config.name}`,
              remediation:
                "Remove the metadata-host MCP entry. If the workload genuinely " +
                "needs to read metadata, do it from a vetted server-side helper " +
                "rather than expose it to an MCP client.",
            },
          ),
        );
      } else if (hostClass === "loopback") {
        findings.push(
          makeFinding(
            findings.length + 1,
            "MEDIUM",
            `MCP server "${config.name}" targets a loopback host`,
            {
              description:
                `Server "${config.name}" connects to loopback host "${url.hostname}". ` +
                "Loopback MCP endpoints can be used to reach unauthenticated " +
                "developer tooling running on the same host. Confirm that " +
                "exposing this service to the agent is intentional.",
              location: `${target} → mcp:${config.name}`,
              remediation:
                "Prefer stdio transport for local MCP servers, or pin to a " +
                "trusted UNIX socket. Document the local-only intent.",
            },
          ),
        );
      } else if (hostClass === "private") {
        findings.push(
          makeFinding(
            findings.length + 1,
            "HIGH",
            `MCP server "${config.name}" targets a private/link-local host`,
            {
              description:
                `Server "${config.name}" connects to private host "${url.hostname}". ` +
                "Private-range MCP endpoints can reach internal services " +
                "(databases, admin panels, link-local self-targets) that " +
                "should not normally be exposed to an agent.",
              location: `${target} → mcp:${config.name}`,
              remediation:
                "Use a public, authenticated MCP endpoint or restrict the " +
                "internal service with an explicit allow-list.",
            },
          ),
        );
      }

      if (
        hostClass === "public" &&
        url.protocol !== "https:"
      ) {
        findings.push(
          makeFinding(
            findings.length + 1,
            "CRITICAL",
            `MCP server "${config.name}" connects to remote host over HTTP`,
            {
              description:
                `Server "${config.name}" connects to remote host "${url.hostname}" without TLS. ` +
                "This exposes all MCP traffic to interception.",
              location: `${target} → mcp:${config.name}`,
              remediation: "Use HTTPS for all remote MCP connections.",
            },
          ),
        );
      }

      if (url.username || url.password) {
        findings.push(
          makeFinding(
            findings.length + 1,
            "HIGH",
            `MCP server "${config.name}" embeds inline credentials in URL`,
            {
              description:
                `Server "${config.name}" URL "${config.url}" carries inline ` +
                "userinfo. URLs end up in browser history, proxy logs, " +
                "process listings, and crash reports; embedded passwords " +
                "are considered compromised.",
              location: `${target} → mcp:${config.name}`,
              remediation:
                "Move the credential into the server's auth configuration " +
                "(env vars, keyring, or an Authorization header).",
            },
          ),
        );
      }
    } catch {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", `Invalid URL for MCP server "${config.name}"`, {
          description: `Cannot parse URL "${config.url}" for server "${config.name}".`,
          location: `${target} → mcp:${config.name}`,
          remediation: "Provide a valid URL for the MCP server.",
        }),
      );
    }
  }

  if (config.transport === "http" && !config.url) {
    findings.push(
      makeFinding(
        findings.length + 1,
        "MEDIUM",
        `MCP server "${config.name}" uses HTTP transport without URL`,
        {
          description:
            `Server "${config.name}" declares HTTP transport but no URL is configured.`,
          location: `${target} → mcp:${config.name}`,
          remediation: "Configure the server URL with HTTPS endpoint.",
        },
      ),
    );
  }
}

function checkTools(
  config: MCPServerConfig,
  findings: Finding[],
  target: string,
): void {
  if (!config.tools) return;

  for (const tool of config.tools) {
    if (!tool.description) {
      findings.push(
        makeFinding(
          findings.length + 1,
          "LOW",
          `MCP tool "${tool.name}" on "${config.name}" lacks description`,
          {
            description:
              "Tools without descriptions cannot be reviewed for safety by users.",
            location: `${target} → mcp:${config.name} → tool:${tool.name}`,
            remediation: "Add a description to every MCP tool.",
          },
        ),
      );
    }

    if (tool.permissions) {
      for (const perm of tool.permissions) {
        if (perm.endsWith(":*") || perm === "*") {
          findings.push(
            makeFinding(
              findings.length + 1,
              "HIGH",
              `MCP tool "${tool.name}" requests wildcard permission`,
              {
                description:
                  `Tool "${tool.name}" on server "${config.name}" requests wildcard permission "${perm}".`,
                location: `${target} → mcp:${config.name} → tool:${tool.name}`,
                remediation: "Scope tool permissions to specific resources.",
              },
            ),
          );
        }
      }
    }
  }
}

function makeFinding(
  id: number,
  severity: Severity,
  title: string,
  opts: {
    description: string;
    location?: string;
    remediation?: string;
  },
): Finding {
  return {
    id: `mcp-${id}`,
    severity,
    title,
    description: opts.description,
    location: opts.location,
    remediation: opts.remediation,
    scanner: SCANNER_NAME,
  };
}

function buildResult(
  target: string,
  findings: Finding[],
  startMs: number,
): ScanResult {
  return {
    scanner: SCANNER_NAME,
    target,
    timestamp: new Date().toISOString(),
    findings,
    duration_ns: (Date.now() - startMs) * 1_000_000,
  };
}
