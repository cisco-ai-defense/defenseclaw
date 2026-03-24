import { readFile, readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import type {
  Finding,
  ScanResult,
  Severity,
  MCPServerConfig,
} from "../types.js";

const SCANNER_NAME = "defenseclaw-mcp-scanner";

const DANGEROUS_ENV_KEYS = new Set([
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "OPENAI_API_KEY",
  "ANTHROPIC_API_KEY",
  "GITHUB_TOKEN",
  "DATABASE_URL",
  "DB_PASSWORD",
  "SECRET_KEY",
  "PRIVATE_KEY",
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

export async function scanMCPServer(
  configPathOrDir: string,
): Promise<ScanResult> {
  const start = Date.now();
  const target = resolve(configPathOrDir);
  const findings: Finding[] = [];

  const configs = await loadMCPConfigs(target);

  if (configs.length === 0) {
    findings.push(
      makeFinding(1, "INFO", "No MCP server configurations found", {
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

async function loadMCPConfigs(target: string): Promise<MCPServerConfig[]> {
  const configs: MCPServerConfig[] = [];

  try {
    const info = await stat(target);

    if (info.isFile()) {
      const parsed = await parseConfigFile(target);
      configs.push(...parsed);
    } else if (info.isDirectory()) {
      const entries = await readdir(target);
      for (const entry of entries) {
        if (!entry.endsWith(".json") && !entry.endsWith(".yaml") && !entry.endsWith(".yml"))
          continue;

        const fullPath = join(target, entry);
        const parsed = await parseConfigFile(fullPath);
        configs.push(...parsed);
      }
    }
  } catch {
    return configs;
  }

  return configs;
}

async function parseConfigFile(filePath: string): Promise<MCPServerConfig[]> {
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
    return extractMCPServers(parsed, filePath);
  } catch {
    return [];
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
        findings.push(
          makeFinding(
            findings.length + 1,
            "INFO",
            `MCP server passes sensitive env var: ${key}`,
            {
              description:
                `MCP server "${config.name}" passes sensitive environment variable "${key}". ` +
                "Ensure this follows the principle of least privilege.",
              location: `${target} → mcp:${config.name} → env.${key}`,
              remediation:
                "Verify the MCP server requires this credential and that it is scoped minimally.",
            },
          ),
        );
      }
    }
  }
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

      if (
        url.hostname !== "localhost" &&
        url.hostname !== "127.0.0.1" &&
        url.hostname !== "::1" &&
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
