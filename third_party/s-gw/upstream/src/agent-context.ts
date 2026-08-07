import { execFileSync } from "node:child_process";
import type { AgentIdentitySource } from "./types.js";

export type { AgentIdentitySource } from "./types.js";

export interface AgentIdentity {
  name: string;
  source: AgentIdentitySource;
}

export interface AgentIdentityContext {
  agentName?: string;
  mcpClientName?: string;
  env?: NodeJS.ProcessEnv;
}

export function agentNameFromReason(reason: string): string {
  return knownAgentNameFromText(reason) || "Agent";
}

export function requestAgentName(reason: string, env: NodeJS.ProcessEnv = process.env): string {
  return requestAgentIdentity(reason, { env }).name;
}

export function requestAgentIdentity(reason: string, context: AgentIdentityContext = {}): AgentIdentity {
  const env = context.env || process.env;
  const configured = cleanAgentName(context.agentName || env.SGW_AGENT_NAME || env.SGW_REQUEST_AGENT_NAME);
  if (configured) {
    return { name: configured, source: "configured" };
  }

  const mcpClient = agentNameFromMcpClient(context.mcpClientName);
  if (mcpClient) {
    return { name: mcpClient, source: "mcp-client" };
  }

  const runtime = detectRuntimeAgentName(env);
  if (runtime) {
    return { name: runtime, source: "runtime" };
  }

  const processAgent = detectProcessTreeAgentName(env);
  if (processAgent) {
    return { name: processAgent, source: "process" };
  }

  const fromReason = agentNameFromReason(reason);
  if (fromReason !== "Agent") {
    return { name: fromReason, source: "reason" };
  }

  return { name: "Agent", source: "unknown" };
}

export function agentNameFromMcpClient(value?: string): string | undefined {
  const cleaned = String(value || "").trim();
  if (!cleaned) {
    return undefined;
  }

  const known = knownAgentNameFromText(cleaned);
  if (known && known !== "MCP") {
    return known;
  }

  const generic = cleaned.toLowerCase().replace(/[^a-z0-9]+/g, "");
  if (["agent", "client", "mcp", "mcpclient", "modelcontextprotocol"].includes(generic)) {
    return undefined;
  }

  return cleanAgentName(cleaned);
}

export function detectRuntimeAgentName(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const explicit = cleanAgentName(env.SGW_AGENT_NAME || env.SGW_REQUEST_AGENT_NAME);
  if (explicit) {
    return explicit;
  }

  const guardAgent = cleanAgentName(env.SGW_GUARD_AGENT);
  if (guardAgent) {
    return displayNameForAgentId(guardAgent);
  }

  const bundleId = String(env.__CFBundleIdentifier || "").toLowerCase();
  if (hasAnyEnv(env, ["CODEX_SHELL", "CODEX_THREAD_ID", "CODEX_CI", "CODEX_INTERNAL_ORIGINATOR_OVERRIDE"]) || bundleId.includes("codex")) {
    return "Codex";
  }
  if (hasAnyEnv(env, ["CLAUDECODE", "CLAUDE_CODE", "CLAUDECODE_CLI", "CLAUDE_PROJECT_DIR"]) || bundleId.includes("claude")) {
    return "Claude";
  }
  if (hasAnyEnv(env, ["CURSOR_TRACE_ID", "CURSOR_AGENT", "CURSOR_SESSION_ID"]) || bundleId.includes("cursor")) {
    return "Cursor";
  }
  if (hasAnyEnv(env, ["OPENCODE", "OPENCODE_SESSION", "OPENCODE_AGENT"]) || bundleId.includes("opencode")) {
    return "OpenCode";
  }
  if (hasAnyEnv(env, ["GEMINI_CLI", "GEMINI_AGENT"]) || bundleId.includes("gemini")) {
    return "Gemini";
  }
  if (hasAnyEnv(env, ["GITHUB_COPILOT_TOKEN", "COPILOT_AGENT", "COPILOT_CLI"]) || bundleId.includes("copilot")) {
    return "GitHub Copilot";
  }
  if (hasAnyEnv(env, ["WINDSURF_AGENT", "WINDSURF_SESSION"]) || bundleId.includes("windsurf")) {
    return "Windsurf";
  }

  return undefined;
}

export function detectProcessTreeAgentName(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const fixture = env.SGW_AGENT_PROCESS_TREE;
  if (fixture) {
    return knownAgentNameFromText(fixture);
  }

  if (env.SGW_DISABLE_PROCESS_AGENT_DETECTION === "1") {
    return undefined;
  }

  return knownAgentNameFromText(readParentProcessTree());
}

function hasAnyEnv(env: NodeJS.ProcessEnv, keys: string[]): boolean {
  return keys.some((key) => {
    const value = env[key];
    return value !== undefined && String(value).trim() !== "";
  });
}

function cleanAgentName(value?: string): string | undefined {
  const cleaned = String(value || "").trim();
  if (!cleaned) {
    return undefined;
  }
  return displayNameForAgentId(cleaned);
}

function knownAgentNameFromText(value: string): string | undefined {
  const lower = String(value || "").toLowerCase();
  if (lower.includes("opencode") || lower.includes("open code")) return "OpenCode";
  if (lower.includes("openclaw")) return "OpenClaw";
  if (lower.includes("zeptoclaw")) return "ZeptoClaw";
  if (lower.includes("claude-code") || lower.includes("claudecode") || lower.includes("claude")) return "Claude";
  if (lower.includes("github-copilot") || lower.includes("github copilot") || lower.includes("copilot")) return "GitHub Copilot";
  if (lower.includes("gemini")) return "Gemini";
  if (lower.includes("windsurf")) return "Windsurf";
  if (lower.includes("hermes")) return "Hermes";
  if (lower.includes("openhands")) return "OpenHands";
  if (lower.includes("antigravity") || lower.includes("/agy") || lower.includes(" agy")) return "Antigravity";
  if (lower.includes("omnigent") || lower.includes("omniagent")) return "OmniGent";
  if (lower.includes("cursor")) return "Cursor";
  if (lower.includes("codex") || lower.includes("com.openai.codex")) return "Codex";
  if (lower.includes("console")) return "Console";
  if (lower.includes("mcp")) return "MCP";
  return undefined;
}

function readParentProcessTree(): string {
  let pid = process.ppid;
  const rows: string[] = [];

  for (let depth = 0; depth < 8 && pid > 1; depth += 1) {
    const row = readProcessRow(pid);
    if (!row) {
      break;
    }
    rows.push(row.text);
    pid = row.parentPid;
  }

  return rows.join("\n");
}

function readProcessRow(pid: number): { parentPid: number; text: string } | undefined {
  try {
    const output = execFileSync("/bin/ps", ["-p", String(pid), "-o", "ppid=", "-o", "command="], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 250
    }).trim();
    if (!output) {
      return undefined;
    }

    const match = output.match(/^(\d+)\s+([\s\S]+)$/);
    if (!match) {
      return undefined;
    }

    return {
      parentPid: Number(match[1]),
      text: match[2]
    };
  } catch {
    return undefined;
  }
}

function displayNameForAgentId(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/g, "");
  if (normalized === "codex") return "Codex";
  if (normalized === "claude" || normalized === "claudecode") return "Claude";
  if (normalized === "cursor") return "Cursor";
  if (normalized === "opencode") return "OpenCode";
  if (normalized === "gemini" || normalized === "geminicli") return "Gemini";
  if (normalized === "githubcopilot" || normalized === "copilot" || normalized === "copilotcli") return "GitHub Copilot";
  if (normalized === "windsurf") return "Windsurf";
  if (normalized === "openclaw") return "OpenClaw";
  if (normalized === "zeptoclaw") return "ZeptoClaw";
  if (normalized === "hermes") return "Hermes";
  if (normalized === "openhands") return "OpenHands";
  if (normalized === "antigravity" || normalized === "agy") return "Antigravity";
  if (normalized === "omnigent" || normalized === "omniagent") return "OmniGent";
  if (normalized === "console") return "Console";
  if (normalized === "mcp") return "MCP";
  return value.trim();
}
