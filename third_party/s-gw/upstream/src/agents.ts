export type AgentMcpStatus = "supported" | "manual" | "planned" | "unsupported";
export type AgentSnippetFormat = "toml" | "json" | "jsonc" | "yaml" | "text";
export type AgentHookKind = "proxy" | "hook" | "plugin" | "policy" | "none";
export type CodeGuardRoute = "agent-skill" | "rule-files" | "plugin-marketplace" | "not-available";

export interface AgentSurface {
  supported: boolean;
  configPaths: string[];
  notes: string[];
}

export interface AgentMcpSurface extends AgentSurface {
  status: AgentMcpStatus;
  snippet: AgentSnippetFormat;
  writeMode: "safe" | "manual" | "unknown";
}

export interface AgentHookSurface extends AgentSurface {
  kind: AgentHookKind;
  events: string[];
}

export interface AgentProfile {
  id: string;
  displayName: string;
  aliases: string[];
  defenseClawConnector?: string;
  mcp: AgentMcpSurface;
  skills: AgentSurface;
  plugins: AgentSurface;
  hooks?: AgentHookSurface;
  limitations: string[];
}

export interface McpSnippetOptions {
  serverName?: string;
  command?: string;
  args?: string[];
  env?: Record<string, string>;
}

export interface AgentProfileSummary {
  id: string;
  displayName: string;
  aliases: string[];
  defenseClawConnector?: string;
  mcpStatus: AgentMcpStatus;
  mcpConfigPaths: string[];
  hookKind?: AgentHookKind;
  hookConfigPaths: string[];
  hookEvents: string[];
  codeGuardRoute: CodeGuardRoute;
  codeGuardInstallPaths: string[];
}

export interface AgentCodeGuardPlan {
  agentId: string;
  displayName: string;
  supported: boolean;
  route: CodeGuardRoute;
  sourceRepo: string;
  releaseArtifact?: string;
  installPaths: string[];
  commands: string[];
  notes: string[];
}

const home = "~";
const project = ".";
const codeGuardSourceRepo = "https://github.com/cosai-oasis/project-codeguard";

const codeGuardPlans: Record<string, Omit<AgentCodeGuardPlan, "agentId" | "displayName" | "sourceRepo">> = {
  claudecode: {
    supported: true,
    route: "plugin-marketplace",
    releaseArtifact: "codeguard-claude.zip",
    installPaths: ["Claude Code plugin marketplace", `${project}/.claude/skills/codeguard`],
    commands: [
      "/plugin marketplace add cosai-oasis/project-codeguard",
      "/plugin install codeguard-security@project-codeguard",
      "/reload-plugins"
    ],
    notes: [
      "Preferred path is the Claude Code plugin marketplace; the release zip is the repo-scoped fallback.",
      "CodeGuard guidance complements s-gw: CodeGuard steers generated code, while s-gw keeps credential redemption local."
    ]
  },
  codex: {
    supported: true,
    route: "agent-skill",
    releaseArtifact: "codeguard-codex.zip",
    installPaths: [`${project}/.agents/skills/codeguard`],
    commands: [
      "Download codeguard-codex.zip from the CodeGuard releases page.",
      "Unzip it and copy the .agents/ directory into the project root.",
      "Restart Codex so it discovers .agents/skills/codeguard/SKILL.md."
    ],
    notes: [
      "Use project-local .agents/skills/codeguard for the CodeGuard skill.",
      "Do not use project-local .codex/skills for CodeGuard; current CodeGuard docs call that older path stale for project discovery."
    ]
  },
  cursor: {
    supported: true,
    route: "rule-files",
    releaseArtifact: "codeguard-cursor.zip",
    installPaths: [`${project}/.cursor/rules`],
    commands: [
      "Download codeguard-cursor.zip from the CodeGuard releases page.",
      "Unzip it and copy the .cursor/ directory into the project root."
    ],
    notes: [
      "Cursor consumes the generated CodeGuard rule files from .cursor/rules.",
      "CodeGuard also emits a Cursor reviewer subagent for explicit security scans."
    ]
  },
  windsurf: {
    supported: true,
    route: "rule-files",
    releaseArtifact: "codeguard-windsurf.zip",
    installPaths: [`${project}/.windsurf/rules`],
    commands: [
      "Download codeguard-windsurf.zip from the CodeGuard releases page.",
      "Unzip it and copy the .windsurf/ directory into the project root."
    ],
    notes: ["Windsurf's ready-to-use CodeGuard bundle is rule-file based, not an s-gw credential hook."]
  },
  copilot: {
    supported: true,
    route: "rule-files",
    releaseArtifact: "codeguard-copilot.zip",
    installPaths: [`${project}/.github/instructions`],
    commands: [
      "Download codeguard-copilot.zip from the CodeGuard releases page.",
      "Unzip it and copy the .github/ directory into the project root."
    ],
    notes: ["This is repository instruction content for GitHub Copilot, separate from the s-gw MCP server registration."]
  },
  vscode: {
    supported: true,
    route: "rule-files",
    releaseArtifact: "codeguard-copilot.zip",
    installPaths: [`${project}/.github/instructions`],
    commands: [
      "Download codeguard-copilot.zip from the CodeGuard releases page.",
      "Unzip it and copy the .github/ directory into the project root."
    ],
    notes: ["VS Code Copilot Agent Mode can share GitHub Copilot repository instructions."]
  },
  antigravity: {
    supported: true,
    route: "rule-files",
    releaseArtifact: "codeguard-antigravity.zip",
    installPaths: [`${project}/.agents/rules`],
    commands: [
      "Download codeguard-antigravity.zip from the CodeGuard releases page.",
      "Unzip it and copy the .agents/rules/ directory into the project root."
    ],
    notes: ["Antigravity uses .agents/rules for CodeGuard rules; Codex uses .agents/skills in the same top-level directory."]
  },
  opencode: {
    supported: true,
    route: "agent-skill",
    releaseArtifact: "codeguard-opencode.zip",
    installPaths: [`${project}/.opencode/skills/codeguard`],
    commands: [
      "Download codeguard-opencode.zip from the CodeGuard releases page.",
      "Unzip it and copy the .opencode/ directory into the project root."
    ],
    notes: [
      "OpenCode can also load remote instruction URLs, but project-local skills are easier to audit and pin."
    ]
  },
  openclaw: {
    supported: true,
    route: "agent-skill",
    releaseArtifact: "codeguard-openclaw.zip",
    installPaths: [`${project}/.openclaw/skills/codeguard`],
    commands: [
      "Download codeguard-openclaw.zip from the CodeGuard releases page.",
      "Unzip it and copy the .openclaw/ directory into the project root."
    ],
    notes: ["OpenClaw uses the Agent Skills layout for CodeGuard."]
  },
  hermes: {
    supported: true,
    route: "agent-skill",
    releaseArtifact: "codeguard-hermes.zip",
    installPaths: [`${project}/.hermes/skills/codeguard`],
    commands: [
      "Download codeguard-hermes.zip from the CodeGuard releases page.",
      "Unzip it and copy the .hermes/ directory into the project root."
    ],
    notes: ["Hermes uses the Agent Skills layout for CodeGuard."]
  }
};

export const agentProfiles: AgentProfile[] = [
  {
    id: "openclaw",
    displayName: "OpenClaw",
    aliases: ["open-claw"],
    defenseClawConnector: "openclaw",
    mcp: {
      supported: true,
      status: "manual",
      snippet: "json",
      writeMode: "manual",
      configPaths: [`${home}/.openclaw/openclaw.json`],
      notes: ["Preferred write path is OpenClaw's own config command or UI; avoid hand-editing while OpenClaw is running."]
    },
    skills: {
      supported: true,
      configPaths: [`${project}/.openclaw/skills`, `${home}/.openclaw/workspace/skills`, `${home}/.openclaw/skills`],
      notes: ["OpenClaw may add extra skill directories from openclaw.json."]
    },
    plugins: {
      supported: true,
      configPaths: [`${home}/.openclaw/extensions`],
      notes: ["A future native extension can surface s-gw approval status inside OpenClaw."]
    },
    hooks: {
      supported: false,
      kind: "proxy",
      configPaths: [],
      events: [],
      notes: ["DefenseClaw treats OpenClaw as a proxy connector, not a native hook connector."]
    },
    limitations: ["s-gw currently uses MCP tools with local approval, not an OpenClaw fetch interceptor."]
  },
  {
    id: "zeptoclaw",
    displayName: "ZeptoClaw",
    aliases: ["zepto-claw"],
    defenseClawConnector: "zeptoclaw",
    mcp: {
      supported: true,
      status: "manual",
      snippet: "json",
      writeMode: "manual",
      configPaths: [`${home}/.zeptoclaw/config.json`, `${project}/.mcp.json`],
      notes: ["DefenseClaw treats ZeptoClaw MCP writes as manual because the ZeptoClaw app owns config autosave."]
    },
    skills: {
      supported: true,
      configPaths: [`${home}/.zeptoclaw/skills`, `${project}/.zeptoclaw/skills`],
      notes: []
    },
    plugins: {
      supported: true,
      configPaths: [`${home}/.zeptoclaw/plugins`, `${home}/.zeptoclaw/plugins/cache`],
      notes: []
    },
    hooks: {
      supported: false,
      kind: "proxy",
      configPaths: [],
      events: [],
      notes: ["DefenseClaw treats ZeptoClaw as a proxy connector, not a native hook connector."]
    },
    limitations: ["No automatic ZeptoClaw config patching yet."]
  },
  {
    id: "claudecode",
    displayName: "Claude Code",
    aliases: ["claude", "claude-code"],
    defenseClawConnector: "claudecode",
    mcp: {
      supported: true,
      status: "supported",
      snippet: "json",
      writeMode: "safe",
      // Claude Code reads MCP servers from `.mcp.json` (project scope, the shape this
      // snippet emits) or `~/.claude.json` via `claude mcp add` - NOT `settings.json`,
      // which only holds hooks/permissions/env.
      configPaths: [`${project}/.mcp.json`, `${home}/.claude.json`],
      notes: [
        "Recommended: `claude mcp add --transport stdio --scope user s-gw -- s-gw-mcp` (writes ~/.claude.json).",
        "Or commit this snippet as project-scoped `.mcp.json`. Do not paste it into ~/.claude/settings.json; Claude Code does not read MCP servers from settings.json."
      ]
    },
    skills: {
      supported: true,
      configPaths: [`${home}/.claude/skills`, `${project}/.claude/skills`],
      notes: []
    },
    plugins: {
      supported: true,
      configPaths: [`${home}/.claude/plugins`, `${project}/.claude/plugins`],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.claude/settings.json`, `${project}/.claude/settings.json`],
      events: ["UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop"],
      notes: ["DefenseClaw writes Claude Code hooks and telemetry env there; keep MCP config separate."]
    },
    limitations: []
  },
  {
    id: "codex",
    displayName: "Codex",
    aliases: ["openai-codex"],
    defenseClawConnector: "codex",
    mcp: {
      supported: true,
      status: "supported",
      snippet: "toml",
      writeMode: "safe",
      configPaths: [`${home}/.codex/config.toml`, `${project}/.mcp.json`],
      notes: ["Codex can use a global config.toml MCP server or project-local .mcp.json."]
    },
    skills: {
      supported: true,
      configPaths: [`${home}/.codex/skills`, `${project}/.agents/skills`],
      notes: [
        "User-level Codex skills can live under CODEX_HOME (~/.codex/skills by default).",
        "Project-local Codex skills should use .agents/skills; project-local .codex/skills is not a documented discovery path."
      ]
    },
    plugins: {
      supported: true,
      configPaths: [`${home}/.codex/plugins`, `${home}/.codex/plugins/cache`],
      notes: ["s-gw already ships a Codex plugin manifest."]
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.codex/config.toml`],
      events: ["SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop", "Notify"],
      notes: ["DefenseClaw wires Codex hooks, native OTel, and notify bridge in config.toml."]
    },
    limitations: ["s-gw does not rely on Codex hook tables; MCP tools carry the workflow."]
  },
  {
    id: "hermes",
    displayName: "Hermes Agent",
    aliases: ["hermes-agent"],
    defenseClawConnector: "hermes",
    mcp: {
      supported: true,
      status: "manual",
      snippet: "yaml",
      writeMode: "manual",
      configPaths: [`${home}/.hermes/config.yaml`],
      notes: ["Hermes MCP configuration is YAML-shaped."]
    },
    skills: {
      supported: true,
      configPaths: [`${project}/.hermes/skills`, `${home}/.hermes/skills`],
      notes: []
    },
    plugins: {
      supported: true,
      configPaths: [`${home}/.hermes/plugins`, `${project}/.hermes/plugins`],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.hermes/config.yaml`],
      events: ["pre_llm_call", "pre_tool_call", "post_tool_call", "post_llm_call", "on_session_start", "on_session_end", "subagent_stop"],
      notes: ["Hermes can block pre_tool_call; native ask is not available in DefenseClaw's current contract."]
    },
    limitations: ["No automatic YAML patcher yet."]
  },
  {
    id: "cursor",
    displayName: "Cursor",
    aliases: [],
    defenseClawConnector: "cursor",
    mcp: {
      supported: true,
      status: "supported",
      snippet: "json",
      writeMode: "safe",
      configPaths: [`${project}/.cursor/mcp.json`, `${home}/.cursor/mcp.json`],
      notes: ["Project-local Cursor MCP config is preferred for team reproducibility."]
    },
    skills: {
      supported: true,
      configPaths: [`${project}/.cursor/skills`, `${project}/.agents/skills`, `${home}/.cursor/skills`, `${home}/.agents/skills`],
      notes: []
    },
    plugins: {
      supported: false,
      configPaths: [],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.cursor/hooks.json`],
      events: ["beforeShellExecution", "beforeMCPExecution", "beforeReadFile", "beforeTabFileRead", "beforeSubmitPrompt", "stop"],
      notes: ["Cursor supports native ask only on beforeShellExecution and beforeMCPExecution."]
    },
    limitations: []
  },
  {
    id: "windsurf",
    displayName: "Windsurf",
    aliases: ["codeium-windsurf"],
    defenseClawConnector: "windsurf",
    mcp: {
      supported: true,
      status: "manual",
      snippet: "json",
      writeMode: "manual",
      configPaths: [`${home}/.codeium/windsurf/mcp_config.json`, `${home}/.codeium/windsurf/mcp.json`],
      notes: ["DefenseClaw only writes Windsurf MCP config when an existing documented file is present."]
    },
    skills: {
      supported: false,
      configPaths: [],
      notes: []
    },
    plugins: {
      supported: false,
      configPaths: [],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.codeium/windsurf/hooks.json`],
      events: ["pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"],
      notes: ["Windsurf can block through Cascade hooks; native ask is not available in DefenseClaw's current contract."]
    },
    limitations: ["Do not guess new Windsurf config paths during install."]
  },
  {
    id: "geminicli",
    displayName: "Gemini CLI",
    aliases: ["gemini", "gemini-cli"],
    defenseClawConnector: "geminicli",
    mcp: {
      supported: true,
      status: "supported",
      snippet: "json",
      writeMode: "safe",
      configPaths: [`${home}/.gemini/settings.json`, `${project}/.gemini/settings.json`],
      notes: ["Gemini CLI reads MCP servers from settings.json."]
    },
    skills: {
      supported: true,
      configPaths: [`${project}/.gemini/skills`, `${project}/.agents/skills`, `${home}/.gemini/skills`],
      notes: []
    },
    plugins: {
      supported: true,
      configPaths: [`${project}/.gemini/extensions`, `${home}/.gemini/extensions`],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.gemini/settings.json`],
      events: ["BeforeAgent", "BeforeModel", "BeforeTool", "AfterTool", "AfterAgent"],
      notes: ["Gemini CLI has no native ask surface in DefenseClaw's current contract."]
    },
    limitations: []
  },
  {
    id: "copilot",
    displayName: "GitHub Copilot CLI",
    aliases: ["copilot-cli", "github-copilot", "github-copilot-cli"],
    defenseClawConnector: "copilot",
    mcp: {
      supported: true,
      status: "supported",
      snippet: "json",
      writeMode: "safe",
      configPaths: [`${home}/.copilot/mcp-config.json`, `${project}/.github/mcp.json`, `${project}/.mcp.json`],
      notes: ["Workspace .github/mcp.json is the safest install target when present."]
    },
    skills: {
      supported: true,
      configPaths: [`${project}/.github/skills`, `${project}/.agents/skills`, `${home}/.copilot/skills`],
      notes: []
    },
    plugins: {
      supported: true,
      configPaths: ["Copilot CLI marketplace/plugin flow"],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.copilot/hooks/defenseclaw.json`, `${project}/.github/hooks/defenseclaw.json`],
      events: ["preToolUse", "permissionRequest", "agentStop", "subagentStop", "postToolUseFailure"],
      notes: ["Copilot CLI supports native ask on preToolUse."]
    },
    limitations: []
  },
  {
    id: "openhands",
    displayName: "OpenHands",
    aliases: ["open-hands"],
    defenseClawConnector: "openhands",
    mcp: {
      supported: true,
      status: "manual",
      snippet: "json",
      writeMode: "manual",
      configPaths: [`${home}/.openhands/mcp.json`],
      notes: ["DefenseClaw discovers OpenHands MCP servers from ~/.openhands/mcp.json; hooks are configured separately."]
    },
    skills: {
      supported: true,
      configPaths: [
        `${project}/.agents/skills`,
        `${project}/.openhands/skills`,
        `${project}/.openhands/microagents`,
        `${home}/.agents/skills`,
        `${home}/.openhands/skills`,
        `${home}/.openhands/microagents`,
        `${home}/.openhands/skills/installed`,
        `${home}/.openhands/cache/skills/public-skills/skills`
      ],
      notes: ["OpenHands has no documented plugin install surface; skills and microagents are discovery surfaces."]
    },
    plugins: {
      supported: false,
      configPaths: [],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.openhands/hooks.json`, `${project}/.openhands/hooks.json`],
      events: ["user_prompt_submit", "pre_tool_use", "post_tool_use", "stop"],
      notes: ["OpenHands can deny supported hook events but has no native ask/approval surface."]
    },
    limitations: ["Profile borrowed from DefenseClaw 0.8.3; s-gw has not run a hands-on OpenHands smoke test yet."]
  },
  {
    id: "antigravity",
    displayName: "Antigravity",
    aliases: ["agy", "google-antigravity"],
    defenseClawConnector: "antigravity",
    mcp: {
      supported: true,
      status: "manual",
      snippet: "json",
      writeMode: "manual",
      configPaths: [`${home}/.gemini/config/mcp_config.json`, `${project}/.agents/mcp_config.json`],
      notes: ["Antigravity uses mcp_config.json with a top-level mcpServers object; hooks live in a separate global hooks.json file."]
    },
    skills: {
      supported: true,
      configPaths: [
        `${project}/.agents/skills`,
        `${project}/_agents/skills`,
        `${home}/.gemini/antigravity-cli/skills`,
        `${home}/.gemini/skills`,
        `${home}/.agents/skills`
      ],
      notes: ["DefenseClaw also scans plugin-contained skills when plugin directories exist."]
    },
    plugins: {
      supported: true,
      configPaths: [
        `${project}/.agents/plugins`,
        `${project}/_agents/plugins`,
        `${home}/.gemini/config/plugins`,
        `${home}/.gemini/antigravity-cli/plugins`
      ],
      notes: ["DefenseClaw treats plugin-contained agents as discovery surfaces until Google publishes stable install semantics."]
    },
    hooks: {
      supported: true,
      kind: "hook",
      configPaths: [`${home}/.gemini/config/hooks.json`],
      events: ["PreInvocation", "PreToolUse", "PostToolUse", "PostInvocation", "Stop"],
      notes: ["DefenseClaw writes only the canonical global hook path to avoid duplicate hook firings; decision=ask can force Antigravity's native prompt."]
    },
    limitations: ["Profile borrowed from DefenseClaw 0.8.3; s-gw has not installed or verified Antigravity hooks yet."]
  },
  {
    id: "opencode",
    displayName: "OpenCode",
    aliases: ["open-code"],
    defenseClawConnector: "opencode",
    mcp: {
      supported: true,
      status: "supported",
      snippet: "jsonc",
      writeMode: "safe",
      configPaths: [`${home}/.config/opencode/opencode.json`, `${home}/.config/opencode/opencode.jsonc`, `${project}/opencode.json`, `${project}/opencode.jsonc`],
      notes: ["s-gw safely merges the user-level JSONC `mcp` entry; project config can intentionally override it."]
    },
    skills: {
      supported: true,
      configPaths: [
        `${project}/.opencode/skills`,
        `${project}/.claude/skills`,
        `${project}/.agents/skills`,
        `${home}/.config/opencode/skills`,
        `${home}/.claude/skills`,
        `${home}/.agents/skills`,
        "$OPENCODE_CONFIG_DIR/skills"
      ],
      notes: ["s-gw installs its user-level skill under the active OpenCode config directory."]
    },
    plugins: {
      supported: true,
      configPaths: [`${project}/.opencode/plugins`, `${home}/.config/opencode/plugins`, "$OPENCODE_CONFIG_DIR/plugins"],
      notes: ["OpenCode auto-loads local plugins from ~/.config/opencode/plugins."]
    },
    hooks: {
      supported: true,
      kind: "plugin",
      configPaths: [`${home}/.config/opencode/plugins/defenseclaw.js`],
      events: ["tool.execute.before", "tool.execute.after"],
      notes: ["DefenseClaw blocks OpenCode by throwing from a JS bridge plugin; OpenCode has no hook-driven native ask surface."]
    },
    limitations: []
  },
  {
    id: "omnigent",
    displayName: "OmniGent",
    aliases: ["omni-gent", "omniagent", "omni-agent"],
    defenseClawConnector: "omnigent",
    mcp: {
      supported: false,
      status: "planned",
      snippet: "text",
      writeMode: "unknown",
      configPaths: ["$OMNIGENT_CONFIG_HOME/config.yaml", `${home}/.omnigent/config.yaml`],
      notes: ["DefenseClaw integrates OmniGent through a custom Python policy bridge, not by writing a normal MCP server entry."]
    },
    skills: {
      supported: false,
      configPaths: [],
      notes: ["DefenseClaw v1 does not modify OmniGent skill, rule, plugin, MCP, or agent-bundle configuration."]
    },
    plugins: {
      supported: false,
      configPaths: [],
      notes: []
    },
    hooks: {
      supported: true,
      kind: "policy",
      configPaths: ["$OMNIGENT_CONFIG_HOME/config.yaml", `${home}/.omnigent/config.yaml`],
      events: ["request", "tool_call", "tool_result", "response", "llm_request", "llm_response"],
      notes: ["OmniGent has native ASK on pre-action phases through its custom policy API; s-gw needs a policy bridge before public support."]
    },
    limitations: ["No s-gw MCP snippet yet; this profile is a roadmap marker for an OmniGent policy bridge."]
  },
  {
    id: "vscode",
    displayName: "VS Code / GitHub Copilot Agent Mode",
    aliases: ["vs-code", "github-copilot-agent", "copilot-agent"],
    mcp: {
      supported: true,
      status: "supported",
      snippet: "json",
      writeMode: "safe",
      configPaths: ["VS Code default user profile mcp.json", `${project}/.vscode/mcp.json`],
      notes: ["s-gw manages the default user profile; named, portable, and custom user-data profiles remain explicit."]
    },
    skills: {
      supported: true,
      configPaths: [`${home}/.agents/skills`, `${home}/.copilot/skills`, `${project}/.agents/skills`, `${project}/.github/skills`],
      notes: ["VS Code discovers personal Agent Skills from ~/.agents/skills and ~/.copilot/skills."]
    },
    plugins: {
      supported: false,
      configPaths: [],
      notes: []
    },
    hooks: {
      supported: false,
      kind: "none",
      configPaths: [],
      events: [],
      notes: ["s-gw currently treats VS Code through MCP only."]
    },
    limitations: ["Automatic registration targets only VS Code's default stable user profile."]
  }
];

export function listAgentProfiles(): AgentProfileSummary[] {
  return agentProfiles.map((profile) => ({
    id: profile.id,
    displayName: profile.displayName,
    aliases: profile.aliases,
    defenseClawConnector: profile.defenseClawConnector,
    mcpStatus: profile.mcp.status,
    mcpConfigPaths: profile.mcp.configPaths,
    hookKind: profile.hooks?.kind,
    hookConfigPaths: profile.hooks?.configPaths || [],
    hookEvents: profile.hooks?.events || [],
    codeGuardRoute: codeGuardPlans[profile.id]?.route || "not-available",
    codeGuardInstallPaths: codeGuardPlans[profile.id]?.installPaths || []
  }));
}

export function resolveAgentProfile(input: string): AgentProfile {
  const wanted = normalizeAgentName(input);
  const found = agentProfiles.find((profile) => {
    if (profile.id === wanted) {
      return true;
    }

    if (profile.defenseClawConnector === wanted) {
      return true;
    }

    return profile.aliases.some((alias) => normalizeAgentName(alias) === wanted);
  });

  if (!found) {
    throw new Error(`Unknown agent '${input}'. Run 's-gw agent list' to see known profiles.`);
  }

  return found;
}

export function renderAgentMcpSnippet(input: string, options: McpSnippetOptions = {}): string {
  const profile = resolveAgentProfile(input);
  if (!profile.mcp.supported) {
    throw new Error(`${profile.displayName} does not have a supported s-gw MCP snippet yet.`);
  }

  const server = buildServerEntry(options, profile.displayName);
  const name = options.serverName || "s-gw";

  if (profile.id === "codex") {
    return renderCodexToml(name, server);
  }

  if (profile.id === "opencode") {
    return renderOpenCodeJsonc(name, server);
  }

  if (profile.id === "vscode") {
    return renderVSCodeJson(name, server);
  }

  if (profile.id === "copilot") {
    return renderCopilotJson(name, server);
  }

  if (profile.id === "hermes") {
    return renderHermesYaml(name, server);
  }

  if (profile.id === "openclaw" || profile.id === "zeptoclaw") {
    return JSON.stringify({ mcp: { servers: { [name]: server } } }, null, 2);
  }

  return JSON.stringify({ mcpServers: { [name]: server } }, null, 2);
}

export function getAgentCodeGuardPlan(input: string): AgentCodeGuardPlan {
  const profile = resolveAgentProfile(input);
  const plan = codeGuardPlans[profile.id];
  if (!plan) {
    return {
      agentId: profile.id,
      displayName: profile.displayName,
      supported: false,
      route: "not-available",
      sourceRepo: codeGuardSourceRepo,
      installPaths: [],
      commands: [],
      notes: [
        "Project CodeGuard does not publish a ready-to-use bundle for this agent yet.",
        "Keep using s-gw MCP/guard mode for local secret handling; add CodeGuard only through a documented rule or skill surface."
      ]
    };
  }

  return {
    agentId: profile.id,
    displayName: profile.displayName,
    sourceRepo: codeGuardSourceRepo,
    ...plan
  };
}

function normalizeAgentName(input: string): string {
  return input.trim().toLowerCase().replace(/[\s_]+/g, "-").replace(/^-+|-+$/g, "");
}

function buildServerEntry(options: McpSnippetOptions, agentName: string) {
  return {
    command: options.command || "s-gw-mcp",
    args: options.args || [],
    env: {
      SGW_HOME: "~/.s-gw",
      SGW_AGENT_NAME: agentName,
      ...(options.env || {})
    }
  };
}

function renderCodexToml(name: string, server: ReturnType<typeof buildServerEntry>): string {
  const lines = [
    `[mcp_servers.${name}]`,
    `command = ${JSON.stringify(server.command)}`,
    `args = ${JSON.stringify(server.args)}`
  ];

  const envPairs = Object.entries(server.env).map(([key, value]) => `${key} = ${JSON.stringify(value)}`);
  if (envPairs.length > 0) {
    lines.push(`env = { ${envPairs.join(", ")} }`);
  }

  lines.push('startup_timeout_sec = 10', 'tool_timeout_sec = 60', 'default_tools_approval_mode = "prompt"');
  return lines.join("\n");
}

function renderOpenCodeJsonc(name: string, server: ReturnType<typeof buildServerEntry>): string {
  return JSON.stringify(
    {
      $schema: "https://opencode.ai/config.json",
      mcp: {
        [name]: {
          type: "local",
          command: [server.command, ...server.args],
          enabled: true,
          environment: server.env
        }
      }
    },
    null,
    2
  );
}

function renderVSCodeJson(name: string, server: ReturnType<typeof buildServerEntry>): string {
  return JSON.stringify(
    {
      servers: {
        [name]: {
          type: "stdio",
          command: server.command,
          args: server.args,
          env: server.env
        }
      }
    },
    null,
    2
  );
}

function renderCopilotJson(name: string, server: ReturnType<typeof buildServerEntry>): string {
  return JSON.stringify(
    {
      mcpServers: {
        [name]: {
          type: "local",
          ...server,
          tools: ["*"]
        }
      }
    },
    null,
    2
  );
}

function renderHermesYaml(name: string, server: ReturnType<typeof buildServerEntry>): string {
  const lines = ["mcp:", "  servers:", `    ${name}:`, `      command: ${server.command}`, "      args:"];
  if (server.args.length === 0) {
    lines.push("        []");
  } else {
    for (const arg of server.args) {
      lines.push(`        - ${JSON.stringify(arg)}`);
    }
  }

  lines.push("      env:");
  for (const [key, value] of Object.entries(server.env)) {
    lines.push(`        ${key}: ${JSON.stringify(value)}`);
  }

  return lines.join("\n");
}
