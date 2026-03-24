/**
 * Plugin scan policy — modeled after the skill scanner's ScanPolicy
 * (skill_scanner/core/scan_policy.py).
 *
 * A policy controls:
 * - Which analyzers run (toggles)
 * - Per-rule severity overrides
 * - Disabled rules (complete suppression)
 * - Confidence thresholds (minimum to report)
 * - Safe dotfiles allowlist
 * - Scan profile (default vs strict)
 *
 * Policies can be loaded from YAML files, presets, or constructed in code.
 * Org-specific policies merge on top of defaults (not replace).
 */
import { readFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import type { Severity, ScanProfile } from "../../types.js";

// ---------------------------------------------------------------------------
// Policy types
// ---------------------------------------------------------------------------

export interface AnalyzersPolicy {
  permissions: boolean;
  dependencies: boolean;
  installScripts: boolean;
  tools: boolean;
  source: boolean;
  directoryStructure: boolean;
  clawManifest: boolean;
  bundleSize: boolean;
  jsonConfigs: boolean;
  lockfile: boolean;
  meta: boolean;
}

export interface SeverityOverride {
  rule_id: string;
  severity: Severity;
}

export interface LLMPolicy {
  /** Enable LLM-based analysis. */
  enabled: boolean;
  /** Model name (e.g. "claude-sonnet-4-20250514"). */
  model: string;
  /** API key (read from config module at build time). */
  api_key: string;
  /** Custom API base URL. */
  api_base: string;
  /** Provider hint (litellm auto-detects from model name). */
  provider: string;
  /** Max output tokens for LLM analyzer (default 8192). */
  max_output_tokens: number;
  /** Max output tokens multiplier for meta analyzer (default 3). */
  meta_multiplier: number;
  /** Number of consensus runs (default 1). */
  consensus_runs: number;
  /** Python binary path. */
  python_binary: string;
}

export interface PluginScanPolicy {
  /** Policy name for identification. */
  policy_name: string;
  /** Policy version. */
  policy_version: string;
  /** Base scan profile. */
  profile: ScanProfile;

  /** Which analyzers are enabled. */
  analyzers: AnalyzersPolicy;

  /** Per-rule severity overrides. */
  severity_overrides: SeverityOverride[];

  /** Rules to completely suppress (by rule_id). */
  disabled_rules: string[];

  /** Minimum confidence to include a finding (0.0-1.0). */
  min_confidence: number;

  /** Safe dotfiles that should not be flagged as hidden files. */
  safe_dotfiles: string[];

  /** Max findings per deduplicated rule (cap occurrence_count reports). */
  max_findings_per_rule: number;

  /** LLM analysis configuration. */
  llm: LLMPolicy;
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

const DEFAULT_SAFE_DOTFILES = [
  ".gitignore", ".gitattributes", ".gitmodules", ".gitkeep",
  ".editorconfig", ".prettierrc", ".prettierrc.json", ".prettierignore",
  ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.cjs", ".eslintrc.yml",
  ".stylelintrc", ".stylelintignore",
  ".npmrc", ".npmignore", ".nvmrc", ".node-version",
  ".python-version", ".ruby-version", ".tool-versions",
  ".flake8", ".pylintrc", ".isort.cfg", ".mypy.ini",
  ".babelrc", ".browserslistrc", ".postcssrc",
  ".dockerignore", ".env.example", ".env.sample", ".env.template",
  ".markdownlint.json", ".markdownlintignore",
  ".yamllint", ".yamllint.yml",
  ".cursorrules", ".cursorignore",
  ".clang-format", ".clang-tidy",
  ".rubocop.yml", ".solhint.json", ".mcp.json", ".envrc",
  ".tsconfig.json",
];

function defaultAnalyzers(): AnalyzersPolicy {
  return {
    permissions: true,
    dependencies: true,
    installScripts: true,
    tools: true,
    source: true,
    directoryStructure: true,
    clawManifest: true,
    bundleSize: true,
    jsonConfigs: true,
    lockfile: true,
    meta: true,
  };
}

function defaultLLM(): LLMPolicy {
  return {
    enabled: false,
    model: "claude-sonnet-4-20250514",
    api_key: "",
    api_base: "",
    provider: "",
    max_output_tokens: 8192,
    meta_multiplier: 3,
    consensus_runs: 1,
    python_binary: "python3",
  };
}

export function defaultPolicy(): PluginScanPolicy {
  return {
    policy_name: "default",
    policy_version: "1.0",
    profile: "default",
    analyzers: defaultAnalyzers(),
    severity_overrides: [],
    disabled_rules: [],
    min_confidence: 0.0,
    safe_dotfiles: [...DEFAULT_SAFE_DOTFILES],
    max_findings_per_rule: 10,
    llm: defaultLLM(),
  };
}

// ---------------------------------------------------------------------------
// Presets
// ---------------------------------------------------------------------------

function strictPolicy(): PluginScanPolicy {
  return {
    policy_name: "strict",
    policy_version: "1.0",
    profile: "strict",
    analyzers: defaultAnalyzers(),
    severity_overrides: [
      { rule_id: "PERM-WILDCARD", severity: "HIGH" },
      { rule_id: "SRC-EVAL", severity: "HIGH" },
      { rule_id: "SRC-NEW-FUNC", severity: "HIGH" },
      { rule_id: "DEP-UNPINNED", severity: "HIGH" },
    ],
    disabled_rules: [],
    min_confidence: 0.0,
    safe_dotfiles: [
      ".gitignore", ".gitattributes", ".gitmodules", ".gitkeep",
      ".editorconfig", ".dockerignore",
    ],
    max_findings_per_rule: 20,
    llm: defaultLLM(),
  };
}

function permissivePolicy(): PluginScanPolicy {
  return {
    policy_name: "permissive",
    policy_version: "1.0",
    profile: "default",
    analyzers: {
      ...defaultAnalyzers(),
      bundleSize: false,
      lockfile: false,
      meta: false,
    },
    severity_overrides: [],
    disabled_rules: [
      "PERM-NONE",
      "TOOL-NO-DESC",
      "CLAW-TOOL-NO-DESC",
      "STRUCT-HIDDEN",
      "STRUCT-SCRIPT",
      "OBF-MINIFIED",
    ],
    min_confidence: 0.5,
    safe_dotfiles: [...DEFAULT_SAFE_DOTFILES],
    max_findings_per_rule: 5,
    llm: defaultLLM(),
  };
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

export function fromPreset(name: string): PluginScanPolicy {
  switch (name) {
    case "strict": return strictPolicy();
    case "permissive": return permissivePolicy();
    case "default": return defaultPolicy();
    default:
      throw new Error(`Unknown policy preset: "${name}". Use "default", "strict", or "permissive".`);
  }
}

/**
 * Load a policy from a YAML file and merge on top of defaults.
 * Only fields present in the YAML override the defaults.
 */
export async function fromYaml(path: string): Promise<PluginScanPolicy> {
  // js-yaml is already a dependency of the extension
  const jsYaml = await import("js-yaml");
  const parseYaml = (jsYaml.load ?? (jsYaml as { default: { load: (s: string) => unknown } }).default.load) as (s: string) => unknown;

  const raw = await readFile(path, "utf-8");
  const data = parseYaml(raw) as Record<string, unknown>;
  return mergePolicy(defaultPolicy(), data);
}

function mergePolicy(
  base: PluginScanPolicy,
  override: Record<string, unknown>,
): PluginScanPolicy {
  const result = { ...base };

  if (typeof override["policy_name"] === "string") {
    result.policy_name = override["policy_name"];
  }
  if (typeof override["policy_version"] === "string") {
    result.policy_version = override["policy_version"];
  }
  if (override["profile"] === "strict" || override["profile"] === "default") {
    result.profile = override["profile"];
  }
  if (typeof override["min_confidence"] === "number") {
    result.min_confidence = override["min_confidence"];
  }
  if (typeof override["max_findings_per_rule"] === "number") {
    result.max_findings_per_rule = override["max_findings_per_rule"];
  }

  // Merge analyzers (only override specified keys)
  if (override["analyzers"] && typeof override["analyzers"] === "object") {
    const a = override["analyzers"] as Record<string, boolean>;
    result.analyzers = { ...base.analyzers };
    for (const [key, val] of Object.entries(a)) {
      if (key in result.analyzers && typeof val === "boolean") {
        (result.analyzers as unknown as Record<string, boolean>)[key] = val;
      }
    }
  }

  // Severity overrides (replace, not merge)
  if (Array.isArray(override["severity_overrides"])) {
    result.severity_overrides = (override["severity_overrides"] as Array<Record<string, string>>)
      .filter((o) => o.rule_id && o.severity)
      .map((o) => ({ rule_id: o.rule_id, severity: o.severity as Severity }));
  }

  // Disabled rules (replace)
  if (Array.isArray(override["disabled_rules"])) {
    result.disabled_rules = override["disabled_rules"] as string[];
  }

  // Safe dotfiles (replace)
  if (Array.isArray(override["safe_dotfiles"])) {
    result.safe_dotfiles = override["safe_dotfiles"] as string[];
  }

  // LLM config (merge)
  if (override["llm"] && typeof override["llm"] === "object") {
    const l = override["llm"] as Record<string, unknown>;
    result.llm = { ...result.llm };
    if (typeof l["enabled"] === "boolean") result.llm.enabled = l["enabled"];
    if (typeof l["model"] === "string") result.llm.model = l["model"];
    if (typeof l["api_key"] === "string") result.llm.api_key = l["api_key"];
    if (typeof l["api_base"] === "string") result.llm.api_base = l["api_base"];
    if (typeof l["provider"] === "string") result.llm.provider = l["provider"];
    if (typeof l["max_output_tokens"] === "number") result.llm.max_output_tokens = l["max_output_tokens"];
    if (typeof l["meta_multiplier"] === "number") result.llm.meta_multiplier = l["meta_multiplier"];
    if (typeof l["consensus_runs"] === "number") result.llm.consensus_runs = l["consensus_runs"];
    if (typeof l["python_binary"] === "string") result.llm.python_binary = l["python_binary"];
  }

  return result;
}

// ---------------------------------------------------------------------------
// Policy application helpers
// ---------------------------------------------------------------------------

/** Get the list of disabled analyzer names from the policy. */
export function disabledAnalyzerNames(policy: PluginScanPolicy): string[] {
  const disabled: string[] = [];
  const map: Record<string, string> = {
    permissions: "permissions",
    dependencies: "dependencies",
    installScripts: "install-scripts",
    tools: "tools",
    source: "source",
    directoryStructure: "directory-structure",
    clawManifest: "claw-manifest",
    bundleSize: "bundle-size",
    jsonConfigs: "json-configs",
    lockfile: "lockfile",
    meta: "meta",
  };

  for (const [key, analyzerName] of Object.entries(map)) {
    if (!(policy.analyzers as unknown as Record<string, boolean>)[key]) {
      disabled.push(analyzerName);
    }
  }

  return disabled;
}

/** Apply severity overrides to a finding. Returns the (possibly modified) finding. */
export function applySeverityOverride(
  finding: { rule_id?: string; severity: Severity },
  overrides: SeverityOverride[],
): void {
  if (!finding.rule_id) return;
  const override = overrides.find((o) => o.rule_id === finding.rule_id);
  if (override) {
    finding.severity = override.severity;
  }
}

/** Check if a finding should be suppressed by policy or meta-analysis. */
export function isSuppressed(
  finding: { rule_id?: string; confidence?: number; suppressed?: boolean },
  policy: PluginScanPolicy,
): boolean {
  if (finding.suppressed) {
    return true;
  }
  if (finding.rule_id && policy.disabled_rules.includes(finding.rule_id)) {
    return true;
  }
  if (finding.confidence !== undefined && finding.confidence < policy.min_confidence) {
    return true;
  }
  return false;
}
