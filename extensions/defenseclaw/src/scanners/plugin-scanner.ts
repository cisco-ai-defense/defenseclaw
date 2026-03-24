import { readFile, readdir, stat, access } from "node:fs/promises";
import { join, basename, resolve } from "node:path";
import type {
  Finding,
  ScanResult,
  ScanMetadata,
  Severity,
  PluginManifest,
  ToolManifest,
} from "../types.js";

const SCANNER_NAME = "defenseclaw-plugin-scanner";

const DANGEROUS_PERMISSIONS = new Set([
  "fs:write",
  "fs:*",
  "net:*",
  "shell:exec",
  "shell:*",
  "env:read",
  "env:*",
  "system:*",
  "crypto:*",
]);

const SUSPICIOUS_TOOL_PATTERNS: Array<{
  pattern: RegExp;
  title: string;
  tags: string[];
}> = [
  { pattern: /\beval\s*\(/i, title: "Plugin uses eval-like execution", tags: ["code-execution"] },
  { pattern: /\bnew\s+Function\s*\(/i, title: "Plugin uses dynamic Function constructor", tags: ["code-execution"] },
  { pattern: /\bexec\s*\(/i, title: "Plugin may execute shell commands", tags: ["code-execution"] },
  { pattern: /\bchild_process\b/i, title: "Plugin references child_process", tags: ["code-execution"] },
  { pattern: /\bfs\.write/i, title: "Plugin performs filesystem writes", tags: ["code-execution"] },
  { pattern: /\bprocess\.env\b/i, title: "Plugin accesses environment variables", tags: ["credential-theft"] },
  {
    pattern: /\b(?:fetch|http|https|request)\s*\(/i,
    title: "Plugin makes network requests",
    tags: ["exfiltration"],
  },
  { pattern: /\bDeno\.run\b/i, title: "Plugin uses Deno.run for command execution", tags: ["code-execution"] },
  { pattern: /\bBun\.spawn\b/i, title: "Plugin uses Bun.spawn for command execution", tags: ["code-execution"] },
  { pattern: /\bnet\.createServer\b/i, title: "Plugin creates a network server", tags: ["gateway-manipulation"] },
  { pattern: /\bhttp\.createServer\b/i, title: "Plugin creates an HTTP server", tags: ["gateway-manipulation"] },
  { pattern: /\bWebSocket\b/i, title: "Plugin uses WebSocket connections", tags: ["exfiltration"] },
];

const DANGEROUS_INSTALL_SCRIPTS = new Set(["preinstall", "postinstall", "install"]);

const SHELL_COMMANDS_IN_SCRIPTS = /\b(?:curl|wget|bash|sh|powershell|nc|ncat)\b/i;

const C2_DOMAINS = new Set([
  "webhook.site",
  "ngrok.io",
  "ngrok-free.app",
  "pipedream.net",
  "requestbin.com",
  "hookbin.com",
  "burpcollaborator.net",
  "interact.sh",
  "oast.fun",
  "canarytokens.com",
]);

const COGNITIVE_FILES = new Set([
  "SOUL.md",
  "IDENTITY.md",
  "TOOLS.md",
  "AGENTS.md",
  "MEMORY.md",
  "openclaw.json",
  "gateway.json",
  "config.yaml",
]);

const RISKY_DEPENDENCIES = new Set([
  "child_process",
  "shelljs",
  "execa",
  "node-pty",
  "vm2",
  "isolated-vm",
  "node-serialize",
  "serialize-javascript",
  "decompress",
  "adm-zip",
  "cross-spawn",
  "minimist",
]);

const BINARY_EXTENSIONS = new Set([
  ".exe", ".sh", ".bat", ".cmd", ".so", ".dylib", ".wasm", ".dll",
]);

const SAFE_DOTFILES = new Set([
  ".gitignore", ".eslintrc", ".eslintrc.js", ".eslintrc.json", ".eslintrc.cjs",
  ".prettierrc", ".prettierrc.json", ".prettierignore",
  ".npmrc", ".npmignore", ".editorconfig", ".nvmrc",
  ".tsconfig.json",
]);

export async function scanPlugin(pluginDir: string): Promise<ScanResult> {
  const start = Date.now();
  const findings: Finding[] = [];
  const target = resolve(pluginDir);
  const capabilities = new Set<string>();

  const manifest = await loadManifest(target);
  if (!manifest) {
    findings.push(makeFinding(findings.length + 1, "MEDIUM", "No plugin manifest found", {
      description:
        "Plugin directory lacks a package.json or manifest.json. " +
        "Cannot verify plugin identity, version, or declared permissions.",
      location: target,
      remediation: "Add a package.json with name, version, and permissions fields.",
      tags: ["supply-chain"],
    }));

    return buildResult(target, findings, start);
  }

  checkPermissions(manifest, findings, target);
  checkDependencies(manifest, findings, target);
  checkInstallScripts(manifest, findings, target);

  if (manifest.tools) {
    for (const tool of manifest.tools) {
      checkTool(tool, findings, target);
    }
  }

  const { fileCount, totalBytes } = await scanSourceFiles(target, findings, capabilities);
  await scanDirectoryStructure(target, findings);

  const hasLockfile = await checkLockfilePresence(target);
  if (!hasLockfile && manifest.dependencies && Object.keys(manifest.dependencies).length > 0) {
    findings.push(makeFinding(findings.length + 1, "MEDIUM", "No lockfile found", {
      description:
        "Plugin has dependencies but no package-lock.json, yarn.lock, or pnpm-lock.yaml. " +
        "Without a lockfile, builds are non-deterministic and vulnerable to supply chain attacks.",
      location: target,
      remediation: "Run npm install to generate a package-lock.json and commit it.",
      tags: ["supply-chain"],
    }));
  }

  const metadata: ScanMetadata = {
    manifest_name: manifest.name,
    manifest_version: manifest.version,
    file_count: fileCount,
    total_size_bytes: totalBytes,
    has_lockfile: hasLockfile,
    has_install_scripts: hasInstallScripts(manifest),
    detected_capabilities: [...capabilities].sort(),
  };

  return buildResult(target, findings, start, metadata);
}

async function loadManifest(dir: string): Promise<PluginManifest | null> {
  for (const name of ["package.json", "manifest.json", "plugin.json"]) {
    try {
      const raw = await readFile(join(dir, name), "utf-8");
      const parsed = JSON.parse(raw) as Record<string, unknown>;
      return normalizeManifest(parsed, name);
    } catch {
      continue;
    }
  }
  return null;
}

function normalizeManifest(
  raw: Record<string, unknown>,
  filename: string,
): PluginManifest {
  const manifest: PluginManifest = {
    name: String(raw["name"] ?? basename(filename)),
    version: raw["version"] as string | undefined,
    description: raw["description"] as string | undefined,
    source: filename,
  };

  if (Array.isArray(raw["permissions"])) {
    manifest.permissions = raw["permissions"] as string[];
  }

  const defenseclaw = raw["defenseclaw"] as Record<string, unknown> | undefined;
  if (defenseclaw && Array.isArray(defenseclaw["permissions"])) {
    manifest.permissions = defenseclaw["permissions"] as string[];
  }

  if (Array.isArray(raw["tools"])) {
    manifest.tools = raw["tools"] as ToolManifest[];
  }

  if (Array.isArray(raw["commands"])) {
    manifest.commands = raw["commands"] as Array<{
      name: string;
      description?: string;
      args?: Array<{ name: string; required?: boolean }>;
    }>;
  }

  if (raw["dependencies"] && typeof raw["dependencies"] === "object") {
    manifest.dependencies = raw["dependencies"] as Record<string, string>;
  }
  if (raw["devDependencies"] && typeof raw["devDependencies"] === "object") {
    manifest.dependencies = {
      ...manifest.dependencies,
      ...(raw["devDependencies"] as Record<string, string>),
    };
  }

  if (raw["scripts"] && typeof raw["scripts"] === "object") {
    manifest.scripts = raw["scripts"] as Record<string, string>;
  }

  return manifest;
}

// --- Phase 1: Install Script Detection (T3) ---

function checkInstallScripts(
  manifest: PluginManifest,
  findings: Finding[],
  target: string,
): void {
  if (!manifest.scripts) return;

  for (const [name, value] of Object.entries(manifest.scripts)) {
    if (typeof value !== "string") continue;

    if (DANGEROUS_INSTALL_SCRIPTS.has(name)) {
      findings.push(
        makeFinding(findings.length + 1, "HIGH", `Dangerous install script: ${name}`, {
          description:
            `Plugin defines a "${name}" script that executes automatically during npm install. ` +
            "Install scripts are the #1 npm supply chain attack vector (ClawHavoc campaign).",
          location: `${target}/${manifest.source ?? "package.json"} → scripts.${name}`,
          remediation:
            `Remove the "${name}" script or replace it with explicit build steps that users run manually.`,
          tags: ["supply-chain"],
        }),
      );
    }

    if (SHELL_COMMANDS_IN_SCRIPTS.test(value)) {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", `Script "${name}" invokes shell commands`, {
          description:
            `The "${name}" script contains shell command invocations (${value.slice(0, 80)}). ` +
            "Scripts that download or execute external code are a supply chain risk.",
          location: `${target}/${manifest.source ?? "package.json"} → scripts.${name}`,
          remediation: "Review the script and remove unnecessary shell invocations.",
          tags: ["supply-chain"],
        }),
      );
    }
  }
}

function hasInstallScripts(manifest: PluginManifest): boolean {
  if (!manifest.scripts) return false;
  return Object.keys(manifest.scripts).some((k) => DANGEROUS_INSTALL_SCRIPTS.has(k));
}

// --- Permissions ---

function checkPermissions(
  manifest: PluginManifest,
  findings: Finding[],
  target: string,
): void {
  if (!manifest.permissions || manifest.permissions.length === 0) {
    findings.push(
      makeFinding(findings.length + 1, "LOW", "Plugin declares no permissions", {
        description:
          "No permissions declared in manifest. This could mean the plugin " +
          "operates without restrictions or that permissions are not documented.",
        location: `${target}/${manifest.source ?? "package.json"}`,
        remediation:
          "Declare required permissions explicitly in the manifest to enable policy enforcement.",
      }),
    );
    return;
  }

  for (const perm of manifest.permissions) {
    if (DANGEROUS_PERMISSIONS.has(perm)) {
      findings.push(
        makeFinding(findings.length + 1, "HIGH", `Dangerous permission: ${perm}`, {
          description: `Plugin requests permission "${perm}" which grants broad ${perm.split(":")[0]} access. ` +
            "This permission should be scoped more narrowly.",
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: `Replace "${perm}" with specific, scoped permissions (e.g., "fs:read:/specific/path").`,
        }),
      );
    }

    if (perm.endsWith(":*")) {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", `Wildcard permission: ${perm}`, {
          description: `Plugin uses wildcard permission "${perm}". Wildcard permissions bypass fine-grained policy enforcement.`,
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: "Use specific, scoped permissions instead of wildcards.",
        }),
      );
    }
  }
}

// --- Dependencies ---

function checkDependencies(
  manifest: PluginManifest,
  findings: Finding[],
  target: string,
): void {
  if (!manifest.dependencies) return;

  for (const dep of Object.keys(manifest.dependencies)) {
    if (RISKY_DEPENDENCIES.has(dep)) {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", `Risky dependency: ${dep}`, {
          description: `Plugin depends on "${dep}" which can execute arbitrary commands or code.`,
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: `Review usage of "${dep}" and ensure it does not process untrusted input.`,
          tags: ["supply-chain"],
        }),
      );
    }
  }

  for (const [dep, version] of Object.entries(manifest.dependencies)) {
    if (typeof version !== "string") continue;

    if (version === "*" || version === "latest" || version === "") {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", `Unpinned dependency: ${dep}@${version}`, {
          description: `Dependency "${dep}" uses unpinned version "${version}". Supply chain attacks exploit unpinned versions.`,
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: `Pin "${dep}" to a specific version or range (e.g., "^1.2.3").`,
          tags: ["supply-chain"],
        }),
      );
    }

    if (version.startsWith("http://")) {
      findings.push(
        makeFinding(findings.length + 1, "HIGH", `Dependency "${dep}" fetched over HTTP`, {
          description: `Dependency "${dep}" uses an unencrypted HTTP URL. This allows man-in-the-middle attacks on the package.`,
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: "Use HTTPS or a registry reference instead.",
          tags: ["supply-chain"],
        }),
      );
    }

    if (version.startsWith("file:")) {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", `Dependency "${dep}" uses local file path`, {
          description: `Dependency "${dep}" references a local file path ("${version}"). This could be a path traversal vector.`,
          location: `${target}/${manifest.source ?? "package.json"}`,
          remediation: "Use a registry-published package instead of a local file reference.",
          tags: ["supply-chain"],
        }),
      );
    }

    if (version.startsWith("git") || version.startsWith("github:")) {
      if (!/#[a-f0-9]{7,}/.test(version)) {
        findings.push(
          makeFinding(findings.length + 1, "MEDIUM", `Git dependency "${dep}" without commit pin`, {
            description: `Dependency "${dep}" references a git source without a commit hash. The content can change silently.`,
            location: `${target}/${manifest.source ?? "package.json"}`,
            remediation: `Pin "${dep}" to a specific commit hash (e.g., "github:user/repo#abc1234").`,
            tags: ["supply-chain"],
          }),
        );
      }
    }
  }
}

// --- Tools ---

function checkTool(
  tool: ToolManifest,
  findings: Finding[],
  target: string,
): void {
  if (!tool.description) {
    findings.push(
      makeFinding(findings.length + 1, "LOW", `Tool "${tool.name}" lacks description`, {
        description:
          "Tools without descriptions cannot be properly reviewed for safety by users or automated systems.",
        location: `${target} → tool:${tool.name}`,
        remediation: "Add a clear description explaining what this tool does.",
      }),
    );
  }

  if (tool.permissions) {
    for (const perm of tool.permissions) {
      if (DANGEROUS_PERMISSIONS.has(perm)) {
        findings.push(
          makeFinding(
            findings.length + 1,
            "HIGH",
            `Tool "${tool.name}" requests dangerous permission: ${perm}`,
            {
              description: `Tool "${tool.name}" requests "${perm}" which grants broad system access.`,
              location: `${target} → tool:${tool.name}`,
              remediation: `Scope the permission for tool "${tool.name}" more narrowly.`,
            },
          ),
        );
      }
    }
  }
}

// --- Source file scanning (multi-occurrence, all phases) ---

async function scanSourceFiles(
  dir: string,
  findings: Finding[],
  capabilities: Set<string>,
): Promise<{ fileCount: number; totalBytes: number }> {
  const tsFiles = await collectFiles(dir, [".ts", ".js", ".mjs"]);
  let totalBytes = 0;

  for (const file of tsFiles) {
    let content: string;
    try {
      content = await readFile(file, "utf-8");
    } catch {
      continue;
    }

    totalBytes += content.length;
    if (content.length > 512 * 1024) continue;

    const relPath = file.replace(dir + "/", "");
    const lines = content.split("\n");

    scanSuspiciousPatterns(lines, relPath, findings, capabilities);
    checkForHardcodedSecrets(lines, relPath, findings);
    checkForCredentialAccess(lines, relPath, findings, capabilities);
    checkForExfiltration(lines, content, relPath, findings, capabilities);
    checkForCognitiveFileTampering(lines, content, relPath, findings);
    checkForObfuscation(lines, content, relPath, findings);
    checkForGatewayManipulation(lines, relPath, findings);
    checkForCostRunaway(lines, relPath, findings);
  }

  return { fileCount: tsFiles.length, totalBytes };
}

function scanSuspiciousPatterns(
  lines: string[],
  relPath: string,
  findings: Finding[],
  capabilities: Set<string>,
): void {
  for (const { pattern, title, tags } of SUSPICIOUS_TOOL_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        findings.push(
          makeFinding(findings.length + 1, "INFO", title, {
            description: "Detected suspicious pattern in source file. Review for secure usage.",
            location: `${relPath}:${i + 1}`,
            remediation: "Ensure this pattern is used safely and does not process untrusted input.",
            tags,
          }),
        );

        if (tags.includes("code-execution")) capabilities.add("child-process");
        if (tags.includes("exfiltration")) capabilities.add("network");
        if (tags.includes("credential-theft")) capabilities.add("env-access");
        if (title.includes("filesystem writes")) capabilities.add("filesystem-write");

        break;
      }
    }
  }
}

// --- Phase 2: Credential Theft Detection (T2) ---

function checkForHardcodedSecrets(
  lines: string[],
  relPath: string,
  findings: Finding[],
): void {
  const secretPatterns = [
    {
      pattern: /(?:^|[\s=:])(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/,
      title: "Possible AWS key detected",
    },
    {
      pattern: /(?:sk_live_|pk_live_|sk_test_|pk_test_)[a-zA-Z0-9]{20,}/,
      title: "Possible Stripe key detected",
    },
    {
      pattern: /(?:ghp_|gho_|ghu_|ghs_|ghr_)[a-zA-Z0-9]{36,}/,
      title: "Possible GitHub token detected",
    },
    {
      pattern: /-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----/,
      title: "Private key embedded in source",
    },
    {
      pattern: /AIza[0-9A-Za-z\-_]{35}/,
      title: "Possible Google API key detected",
    },
    {
      pattern: /xox[bpors]-[0-9a-zA-Z\-]{10,}/,
      title: "Possible Slack token detected",
    },
    {
      pattern: /eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_.+/=]*/,
      title: "Possible JWT token detected",
    },
    {
      pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@/,
      title: "Connection string with embedded credentials",
    },
  ];

  for (const { pattern, title } of secretPatterns) {
    const lineIdx = lines.findIndex((l) => pattern.test(l));
    if (lineIdx >= 0) {
      findings.push(
        makeFinding(findings.length + 1, "CRITICAL", title, {
          description:
            "Hardcoded credential detected in plugin source code. " +
            "Credentials in source are considered compromised.",
          location: `${relPath}:${lineIdx + 1}`,
          remediation:
            "Remove the credential from source code immediately. " +
            "Use environment variables or a secrets manager instead.",
          tags: ["credential-theft"],
        }),
      );
    }
  }
}

const CREDENTIAL_PATH_PATTERNS: Array<{ pattern: RegExp; title: string }> = [
  {
    pattern: /\.openclaw\/credentials/i,
    title: "Plugin accesses OpenClaw credentials directory",
  },
  {
    pattern: /\.openclaw\/\.env/i,
    title: "Plugin accesses OpenClaw .env file",
  },
  {
    pattern: /\.openclaw\/agents\//i,
    title: "Plugin accesses OpenClaw agents directory",
  },
  {
    pattern: /readFile\w*\s*\([^)]*(?:\.env|credentials|secrets)/i,
    title: "Plugin reads credential or secrets files",
  },
];

function checkForCredentialAccess(
  lines: string[],
  relPath: string,
  findings: Finding[],
  capabilities: Set<string>,
): void {
  for (const { pattern, title } of CREDENTIAL_PATH_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        capabilities.add("credential-access");
        findings.push(
          makeFinding(findings.length + 1, "HIGH", title, {
            description:
              "Plugin accesses sensitive credential paths. A compromised plugin " +
              "with credential access can exfiltrate API keys and tokens.",
            location: `${relPath}:${i + 1}`,
            remediation:
              "Plugins should not access credential files directly. " +
              "Use the PluginContext API for authorized access.",
            tags: ["credential-theft"],
          }),
        );
        break;
      }
    }
  }
}

function checkForExfiltration(
  lines: string[],
  content: string,
  relPath: string,
  findings: Finding[],
  capabilities: Set<string>,
): void {
  for (const domain of C2_DOMAINS) {
    const idx = lines.findIndex((l) => l.includes(domain));
    if (idx >= 0) {
      capabilities.add("network");
      findings.push(
        makeFinding(findings.length + 1, "CRITICAL", `Known exfiltration domain: ${domain}`, {
          description:
            `Plugin references "${domain}", a known data exfiltration/C2 service. ` +
            "This is a strong indicator of malicious intent (ClawHavoc campaign pattern).",
          location: `${relPath}:${idx + 1}`,
          remediation: "Remove the reference and investigate the plugin's provenance.",
          tags: ["exfiltration"],
        }),
      );
    }
  }

  if (/\bdns\.resolve\b|\bdns\.lookup\b/.test(content) &&
      /process\.env|readFile|credentials/.test(content)) {
    findings.push(
      makeFinding(findings.length + 1, "HIGH", "Possible DNS exfiltration pattern", {
        description:
          "Plugin uses DNS resolution combined with credential/env access. " +
          "DNS queries can be used to exfiltrate data by encoding it in subdomains.",
        location: relPath,
        remediation: "Review DNS usage and ensure it is not used for data exfiltration.",
        tags: ["exfiltration"],
      }),
    );
  }
}

// --- Phase 3: Cognitive File Tampering Detection (T4) ---

const WRITE_FUNCTIONS = /(?:writeFile|appendFile|writeFileSync|appendFileSync|createWriteStream)\s*\(/;

function checkForCognitiveFileTampering(
  lines: string[],
  content: string,
  relPath: string,
  findings: Finding[],
): void {
  for (const cogFile of COGNITIVE_FILES) {
    if (!content.includes(cogFile)) continue;

    const hasWrite = WRITE_FUNCTIONS.test(content);
    if (!hasWrite) continue;

    const lineIdx = lines.findIndex((l) => l.includes(cogFile));
    findings.push(
      makeFinding(findings.length + 1, "HIGH", `Possible cognitive file tampering: ${cogFile}`, {
        description:
          `Plugin references "${cogFile}" and contains file write operations. ` +
          "Modifying OpenClaw cognitive files persists behavioral changes across all sessions, " +
          "enabling long-term agent compromise (T4 threat class).",
        location: `${relPath}:${lineIdx >= 0 ? lineIdx + 1 : 0}`,
        remediation:
          `Plugins must not write to "${cogFile}". ` +
          "Agent identity and behavior files should only be modified by the operator.",
        tags: ["cognitive-tampering"],
      }),
    );
  }
}

// --- Phase 4: Obfuscation Detection ---

function checkForObfuscation(
  lines: string[],
  content: string,
  relPath: string,
  findings: Finding[],
): void {
  for (let i = 0; i < lines.length; i++) {
    if (/Buffer\.from\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']/.test(lines[i]) ||
        /\batob\s*\(\s*["'][A-Za-z0-9+/=]{50,}["']/.test(lines[i])) {
      findings.push(
        makeFinding(findings.length + 1, "MEDIUM", "Base64-encoded payload detected", {
          description:
            "Plugin decodes a large base64 string at runtime. " +
            "Base64 encoding is commonly used to hide malicious URLs, shell commands, or credentials.",
          location: `${relPath}:${i + 1}`,
          remediation: "Decode and review the base64 payload. Remove if it contains suspicious content.",
          tags: ["obfuscation"],
        }),
      );
      break;
    }
  }

  if (/String\.fromCharCode\s*\(\s*(?:\d+\s*,\s*){4,}/.test(content)) {
    const idx = lines.findIndex((l) => /String\.fromCharCode/.test(l));
    findings.push(
      makeFinding(findings.length + 1, "MEDIUM", "String.fromCharCode obfuscation detected", {
        description:
          "Plugin constructs strings from character codes, a technique used to evade static pattern detection.",
        location: `${relPath}:${idx >= 0 ? idx + 1 : 0}`,
        remediation: "Evaluate the constructed string and replace with a readable literal if safe.",
        tags: ["obfuscation"],
      }),
    );
  }

  if (/(?:\\x[0-9a-fA-F]{2}){4,}/.test(content)) {
    const idx = lines.findIndex((l) => /(?:\\x[0-9a-fA-F]{2}){4,}/.test(l));
    findings.push(
      makeFinding(findings.length + 1, "MEDIUM", "Hex escape sequence obfuscation detected", {
        description:
          "Plugin uses hex escape sequences to build strings, a common evasion technique for hiding commands.",
        location: `${relPath}:${idx >= 0 ? idx + 1 : 0}`,
        remediation: "Decode the hex sequence and review the resulting string.",
        tags: ["obfuscation"],
      }),
    );
  }

  const concatEvasion = /['"](?:ev|cu|ch|ex|sp)['"]\s*\+\s*['"](?:al|rl|ild|ec|awn)/;
  if (concatEvasion.test(content)) {
    const idx = lines.findIndex((l) => concatEvasion.test(l));
    findings.push(
      makeFinding(findings.length + 1, "HIGH", "String concatenation evasion detected", {
        description:
          "Plugin splits a dangerous function name across string concatenation to evade static analysis.",
        location: `${relPath}:${idx >= 0 ? idx + 1 : 0}`,
        remediation: "This is a strong indicator of malicious intent. Investigate the plugin immediately.",
        tags: ["obfuscation"],
      }),
    );
  }

  if (lines.length > 0 && lines.length < 20) {
    const totalLen = lines.reduce((sum, l) => sum + l.length, 0);
    const avgLen = totalLen / lines.length;
    if (avgLen > 500 && totalLen > 10_000) {
      findings.push(
        makeFinding(findings.length + 1, "INFO", "Minified or bundled code detected", {
          description:
            "Source file appears to be minified or bundled (very long lines, few line breaks). " +
            "Minified code is difficult to audit for security issues.",
          location: relPath,
          remediation: "Request unminified source for security review, or use a deobfuscation tool.",
          tags: ["obfuscation"],
        }),
      );
    }
  }
}

// --- Phase 5: Gateway and Runtime Manipulation (T5, T7) ---

const GATEWAY_PATTERNS: Array<{ pattern: RegExp; title: string; severity: Severity }> = [
  {
    pattern: /\bprocess\.exit\s*\(/,
    title: "Plugin calls process.exit()",
    severity: "HIGH",
  },
  {
    pattern: /\b(?:require|import)\s*\(\s*['"]module['"]\s*\)/,
    title: "Plugin imports Node module system",
    severity: "HIGH",
  },
  {
    pattern: /\bModule\._load\b/,
    title: "Plugin manipulates Module._load",
    severity: "HIGH",
  },
  {
    pattern: /\bglobalThis\s*[.[=]|\bglobal\s*\.\s*\w+\s*=/,
    title: "Plugin modifies global state",
    severity: "MEDIUM",
  },
  {
    pattern: /Object\.defineProperty\s*\(\s*Object\.prototype/,
    title: "Plugin modifies Object.prototype (prototype pollution)",
    severity: "CRITICAL",
  },
  {
    pattern: /__proto__\s*[=\[]/,
    title: "Plugin accesses __proto__ (prototype pollution)",
    severity: "HIGH",
  },
  {
    pattern: /\bprocess\.env\s*\.\s*\w+\s*=/,
    title: "Plugin modifies environment variables",
    severity: "MEDIUM",
  },
];

function checkForGatewayManipulation(
  lines: string[],
  relPath: string,
  findings: Finding[],
): void {
  for (const { pattern, title, severity } of GATEWAY_PATTERNS) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        findings.push(
          makeFinding(findings.length + 1, severity, title, {
            description:
              "Plugin interacts with gateway internals or modifies the runtime environment. " +
              "A malicious plugin can crash the gateway, hijack the module system, or pollute prototypes (T5 threat class).",
            location: `${relPath}:${i + 1}`,
            remediation:
              "Plugins should not modify the runtime environment. " +
              "Use the PluginContext API for authorized interactions.",
            tags: ["gateway-manipulation"],
          }),
        );
        break;
      }
    }
  }
}

function checkForCostRunaway(
  lines: string[],
  relPath: string,
  findings: Finding[],
): void {
  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/setInterval\s*\([^,]+,\s*(\d+)\s*\)/);
    if (match) {
      const interval = parseInt(match[1], 10);
      if (interval < 1000) {
        const nearbyLines = lines.slice(Math.max(0, i - 5), i + 10).join("\n");
        if (/\b(?:fetch|http|https|request|openai|anthropic|api)\b/i.test(nearbyLines)) {
          findings.push(
            makeFinding(findings.length + 1, "MEDIUM", "Possible cost runaway: rapid API polling", {
              description:
                `Plugin uses setInterval with ${interval}ms delay near API/network calls. ` +
                "This pattern can cause runaway API costs or rate-limit exhaustion (T7 threat class).",
              location: `${relPath}:${i + 1}`,
              remediation: "Use reasonable polling intervals (>= 1 second) and implement backoff.",
              tags: ["cost-runaway"],
            }),
          );
        }
      }
    }
  }
}

// --- Phase 6: Structural scanning ---

async function scanDirectoryStructure(
  dir: string,
  findings: Finding[],
): Promise<void> {
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return;
  }

  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist") continue;

    const ext = entry.lastIndexOf(".") >= 0 ? entry.slice(entry.lastIndexOf(".")) : "";

    if (entry === ".env" || entry === ".env.local" || entry === ".env.production") {
      findings.push(
        makeFinding(findings.length + 1, "CRITICAL", `Environment file found: ${entry}`, {
          description:
            "Plugin directory contains an environment file that likely holds secrets. " +
            "Secrets in a plugin directory risk being published or accessed by other plugins.",
          location: `${dir}/${entry}`,
          remediation: "Remove the .env file and use a secrets manager or environment variables instead.",
          tags: ["credential-theft"],
        }),
      );
    } else if (BINARY_EXTENSIONS.has(ext)) {
      findings.push(
        makeFinding(findings.length + 1, "HIGH", `Binary executable found: ${entry}`, {
          description:
            `Plugin contains a binary file "${entry}". Executables in plugins cannot be audited ` +
            "for security and may contain malware.",
          location: `${dir}/${entry}`,
          remediation: "Remove binary files. Plugins should only contain auditable source code.",
          tags: ["supply-chain"],
        }),
      );
    } else if (entry.startsWith(".") && !SAFE_DOTFILES.has(entry)) {
      findings.push(
        makeFinding(findings.length + 1, "LOW", `Hidden file found: ${entry}`, {
          description: `Plugin contains hidden file "${entry}" which may conceal configuration or data.`,
          location: `${dir}/${entry}`,
          remediation: "Review the hidden file and remove if unnecessary.",
        }),
      );
    }
  }
}

async function checkLockfilePresence(dir: string): Promise<boolean> {
  for (const name of ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]) {
    try {
      await access(join(dir, name));
      return true;
    } catch {
      continue;
    }
  }
  return false;
}

// --- File collection ---

async function collectFiles(
  dir: string,
  extensions: string[],
  maxDepth = 4,
  depth = 0,
): Promise<string[]> {
  if (depth >= maxDepth) return [];

  const files: string[] = [];
  let entries: string[];
  try {
    entries = await readdir(dir);
  } catch {
    return files;
  }

  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist" || entry.startsWith("."))
      continue;

    const fullPath = join(dir, entry);
    try {
      const info = await stat(fullPath);
      if (info.isDirectory()) {
        const nested = await collectFiles(fullPath, extensions, maxDepth, depth + 1);
        files.push(...nested);
      } else if (extensions.some((ext) => entry.endsWith(ext))) {
        files.push(fullPath);
      }
    } catch {
      continue;
    }
  }

  return files;
}

// --- Helpers ---

function makeFinding(
  id: number,
  severity: Severity,
  title: string,
  opts: {
    description: string;
    location?: string;
    remediation?: string;
    tags?: string[];
  },
): Finding {
  return {
    id: `plugin-${id}`,
    severity,
    title,
    description: opts.description,
    location: opts.location,
    remediation: opts.remediation,
    scanner: SCANNER_NAME,
    tags: opts.tags,
  };
}

function buildResult(
  target: string,
  findings: Finding[],
  startMs: number,
  metadata?: ScanMetadata,
): ScanResult {
  return {
    scanner: SCANNER_NAME,
    target,
    timestamp: new Date().toISOString(),
    findings,
    duration_ns: (Date.now() - startMs) * 1_000_000,
    metadata,
  };
}
