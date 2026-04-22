/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createRequire } from "node:module";

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("patchAwsSdkHttp1ForGuardrail", () => {
  beforeEach(() => {
    vi.resetModules();
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1GuardrailPatch;
  });

  afterEach(() => {
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1GuardrailPatch;
    delete process.env.DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM;
    delete process.env.DEFENSECLAW_FORCE_AWS_HTTP1_SHIM;
    delete process.env.DEFENSECLAW_OPENCLAW_MAIN;
    delete process.env.AWS_BEDROCK_FORCE_HTTP1;
  });

  it("respects DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM", async () => {
    process.env.DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM = "1";
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { patchAwsSdkHttp1ForGuardrail } = await import(
      "../aws-sdk-http1-for-guardrail.js"
    );
    patchAwsSdkHttp1ForGuardrail();
    expect(log).toHaveBeenCalledWith(
      expect.stringContaining("skipped"),
    );
    expect(process.env.AWS_BEDROCK_FORCE_HTTP1).toBeUndefined();
    log.mockRestore();
  });

  it("skips on auto when config has no Bedrock", async () => {
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    const { patchAwsSdkHttp1ForGuardrail } = await import(
      "../aws-sdk-http1-for-guardrail.js"
    );
    patchAwsSdkHttp1ForGuardrail({
      openclawConfig: {
        agents: { defaults: { model: { primary: "openai/gpt-4o" } } },
      },
      pluginConfig: { awsHttp1Shim: "auto" },
    });
    expect(log).toHaveBeenCalledWith(
      expect.stringContaining("no Amazon Bedrock"),
    );
    expect(process.env.AWS_BEDROCK_FORCE_HTTP1).toBeUndefined();
    log.mockRestore();
  });

  it("resolves Smithy from global npm layout when argv has no script path", async () => {
    const root = mkdtempSync(join(tmpdir(), "dc-smithy-"));
    const fakeExecPath = join(root, "bin", "node");
    mkdirSync(join(root, "bin"), { recursive: true });
    const openclawMain = join(
      root,
      "lib",
      "node_modules",
      "openclaw",
      "openclaw.mjs",
    );
    mkdirSync(join(root, "lib", "node_modules", "openclaw"), { recursive: true });
    writeFileSync(openclawMain, "export {}\n");

    const smithyDir = join(
      root,
      "lib",
      "node_modules",
      "@smithy",
      "node-http-handler",
    );
    mkdirSync(smithyDir, { recursive: true });
    writeFileSync(
      join(smithyDir, "package.json"),
      JSON.stringify({
        name: "@smithy/node-http-handler",
        main: "index.cjs",
      }),
    );
    writeFileSync(
      join(smithyDir, "index.cjs"),
      `
const NodeHttp2Handler = { create: () => ({ tag: "h2" }) };
const NodeHttpHandler = { create: () => ({ tag: "h1" }) };
module.exports = { NodeHttp2Handler, NodeHttpHandler };
`,
    );

    const origArgv = [...process.argv];
    const origExecPath = process.execPath;
    Object.defineProperty(process, "argv", {
      value: ["openclaw-gateway"],
      configurable: true,
    });
    Object.defineProperty(process, "execPath", {
      value: fakeExecPath,
      configurable: true,
    });

    vi.resetModules();
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1GuardrailPatch;

    process.env.DEFENSECLAW_FORCE_AWS_HTTP1_SHIM = "1";
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});

    const { patchAwsSdkHttp1ForGuardrail } = await import(
      "../aws-sdk-http1-for-guardrail.js"
    );
    patchAwsSdkHttp1ForGuardrail();

    expect(process.env.AWS_BEDROCK_FORCE_HTTP1).toBe("1");

    const req = createRequire(openclawMain);
    const smithy = req("@smithy/node-http-handler") as {
      NodeHttp2Handler: { create: () => { tag: string } };
    };
    expect(smithy.NodeHttp2Handler.create().tag).toBe("h1");
    expect(warn).not.toHaveBeenCalled();

    Object.defineProperty(process, "argv", {
      value: origArgv,
      configurable: true,
    });
    Object.defineProperty(process, "execPath", {
      value: origExecPath,
      configurable: true,
    });
    rmSync(root, { recursive: true, force: true });
    warn.mockRestore();
  });

  it("accepts DEFENSECLAW_OPENCLAW_MAIN when it resolves under the execPath install root", async () => {
    const root = mkdtempSync(join(tmpdir(), "dc-smithy-trust-"));
    const fakeExecPath = join(root, "bin", "node");
    mkdirSync(join(root, "bin"), { recursive: true });
    const openclawMain = join(
      root,
      "lib",
      "node_modules",
      "openclaw",
      "openclaw.mjs",
    );
    mkdirSync(join(root, "lib", "node_modules", "openclaw"), {
      recursive: true,
    });
    writeFileSync(openclawMain, "export {}\n");

    const smithyDir = join(
      root,
      "lib",
      "node_modules",
      "@smithy",
      "node-http-handler",
    );
    mkdirSync(smithyDir, { recursive: true });
    writeFileSync(
      join(smithyDir, "package.json"),
      JSON.stringify({ name: "@smithy/node-http-handler", main: "index.cjs" }),
    );
    writeFileSync(
      join(smithyDir, "index.cjs"),
      `
const NodeHttp2Handler = { create: () => ({ tag: "h2" }) };
const NodeHttpHandler = { create: () => ({ tag: "h1" }) };
module.exports = { NodeHttp2Handler, NodeHttpHandler };
`,
    );

    const origArgv = [...process.argv];
    const origExecPath = process.execPath;
    Object.defineProperty(process, "argv", {
      value: ["openclaw-gateway"],
      configurable: true,
    });
    Object.defineProperty(process, "execPath", {
      value: fakeExecPath,
      configurable: true,
    });

    process.env.DEFENSECLAW_OPENCLAW_MAIN = openclawMain;
    process.env.DEFENSECLAW_FORCE_AWS_HTTP1_SHIM = "1";

    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    vi.resetModules();
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1GuardrailPatch;

    const { patchAwsSdkHttp1ForGuardrail, isPermittedOpenclawMain } =
      await import("../aws-sdk-http1-for-guardrail.js");
    expect(isPermittedOpenclawMain(openclawMain)).toBe(true);
    patchAwsSdkHttp1ForGuardrail();

    expect(warn).not.toHaveBeenCalled();
    expect(process.env.AWS_BEDROCK_FORCE_HTTP1).toBe("1");

    Object.defineProperty(process, "argv", {
      value: origArgv,
      configurable: true,
    });
    Object.defineProperty(process, "execPath", {
      value: origExecPath,
      configurable: true,
    });
    rmSync(root, { recursive: true, force: true });
    warn.mockRestore();
  });

  it("rejects DEFENSECLAW_OPENCLAW_MAIN outside any trusted root and warns", async () => {
    const attackerRoot = mkdtempSync(join(tmpdir(), "dc-attacker-"));
    const attackerMain = join(attackerRoot, "evil", "openclaw.mjs");
    mkdirSync(dirname(attackerMain), { recursive: true });
    writeFileSync(attackerMain, "export {}\n");

    // Point execPath somewhere unrelated so the attacker path is not a sibling.
    const safeRoot = mkdtempSync(join(tmpdir(), "dc-safe-"));
    const fakeExecPath = join(safeRoot, "bin", "node");
    mkdirSync(join(safeRoot, "bin"), { recursive: true });

    const origExecPath = process.execPath;
    const origArgv = [...process.argv];
    const origHome = process.env.HOME;
    Object.defineProperty(process, "execPath", {
      value: fakeExecPath,
      configurable: true,
    });
    Object.defineProperty(process, "argv", {
      value: ["openclaw-gateway"],
      configurable: true,
    });
    // Force HOME to a directory that does NOT contain the attacker path so the
    // nvm/volta/pnpm allow-list roots cannot accidentally cover it.
    process.env.HOME = safeRoot;

    process.env.DEFENSECLAW_OPENCLAW_MAIN = attackerMain;
    process.env.DEFENSECLAW_FORCE_AWS_HTTP1_SHIM = "1";

    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const log = vi.spyOn(console, "log").mockImplementation(() => {});
    vi.resetModules();
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1ShimEvaluated;
    delete (globalThis as Record<string, unknown>).__defenseclawAwsHttp1GuardrailPatch;

    const { patchAwsSdkHttp1ForGuardrail, isPermittedOpenclawMain } =
      await import("../aws-sdk-http1-for-guardrail.js");
    expect(isPermittedOpenclawMain(attackerMain)).toBe(false);
    patchAwsSdkHttp1ForGuardrail();

    expect(warn).toHaveBeenCalledWith(
      expect.stringContaining("Ignoring DEFENSECLAW_OPENCLAW_MAIN"),
    );
    // Env was still set by force-mode (pi-ai path), but Smithy patch should not have run
    // since the attacker path was rejected and no other candidate resolves @smithy here.
    expect(process.env.AWS_BEDROCK_FORCE_HTTP1).toBe("1");

    Object.defineProperty(process, "execPath", {
      value: origExecPath,
      configurable: true,
    });
    Object.defineProperty(process, "argv", {
      value: origArgv,
      configurable: true,
    });
    if (origHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = origHome;
    }
    rmSync(attackerRoot, { recursive: true, force: true });
    rmSync(safeRoot, { recursive: true, force: true });
    warn.mockRestore();
    log.mockRestore();
  });

  it("rejects empty or relative DEFENSECLAW_OPENCLAW_MAIN values without throwing", async () => {
    vi.resetModules();
    const { isPermittedOpenclawMain } = await import(
      "../aws-sdk-http1-for-guardrail.js"
    );
    expect(isPermittedOpenclawMain("")).toBe(false);
    expect(isPermittedOpenclawMain("../../../../etc/passwd")).toBe(false);
  });
});
