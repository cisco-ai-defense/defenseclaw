/**
 * Copyright 2026 Cisco Systems, Inc. and its affiliates
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * Amazon's JS SDK v3 defaults many services (including Bedrock Runtime) to
 * {@link NodeHttp2Handler}, which uses `node:http2` and bypasses DefenseClaw's
 * `https.request` / `fetch` hooks. Redirecting those calls through the local
 * guardrail proxy requires HTTP/1.1 {@link NodeHttpHandler}.
 *
 * OpenClaw’s `@mariozechner/pi-ai` Bedrock provider reads **`AWS_BEDROCK_FORCE_HTTP1=1`**
 * and switches the AWS SDK to `NodeHttpHandler` (HTTP/1). Without that,
 * Bedrock stays on HTTP/2 and never hits our `https.request` / `fetch` hooks.
 *
 * This module sets that env when the shim is active, and also tries to replace
 * `NodeHttp2Handler.create` with `NodeHttpHandler.create` on any resolvable
 * `@smithy/node-http-handler` instance (fallback for other callers).
 *
 * **When it runs (default `awsHttp1Shim: auto` in plugin config):** only if
 * OpenClaw config references Amazon Bedrock (see `bedrock-config-detect.ts`).
 *
 * **Overrides**
 * - `plugins.entries.defenseclaw.awsHttp1Shim`: `"on"` | `"off"` | `"auto"`
 * - `DEFENSECLAW_FORCE_AWS_HTTP1_SHIM=1` — always patch (escape hatch)
 * - `DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM=1` — never patch
 * - `DEFENSECLAW_OPENCLAW_MAIN` — absolute path to `openclaw.mjs` (or any file under the
 *   global `openclaw` install) used to resolve `@smithy/node-http-handler` when the gateway
 *   process has no `process.argv[1]` (common for `openclaw-gateway` shims).
 *
 * **Trust model for `DEFENSECLAW_OPENCLAW_MAIN`:** this env var is read at gateway
 * startup to locate OpenClaw's hoisted `node_modules`. Setting it to a path under an
 * attacker-controlled tree would steer Smithy resolution (and therefore the
 * `NodeHttp2Handler → NodeHttpHandler` monkey-patch) to attacker-supplied code. In
 * practice anyone able to set this env var can already set `NODE_OPTIONS=--require …`
 * or replace the `openclaw-gateway` binary outright, so the marginal new capability
 * is small — but we still reject paths outside a fixed allow-list of roots (global
 * npm prefix sibling of `process.execPath`, NVM / Volta / pnpm trees, and the
 * plugin's own install tree) so a misconfigured supervisor or unprivileged shell env
 * cannot widen the blast radius. Rejections are logged via `console.warn` and the
 * override is silently dropped — resolution continues through the remaining
 * candidates (`argv[1]`, `process.execPath` sibling, `import.meta.url`).
 */

import { existsSync, realpathSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { openClawConfigUsesAmazonBedrock } from "./bedrock-config-detect.js";

const DONE_FLAG = "__defenseclawAwsHttp1ShimEvaluated";
const PATCHED_FLAG = "__defenseclawAwsHttp1GuardrailPatch";

export type AwsHttp1ShimMode = "auto" | "on" | "off";

export interface PatchAwsSdkHttp1ForGuardrailOptions {
  /** Full OpenClaw gateway config (`api.config`). */
  openclawConfig?: unknown;
  /** Validated `plugins.entries.defenseclaw` slice (`api.pluginConfig`). */
  pluginConfig?: { awsHttp1Shim?: AwsHttp1ShimMode };
}

/**
 * When the gateway is started as a bare `openclaw-gateway` name (argv has no script path),
 * `createRequire(process.argv[1])` cannot load OpenClaw's hoisted deps. Global npm installs
 * place `openclaw` next to the Node binary: `{prefix}/lib/node_modules/openclaw/openclaw.mjs`.
 */
function tryOpenclawEntryFromNodeExecPath(execPath: string): string | null {
  const binDir = dirname(execPath);
  const roots = [
    join(binDir, "..", "lib", "node_modules", "openclaw", "openclaw.mjs"),
    join(binDir, "..", "lib", "node_modules", "openclaw", "dist", "index.js"),
  ];
  for (const p of roots) {
    if (existsSync(p)) return p;
  }
  return null;
}

/**
 * Roots under which `DEFENSECLAW_OPENCLAW_MAIN` is considered trusted enough
 * to drive `createRequire()`. Anything outside these trees will be ignored
 * with a `console.warn` so a rogue environment variable cannot silently
 * redirect Smithy resolution to an attacker-controlled `node_modules/`.
 */
function trustedOpenclawRoots(): string[] {
  const roots = new Set<string>();

  // 1. Global npm prefix sibling of process.execPath:
  //    {prefix}/bin/node + {prefix}/lib/node_modules -> {prefix}
  const execDir = dirname(process.execPath);
  roots.add(resolve(execDir, ".."));

  // 2. This module's own install tree (covers local `npm link`, monorepo checkout,
  //    and distro packaging that drops the extension alongside the gateway).
  try {
    const self = fileURLToPath(import.meta.url);
    // Walk up to the nearest `node_modules` ancestor, or fall back to 3 levels.
    let dir = dirname(self);
    for (let i = 0; i < 6; i++) {
      const parent = dirname(dir);
      if (parent === dir) break;
      if (dir.endsWith(`${sep}node_modules`)) {
        roots.add(resolve(parent));
        break;
      }
      dir = parent;
    }
    roots.add(resolve(dirname(self), "..", ".."));
  } catch {
    /* ignore */
  }

  // 3. Common user-local Node manager layouts — any of these being present on disk
  //    already implies the user installed openclaw through that path, so resolving
  //    through them is equivalent to running the gateway through them.
  const home = process.env.HOME || process.env.USERPROFILE;
  if (home) {
    roots.add(resolve(home, ".nvm"));
    roots.add(resolve(home, ".volta"));
    roots.add(resolve(home, ".local", "share", "pnpm"));
    roots.add(resolve(home, ".local", "share", "fnm"));
    roots.add(resolve(home, "Library", "pnpm")); // macOS
    roots.add(resolve(home, "AppData", "Roaming", "npm")); // Windows
  }

  return [...roots].filter((r) => r.length > 0);
}

function canonical(p: string): string | null {
  try {
    return realpathSync(p);
  } catch {
    return resolve(p);
  }
}

/**
 * Returns `true` when `candidate` resolves to a file under one of the
 * `trustedOpenclawRoots()`. We compare canonicalized absolute paths to defeat
 * `../` traversal and symlink tricks (`realpath` is best-effort; if it fails we
 * fall back to `resolve()` which still blocks literal traversal).
 */
export function isPermittedOpenclawMain(candidate: string): boolean {
  if (typeof candidate !== "string" || candidate.length === 0) return false;
  const target = canonical(candidate);
  if (!target) return false;
  const roots = trustedOpenclawRoots()
    .map((r) => canonical(r))
    .filter((r): r is string => Boolean(r));
  for (const root of roots) {
    const prefix = root.endsWith(sep) ? root : root + sep;
    if (target === root || target.startsWith(prefix)) return true;
  }
  return false;
}

function resolveSmithyModule(): Record<string, unknown> | null {
  const candidates: string[] = [];

  const envMain = process.env.DEFENSECLAW_OPENCLAW_MAIN;
  if (typeof envMain === "string" && envMain.length > 0) {
    if (isPermittedOpenclawMain(envMain)) {
      candidates.push(envMain);
    } else {
      console.warn(
        `[defenseclaw] Ignoring DEFENSECLAW_OPENCLAW_MAIN=${envMain} — path is not under a trusted OpenClaw install root; falling back to argv/execPath-based resolution.`,
      );
    }
  }

  const argv1 = process.argv[1];
  if (typeof argv1 === "string" && argv1.length > 0) {
    candidates.push(argv1);
  }

  const fromExec = tryOpenclawEntryFromNodeExecPath(process.execPath);
  if (fromExec) {
    candidates.push(fromExec);
  }

  try {
    candidates.push(fileURLToPath(import.meta.url));
  } catch {
    /* ignore */
  }

  for (const entry of candidates) {
    try {
      const req = createRequire(entry);
      return req("@smithy/node-http-handler") as Record<string, unknown>;
    } catch {
      /* try next entry */
    }
  }
  return null;
}

/**
 * @returns whether the optional Smithy package monkey-patch was applied.
 *   Bedrock HTTP/1 for pi-ai is driven by `AWS_BEDROCK_FORCE_HTTP1` (see `enableBedrockHttp1ForGuardrailProxy`).
 */
function applySmithyHttp1Patch(): boolean {
  const smithy = resolveSmithyModule();
  if (!smithy) {
    console.log(
      "[defenseclaw] Smithy package patch skipped (could not resolve @smithy/node-http-handler); pi-ai still uses HTTP/1 via AWS_BEDROCK_FORCE_HTTP1.",
    );
    return false;
  }

  const NodeHttp2Handler = smithy.NodeHttp2Handler as
    | { create: (instanceOrOptions?: unknown) => unknown }
    | undefined;
  const NodeHttpHandler = smithy.NodeHttpHandler as
    | { create: (instanceOrOptions?: unknown) => unknown }
    | undefined;

  if (
    !NodeHttp2Handler ||
    typeof NodeHttp2Handler.create !== "function" ||
    !NodeHttpHandler ||
    typeof NodeHttpHandler.create !== "function"
  ) {
    console.log(
      "[defenseclaw] Smithy package patch skipped (missing NodeHttp2Handler/NodeHttpHandler exports); pi-ai still uses HTTP/1 via AWS_BEDROCK_FORCE_HTTP1.",
    );
    return false;
  }

  NodeHttp2Handler.create = ((instanceOrOptions?: unknown) => {
    return NodeHttpHandler.create(instanceOrOptions);
  }) as typeof NodeHttp2Handler.create;

  const g = globalThis as typeof globalThis & Record<string, unknown>;
  g[PATCHED_FLAG] = true;

  return true;
}

/** Forces Bedrock over HTTP/1 so LLM traffic can reach the guardrail proxy (pi-ai + optional Smithy patch). */
function enableBedrockHttp1ForGuardrailProxy(): void {
  process.env.AWS_BEDROCK_FORCE_HTTP1 = "1";
  const smithyPatched = applySmithyHttp1Patch();
  console.log(
    smithyPatched
      ? "[defenseclaw] Amazon Bedrock → HTTP/1 for guardrail: AWS_BEDROCK_FORCE_HTTP1=1 (pi-ai) and Smithy NodeHttp2Handler→NodeHttpHandler patch."
      : "[defenseclaw] Amazon Bedrock → HTTP/1 for guardrail: AWS_BEDROCK_FORCE_HTTP1=1 (pi-ai).",
  );
}

/**
 * Patches `@smithy/node-http-handler` when Bedrock is in use (or forced).
 * Idempotent.
 */
export function patchAwsSdkHttp1ForGuardrail(
  opts?: PatchAwsSdkHttp1ForGuardrailOptions,
): void {
  const g = globalThis as typeof globalThis & Record<string, unknown>;
  if (g[DONE_FLAG]) return;
  g[DONE_FLAG] = true;

  if (process.env.DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM === "1") {
    console.log(
      "[defenseclaw] AWS HTTP/1 shim skipped (DEFENSECLAW_DISABLE_AWS_HTTP1_SHIM=1)",
    );
    return;
  }

  if (process.env.DEFENSECLAW_FORCE_AWS_HTTP1_SHIM === "1") {
    console.log(
      "[defenseclaw] AWS HTTP/1 shim forced (DEFENSECLAW_FORCE_AWS_HTTP1_SHIM=1)",
    );
    enableBedrockHttp1ForGuardrailProxy();
    return;
  }

  const mode: AwsHttp1ShimMode = opts?.pluginConfig?.awsHttp1Shim ?? "auto";

  if (mode === "off") {
    console.log(
      "[defenseclaw] AWS HTTP/1 shim disabled (plugins.entries.defenseclaw.awsHttp1Shim=off)",
    );
    return;
  }

  if (mode === "on") {
    enableBedrockHttp1ForGuardrailProxy();
    return;
  }

  // auto
  if (!openClawConfigUsesAmazonBedrock(opts?.openclawConfig)) {
    console.log(
      "[defenseclaw] AWS HTTP/1 shim skipped (no Amazon Bedrock in model config). Set plugins.entries.defenseclaw.awsHttp1Shim to \"on\" or DEFENSECLAW_FORCE_AWS_HTTP1_SHIM=1 if your setup needs it.",
    );
    return;
  }

  enableBedrockHttp1ForGuardrailProxy();
}
