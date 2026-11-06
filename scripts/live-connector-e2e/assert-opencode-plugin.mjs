// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, rm } from "node:fs/promises";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import { pathToFileURL } from "node:url";

const [pluginPath, scratchPath, expected, command] = process.argv.slice(2);
if (
  !pluginPath ||
  !scratchPath ||
  !["allow", "block", "lifecycle", "load"].includes(expected) ||
  !command
) {
  throw new Error(
    "usage: node assert-opencode-plugin.mjs <plugin.js> <scratch.mjs> <allow|block|lifecycle|load> <command-or-event>",
  );
}

await copyFile(pluginPath, scratchPath);
const probeID = basename(scratchPath, ".mjs");
const moduleURL = `${pathToFileURL(scratchPath).href}?v=${Date.now()}`;
const nativeFetch = globalThis.fetch;
let observedAfterPayload;
globalThis.fetch = async (url, init) => {
  const payload = JSON.parse(init?.body || "{}");
  if (payload.hook_event_name === "tool.execute.after") {
    observedAfterPayload = payload;
    return {
      ok: true,
      status: 200,
      async json() {
        return { hook_output: { decision: "allow" } };
      },
    };
  }
  return nativeFetch(url, init);
};
// A per-user plugin posts through its gateway's hook-post (execFileSync, the
// JSON request on stdin) rather than fetch: capture the after payload there
// too. The plugin imports execFileSync by name, so the patched CommonJS export
// is synced into the ESM binding before the plugin loads.
const childProcess = createRequire(import.meta.url)("node:child_process");
const nativeExecFileSync = childProcess.execFileSync;
childProcess.execFileSync = function (file, args, options) {
  if (Array.isArray(args) && args[0] === "hook-post" && typeof options?.input === "string") {
    const request = JSON.parse(options.input);
    const payload = JSON.parse(request.body || "{}");
    if (payload.hook_event_name === "tool.execute.after") {
      observedAfterPayload = payload;
      return JSON.stringify({ status: 200, body: JSON.stringify({ hook_output: { decision: "allow" } }) });
    }
  }
  return nativeExecFileSync.apply(this, arguments);
};
syncBuiltinESMExports();
let cleanup;
let lifecycle;
try {
  const module = await import(moduleURL);
  if (module.default?.id !== "cisco.defenseclaw" || typeof module.default.setup !== "function" || Object.keys(module).join() !== "default") {
    throw new Error("installed OpenCode plugin must export only its V2 setup definition");
  }
  const hooks = new Map();
  const location = { directory: process.cwd() };
  cleanup = await module.default.setup({
    location,
    session: { get: async ({ sessionID }) => ({ id: sessionID, location }) },
    mcp: { list: async () => ({ location, data: [] }) },
    tool: { hook: async (name, callback) => {
      hooks.set(name, callback);
      return { dispose: async () => hooks.delete(name) };
    } },
    event: { subscribe: async function* ({ signal }) {
      const event = await new Promise((resolve) => {
        lifecycle = resolve;
        signal.addEventListener("abort", () => resolve(null), { once: true });
      });
      if (event) yield event;
    } },
  });
  if (
    typeof hooks.get("execute.before") !== "function" ||
    typeof hooks.get("execute.after") !== "function"
  ) {
    throw new Error("installed OpenCode V2 plugin is missing awaited tool callbacks");
  }

  if (expected === "load") {
    // Setup convergence only needs the authenticated V2 setup heartbeat.
    // Avoid spending its bounded readiness window on unrelated tool hooks.
  } else if (expected === "lifecycle") {
    const nativeType = {
      "session.status": "session.execution.started",
      "session.idle": "session.execution.succeeded",
      "session.error": "session.execution.failed",
    }[command] || command;
    lifecycle({
      type: nativeType, location,
      data: { sessionID: `defenseclaw-windows-contract-lifecycle-${probeID}` },
    });
    // Give the asynchronous subscription one turn to post the lifecycle event.
    await new Promise((resolve) => setImmediate(resolve));
  } else {
    let blocked = false;
    let reason = "";
    try {
      await hooks.get("execute.before")({
        tool: "shell", input: { command },
        sessionID: `defenseclaw-windows-contract-${probeID}`,
        id: `defenseclaw-windows-contract-${probeID}-call`,
      });
    } catch (error) {
      blocked = true;
      reason = error instanceof Error ? error.message : String(error);
      if (!(error instanceof Error) || !error.message) {
        throw new Error("OpenCode block path did not throw an Error with a reason");
      }
    }
    if ((expected === "block") !== blocked) {
      throw new Error(`OpenCode plugin verdict mismatch: expected=${expected} blocked=${blocked}${reason ? ` reason=${reason.slice(0, 600)}` : ""}${perUserPostDiagnostic(reason)}`);
    }

    // This hook is intentionally observe-only. Awaiting its returned promise
    // proves the handler itself completes without turning telemetry failure into
    // a tool failure; the plugin does not await its internal POST.
    await hooks.get("execute.after")({
      tool: "shell", input: { command },
      sessionID: `defenseclaw-windows-contract-${probeID}`,
      id: `defenseclaw-windows-contract-${probeID}-call`,
      status: "completed", result: {
        output: { output: "synthetic OpenCode output", exit: 0 },
        content: [{ type: "text", text: "synthetic OpenCode output" }],
      },
    });
    if (
      observedAfterPayload?.tool_input?.command !== command ||
      observedAfterPayload?.tool_result?.output?.output !== "synthetic OpenCode output" ||
      observedAfterPayload?.tool_result?.output?.exit !== 0 ||
      observedAfterPayload?.tool_result?.opencode_v2_status !== "completed"
    ) {
      throw new Error(
        `OpenCode after payload does not preserve official input args and result output: ${JSON.stringify(observedAfterPayload)}`,
      );
    }
  }
} finally {
  await cleanup?.();
  globalThis.fetch = nativeFetch;
  childProcess.execFileSync = nativeExecFileSync;
  syncBuiltinESMExports();
  await rm(scratchPath, { force: true });
}

// perUserPostDiagnostic says why a per-user plugin's post through the native
// gateway helper failed: the home the plugin resolves, whether the helper is
// there, and the helper's own error for a bare request (no credential).
function perUserPostDiagnostic(reason) {
  if (!/per-user gateway peer unverified/.test(reason || "")) return "";
  const plugin = readFileSync(pluginPath, "utf8");
  const rendered = (/const DC_GATEWAY_BINARY = "((?:[^"\\]|\\.)*)";/.exec(plugin) || [])[1] || "";
  const gateway = rendered ? JSON.parse(`"${rendered}"`) : join(homedir(), ".local", "bin", process.platform === "win32" ? "defenseclaw-gateway.exe" : "defenseclaw-gateway");
  const address = (/const DC_API_ADDR = "([^"]*)"/.exec(plugin) || [])[1] || "";
  let detail = ` home=${homedir()} gateway=${gateway} exists=${existsSync(gateway)} api=${address}`;
  try {
    execFileSync(gateway, ["hook-post", "--api-addr", address], {
      input: JSON.stringify({ path: "/health", headers: {}, body: "" }),
      timeout: 15000, encoding: "utf8", windowsHide: true, stdio: ["pipe", "pipe", "pipe"],
    });
    detail += " hook-post=ok";
  } catch (error) {
    detail += ` hook-post=${String((error && (error.stderr || error.message)) || error).trim().slice(0, 400)}`;
  }
  return detail;
}
