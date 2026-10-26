// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { copyFile, rm } from "node:fs/promises";
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
try {
  const module = await import(moduleURL);
  if (typeof module.DefenseClaw !== "function") {
    throw new Error("installed OpenCode plugin does not export DefenseClaw");
  }
  const hooks = await module.DefenseClaw({
    directory: process.cwd(),
    worktree: process.cwd(),
  });
  if (
    typeof hooks.config !== "function" ||
    typeof hooks["tool.execute.before"] !== "function" ||
    typeof hooks["tool.execute.after"] !== "function" ||
    typeof hooks.event !== "function"
  ) {
    throw new Error("installed OpenCode plugin is missing required hook functions");
  }

  // OpenCode invokes every plugin's config hook after resolving the complete
  // plugin list. The synthetic contract must model that official loader step
  // so the managed plugin can prove it is last and therefore authoritative
  // over the final tool arguments. Omitting this call correctly forces action
  // mode to refuse the operation.
  await hooks.config({
    plugin_origins: [{ spec: moduleURL }],
    mcp: {},
  });

  if (expected === "load") {
    // Setup convergence only needs the authenticated config-load heartbeat.
    // Avoid spending its bounded readiness window on unrelated tool hooks.
  } else if (expected === "lifecycle") {
    await hooks.event({
      event: {
        type: command,
        properties: {
          info: {
            id: `defenseclaw-windows-contract-lifecycle-${probeID}`,
            title: "DefenseClaw Windows lifecycle contract",
          },
        },
      },
    });
  } else {
    let blocked = false;
    let reason = "";
    try {
      await hooks["tool.execute.before"](
        {
          tool: "bash",
          sessionID: `defenseclaw-windows-contract-${probeID}`,
          callID: `defenseclaw-windows-contract-${probeID}-call`,
        },
        { args: { command } },
      );
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
    await hooks["tool.execute.after"](
      {
        tool: "bash",
        sessionID: `defenseclaw-windows-contract-${probeID}`,
        callID: `defenseclaw-windows-contract-${probeID}-call`,
        args: { command },
      },
      {
        title: "synthetic OpenCode tool result",
        output: "synthetic OpenCode output",
        metadata: { source: "DefenseClaw contract fixture" },
      },
    );
    if (
      observedAfterPayload?.tool_input?.command !== command ||
      observedAfterPayload?.tool_result?.title !== "synthetic OpenCode tool result" ||
      observedAfterPayload?.tool_result?.output !== "synthetic OpenCode output" ||
      observedAfterPayload?.tool_result?.metadata?.source !== "DefenseClaw contract fixture"
    ) {
      throw new Error(
        `OpenCode after payload does not preserve official input args and result output: ${JSON.stringify(observedAfterPayload)}`,
      );
    }
  }
} finally {
  globalThis.fetch = nativeFetch;
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
