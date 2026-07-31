// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import { copyFile, rm } from "node:fs/promises";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";

const [pluginPath, scratchPath, expected, command] = process.argv.slice(2);
if (
  !pluginPath ||
  !scratchPath ||
  !["allow", "block", "event", "lifecycle"].includes(expected) ||
  !command
) {
  throw new Error(
    "usage: node assert-opencode-plugin.mjs <plugin.js> <scratch.mjs> <allow|block|event|lifecycle> <command-or-event>",
  );
}

await copyFile(pluginPath, scratchPath);
const probeID = basename(scratchPath, ".mjs");
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
  const module = await import(`${pathToFileURL(scratchPath).href}?v=${Date.now()}`);
  if (typeof module.DefenseClaw !== "function") {
    throw new Error("installed OpenCode plugin does not export DefenseClaw");
  }
  const hooks = await module.DefenseClaw({
    directory: process.cwd(),
    worktree: process.cwd(),
  });
  if (
    typeof hooks["tool.execute.before"] !== "function" ||
    typeof hooks["tool.execute.after"] !== "function" ||
    typeof hooks.event !== "function"
  ) {
    throw new Error("installed OpenCode plugin is missing required hook functions");
  }

  if (expected === "event" || expected === "lifecycle") {
    const eventType = expected === "event" ? "session.created" : command;
    await hooks.event({
      event: {
        type: eventType,
        properties: {
          info: {
            id: `defenseclaw-windows-contract-lifecycle-${probeID}`,
            title: "DefenseClaw Windows lifecycle contract",
          },
        },
      },
    });
    console.log(JSON.stringify({ decision: "allow", event: eventType }));
  } else {
    let blocked = false;
    const toolCallID = `defenseclaw-windows-contract-${probeID}-${expected}-call`;
    try {
      await hooks["tool.execute.before"](
        {
          tool: "bash",
          sessionID: `defenseclaw-windows-contract-${probeID}`,
          callID: toolCallID,
        },
        { args: { command } },
      );
    } catch (error) {
      blocked = true;
      if (!(error instanceof Error) || !error.message) {
        throw new Error("OpenCode block path did not throw an Error with a reason");
      }
    }
    if ((expected === "block") !== blocked) {
      throw new Error(`OpenCode plugin verdict mismatch: expected=${expected} blocked=${blocked}`);
    }

    // This hook is intentionally observe-only. Awaiting its returned promise
    // proves the handler itself completes without turning telemetry failure into
    // a tool failure; the plugin does not await its internal POST.
    await hooks["tool.execute.after"](
      {
        tool: "bash",
        sessionID: `defenseclaw-windows-contract-${probeID}`,
        callID: toolCallID,
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
    console.log(JSON.stringify({ decision: blocked ? "block" : "allow" }));
  }
} finally {
  globalThis.fetch = nativeFetch;
  await rm(scratchPath, { force: true });
}
