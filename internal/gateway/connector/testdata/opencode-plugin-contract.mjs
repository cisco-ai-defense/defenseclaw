// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const [openPluginPath, closedPluginPath] = process.argv.slice(2);
if (!openPluginPath || !closedPluginPath) {
  throw new Error("expected rendered fail-open and fail-closed OpenCode plugins");
}

const nativeFetch = globalThis.fetch;
let serial = 0;

function successfulResponse(body) {
  return {
    ok: true,
    status: 200,
    async json() {
      return body;
    },
  };
}

async function runScenario({
  name,
  pluginPath = openPluginPath,
  mode = "observe",
  mcp = {},
  tool = "bash",
  laterPlugin = false,
  response = { action: "allow", mode, would_block: false },
  failure,
  expectBlocked = false,
  verify,
}) {
  const requests = [];
  globalThis.fetch = async (url, init) => {
    const payload = JSON.parse(init?.body || "{}");
    requests.push({ url: String(url), init, payload });
    if (payload.hook_event_name === "defenseclaw.plugin.loaded") {
      return successfulResponse({ action: "allow", mode, would_block: false });
    }
    if (failure?.status) {
      return { ok: false, status: failure.status };
    }
    if (failure?.timeout) {
      throw new DOMException("fixture timeout", "AbortError");
    }
    if (failure?.malformed) {
      return {
        ok: true,
        status: 200,
        async json() {
          throw new SyntaxError("fixture malformed gateway JSON");
        },
      };
    }
    return successfulResponse(response);
  };

  const moduleURL = `${pathToFileURL(pluginPath).href}?scenario=${serial++}`;
  const module = await import(moduleURL);
  const hooks = await module.DefenseClaw({ directory: "fixture workspace" });
  const origins = [{ spec: moduleURL }];
  if (laterPlugin) origins.push({ spec: "file:///fixture-later-plugin.mjs" });
  await hooks.config({ plugin_origins: origins, mcp });

  let blockedError;
  try {
    await hooks["tool.execute.before"](
      { tool, sessionID: `fixture-${name}`, callID: `fixture-${name}-call` },
      { args: { value: "fixture input" } },
    );
  } catch (error) {
    blockedError = error;
  }
  assert.equal(Boolean(blockedError), expectBlocked, `${name}: block posture`);
  if (blockedError) assert.match(blockedError.message, /DefenseClaw/);

  const request = requests.find(({ payload }) => payload.hook_event_name === "tool.execute.before");
  assert.ok(request, `${name}: authenticated gateway call was not made`);
  assert.equal(request.url, "http://127.0.0.1:18970/api/v1/opencode/hook");
  assert.equal(request.init.headers.Authorization, "Bearer provided by test runtime");
  assert.equal(request.init.headers["X-DefenseClaw-Client"], "opencode-plugin/1.0");
  if (verify) verify(request.payload);
}

try {
  const collisionMCP = {
    "alpha.beta": { command: ["fixture launcher alpha"], endpoint: "fixture endpoint alpha" },
    "alpha?beta": { command: ["fixture launcher beta"], endpoint: "fixture endpoint beta" },
  };
  const verifyAmbiguity = (payload) => {
    assert.equal(payload.tool_name, "alpha_beta_list");
    assert.equal(payload.mcp_identity_status, "ambiguous");
    assert.equal("mcp_server_name" in payload, false);
    const wire = JSON.stringify(payload);
    for (const guessed of [
      "alpha.beta",
      "alpha?beta",
      "fixture launcher alpha",
      "fixture launcher beta",
      "fixture endpoint alpha",
      "fixture endpoint beta",
    ]) {
      assert.equal(wire.includes(guessed), false, `ambiguous payload guessed ${guessed}`);
    }
  };

  await runScenario({
    name: "collision-observe",
    mcp: collisionMCP,
    tool: "alpha_beta_list",
    response: { action: "allow", mode: "observe", would_block: true },
    verify: verifyAmbiguity,
  });
  await runScenario({
    name: "collision-action",
    mode: "action",
    mcp: collisionMCP,
    tool: "alpha_beta_list",
    response: { action: "allow", mode: "action", would_block: false },
    expectBlocked: true,
    verify: verifyAmbiguity,
  });
  await runScenario({
    name: "unique-authoritative-server",
    mcp: { "jira.prod": { command: ["fixture jira launcher"] } },
    tool: "jira_prod_create_issue",
    verify(payload) {
      assert.equal(payload.mcp_identity_status, "authoritative");
      assert.equal(payload.mcp_server_name, "jira.prod");
    },
  });
  await runScenario({
    name: "non-mcp",
    mcp: { "jira.prod": { command: ["fixture jira launcher"] } },
    tool: "bash",
    verify(payload) {
      assert.equal(payload.mcp_identity_status, "not_mcp");
      assert.equal("mcp_server_name" in payload, false);
    },
  });
  await runScenario({
    name: "later-plugin-observe",
    laterPlugin: true,
    verify(payload) {
      assert.equal(payload.arguments_authoritative, false);
    },
  });
  await runScenario({
    name: "later-plugin-action",
    mode: "action",
    laterPlugin: true,
    response: { action: "allow", mode: "action", would_block: false },
    expectBlocked: true,
    verify(payload) {
      assert.equal(payload.arguments_authoritative, false);
    },
  });
  await runScenario({
    name: "unconditional-gateway-deny",
    response: {
      action: "block",
      mode: "observe",
      would_block: false,
      hook_output: { decision: "deny", reason: "DefenseClaw fixture gateway deny" },
    },
    expectBlocked: true,
  });

  for (const failure of [
    { name: "401", status: 401 },
    { name: "5xx", status: 503 },
    { name: "timeout", timeout: true },
    { name: "malformed", malformed: true },
  ]) {
    await runScenario({ name: `${failure.name}-open`, failure });
    await runScenario({
      name: `${failure.name}-closed`,
      pluginPath: closedPluginPath,
      failure,
      expectBlocked: true,
    });
  }
} finally {
  globalThis.fetch = nativeFetch;
}
