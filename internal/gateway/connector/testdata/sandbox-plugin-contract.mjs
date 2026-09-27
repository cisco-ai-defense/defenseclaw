// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Executable contract of the OpenShell sandbox variants of the OpenCode and
// Amp bridge plugins: the binding token comes from the environment, every
// request carries an idempotency key, a transport failure or relay
// 502/503/504 is retried exactly once with the same key, and every other
// failure fails closed.
//
//   node sandbox-plugin-contract.mjs opencode <rendered plugin.mjs>
//   node sandbox-plugin-contract.mjs amp <rendered plugin.ts>   (TypeScript stripping)

import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const [kind, pluginPath] = process.argv.slice(2);
if (!["opencode", "amp"].includes(kind) || !pluginPath) {
  throw new Error("usage: sandbox-plugin-contract.mjs opencode|amp <rendered plugin>");
}
const TOKEN = "openshell:resolve:env:v13503686996004693124_DEFENSECLAW_SANDBOX_TOKEN";
const ENDPOINT = `http://host.openshell.internal:18971/api/v1/${kind}/hook`;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
let serial = 0;

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      if (body instanceof Error) throw body;
      return body;
    },
  };
}

function setToken(token) {
  if (token === undefined) delete process.env.DEFENSECLAW_SANDBOX_TOKEN;
  else process.env.DEFENSECLAW_SANDBOX_TOKEN = token;
}

async function load() {
  const url = `${pathToFileURL(pluginPath).href}?scenario=${serial++}`;
  return { url, module: await import(url) };
}

// stubFetch records every request and answers the tool request sequence
// with responses[i] (a reply, or an Error to throw); other requests (load
// heartbeat) are allowed.
function stubFetch(responses, isToolRequest) {
  const all = [];
  const tool = [];
  globalThis.fetch = async (url, init) => {
    const payload = JSON.parse(init?.body || "{}");
    const request = { url: String(url), headers: init?.headers || {}, payload };
    all.push(request);
    if (!isToolRequest(payload)) return reply(200, { action: "allow", mode: "observe" });
    tool.push(request);
    const next = responses[Math.min(tool.length, responses.length) - 1];
    if (next instanceof Error) throw next;
    return next;
  };
  return { all, tool };
}

async function openCodeToolCall(responses, token) {
  setToken(token);
  const seen = stubFetch(responses, (p) => p.hook_event_name === "tool.execute.before");
  const { url, module } = await load();
  const hooks = await module.DefenseClaw({ directory: "/work/proj" });
  await hooks.config({ plugin_origins: [{ spec: url }], mcp: {} });
  let error;
  try {
    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: "c1" }, { args: { command: "echo hi" } });
  } catch (err) {
    error = err;
  }
  return { denied: Boolean(error), message: error ? error.message : "", ...seen };
}

async function ampToolCall(responses, token) {
  setToken(token);
  const seen = stubFetch(responses, (p) => p.hook_event_name === "tool.call");
  const { module } = await load();
  const handlers = {};
  const amp = {
    on: (event, fn) => {
      handlers[event] = fn;
    },
    system: { workspaceRoot: "", executor: { kind: "cli" }, user: { id: "u1", workspace: { id: "w1" } } },
    helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
    activeThread: { current: { id: "t1" } },
    ui: { notify: async () => {} },
  };
  module.default(amp);
  const ctx = {
    thread: { agent: async () => ({ definition: { kind: "builtin", mode: "smart" } }) },
    ui: {
      confirm: async () => {
        throw new Error("fixture: no UI");
      },
    },
  };
  const result = await handlers["tool.call"](
    { thread: { id: "t1" }, toolUseID: "tu1", tool: "Bash", input: { cmd: "echo hi" } },
    ctx,
  );
  const denied = result.action !== "allow";
  return { denied, message: result.message || "", ...seen };
}

const toolCall = kind === "opencode" ? openCodeToolCall : ampToolCall;
const allow = () => reply(200, { action: "allow", mode: "observe" });
const header = (request, name) => request.headers[name];

const scenarios = [
  {
    name: "allow carries the env token and an idempotency key",
    responses: [allow()],
    denied: false,
    tool: 1,
    verify(run) {
      const request = run.tool[0];
      assert.equal(request.url, ENDPOINT);
      assert.equal(header(request, "Authorization"), `Bearer ${TOKEN}`);
      assert.match(header(request, "X-DefenseClaw-Hook-Idempotency-Key"), UUID);
      for (const other of run.all) assert.match(header(other, "X-DefenseClaw-Hook-Idempotency-Key"), UUID);
    },
  },
  {
    name: "relay 503 is retried once with the same key",
    responses: [reply(503, {}), allow()],
    denied: false,
    tool: 2,
    verify(run) {
      assert.equal(header(run.tool[0], "X-DefenseClaw-Hook-Idempotency-Key"), header(run.tool[1], "X-DefenseClaw-Hook-Idempotency-Key"));
    },
  },
  {
    name: "a dropped connection is retried once with the same key",
    responses: [new TypeError("fetch failed"), allow()],
    denied: false,
    tool: 2,
    verify(run) {
      assert.equal(header(run.tool[0], "X-DefenseClaw-Hook-Idempotency-Key"), header(run.tool[1], "X-DefenseClaw-Hook-Idempotency-Key"));
    },
  },
  { name: "two relay failures fail closed", responses: [reply(502, {}), reply(504, {})], denied: true, tool: 2 },
  { name: "unreachable ingress fails closed", responses: [new TypeError("fetch failed"), new TypeError("fetch failed")], denied: true, tool: 2 },
  { name: "401 fails closed without a retry", responses: [reply(401, { error: "unauthorized" })], denied: true, tool: 1 },
  { name: "429 fails closed without a retry", responses: [reply(429, {})], denied: true, tool: 1 },
  { name: "a reply without a verdict fails closed", responses: [reply(200, { hook_output: {} })], denied: true, tool: 1 },
  { name: "malformed JSON fails closed", responses: [reply(200, new SyntaxError("fixture"))], denied: true, tool: 1 },
  {
    name: "block with a reason denies",
    responses: [reply(200, { action: "block", reason: "fixture policy", hook_output: { decision: "deny", reason: "fixture policy" } })],
    denied: true,
    tool: 1,
    verify(run) {
      assert.match(run.message, /fixture policy/);
    },
  },
  { name: "block without an event verdict denies", responses: [reply(200, { action: "block", reason: "fixture block" })], denied: true, tool: 1 },
  { name: "missing token fails closed before any request", responses: [allow()], token: undefined, denied: true, tool: 0 },
  { name: "malformed token fails closed before any request", responses: [allow()], token: "bad token\nX-Injected: 1", denied: true, tool: 0 },
];

for (const scenario of scenarios) {
  const token = "token" in scenario ? scenario.token : TOKEN;
  const run = await toolCall(scenario.responses, token);
  assert.equal(run.denied, scenario.denied, `${kind}: ${scenario.name}: denied`);
  assert.equal(run.tool.length, scenario.tool, `${kind}: ${scenario.name}: tool requests`);
  if (scenario.denied) assert.match(run.message, /DefenseClaw|fixture/, `${kind}: ${scenario.name}: message`);
  if (scenario.verify) scenario.verify(run);
}
console.log(`${kind} sandbox plugin contract: ${scenarios.length} scenarios passed`);
