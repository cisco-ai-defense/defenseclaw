// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";

// Source-derived Promise API fixture: @opencode/plugin 2.0.0 / 2.1.4.
// Both real DefenseClaw transports run this contract; no SDK is substituted
// for the bridge itself. The host awaits each before hook before execution.
export async function contract(plugin, fixture) {
  assert.equal(plugin.id, "cisco.defenseclaw");
  assert.equal(typeof plugin.server, "function");
  assert.equal(typeof plugin.setup, "function");
  const hooks = new Map();
  const location = { directory: "/work/repo", workspaceID: "ws_test" };
  let sessionLocation = location;
  let servers = [];
  let disposed = 0;
  let streamStopped = false;
  const ctx = {
    location,
    session: { get: async ({ sessionID }) => ({ id: sessionID, location: sessionLocation }) },
    mcp: { list: async () => ({ location, data: servers }) },
    tool: { hook: async (name, callback) => {
      await Promise.resolve();
      hooks.set(name, callback);
      return { dispose: async () => { hooks.delete(name); disposed++; } };
    } },
    event: { subscribe: async function* ({ signal }) {
      yield { type: "session.created", id: "evt_created", location,
        data: { sessionID: "ses_child", parentID: "ses_parent", agent: "build" } };
      yield { type: "session.created", id: "evt_foreign", location: { directory: "/other" },
        data: { sessionID: "ses_foreign" } };
      yield { type: "session.execution.started", id: "evt_started", data: { sessionID: "ses_child" } };
      yield { type: "session.execution.failed", id: "evt_failed", data: { sessionID: "ses_child", error: { message: "failed" } } };
      if (!signal.aborted) await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
      streamStopped = true;
    } },
  };
  const allow = { action: "allow", mode: "action", hook_output: { decision: "allow" } };
  await fixture.reply(allow);
  const cleanup = await plugin.setup(ctx);
  assert.deepEqual([...hooks.keys()], ["execute.before", "execute.after"]);
  const event = (tool = "shell", input = { command: "echo approved", nested: { list: ["safe"] } }) => ({
    tool, input, sessionID: "ses_test", messageID: "msg_test", id: "call_test", agent: "build",
  });
  const original = event();
  const retained = original.input;
  let executed = 0;
  await hooks.get("execute.before")(original);
  executed++;
  assert.equal(executed, 1);
  retained.command = "uninspected command";
  retained.nested.list[0] = "uninspected value";
  assert.equal(original.input.command, "echo approved");
  assert.equal(original.input.nested.list[0], "safe");
  assert.throws(() => { original.tool = "other"; }, TypeError);
  assert.throws(() => { original.input = {}; }, TypeError);
  assert.throws(() => { original.input.nested.list.push("other"); }, TypeError);

  await fixture.reply({ action: "block", mode: "action", hook_output: { decision: "deny", reason: "policy denied" } });
  executed = 0;
  await assert.rejects(async () => { await hooks.get("execute.before")(event()); executed++; }, /policy denied/);
  assert.equal(executed, 0);
  await fixture.reply(allow);
  servers = [{ name: "corp.docs" }];
  await hooks.get("execute.before")(event("corp_docs_search", { query: "test" }));
  servers.push({ name: "corp_docs" });
  await assert.rejects(hooks.get("execute.before")(event("corp_docs_search")), /ambiguous/);
  servers = [];
  sessionLocation = { directory: "/other", workspaceID: "ws_test" };
  await assert.rejects(hooks.get("execute.before")(event()), /verified session location/);
  sessionLocation = location;
  await assert.rejects(hooks.get("execute.before")(event("shell", { command: "x".repeat(1048577) })), /oversized/);
  await assert.rejects(hooks.get("execute.before")(event("shell", { get command() { return "x"; } })), /accessor/);
  await assert.rejects(hooks.get("execute.before")({ tool: "shell", input: {} }), /incomplete/);

  await hooks.get("execute.after")({ ...event(), status: "completed",
    result: { output: { output: "done", exit: 0, status: "completed" }, content: [{ type: "text", text: "done" }] } });
  await hooks.get("execute.after")({ ...event(), status: "error", error: { message: "execution failed" } });
  await hooks.get("execute.after")({ ...event(), status: "completed" });
  // Delivery is best-effort; after hooks must not break an executed tool.
  ctx.session.get = async () => { throw new Error("context unavailable"); };
  await hooks.get("execute.after")({ ...event(), status: "error", error: { message: "tool failed" } });

  const payloads = await fixture.payloads();
  const pre = payloads.find((p) => p.hook_event_name === "tool.execute.before" && p.tool_name === "shell");
  assert.equal(pre.cwd, location.directory);
  assert.equal(pre.session_id, "ses_test");
  assert.equal(pre.turn_id, "msg_test");
  assert.equal(pre.tool_call_id, "call_test");
  assert.equal(pre.arguments_authoritative, true);
  assert.equal(pre.tool_input.command, "echo approved");
  assert(payloads.some((p) => p.mcp_server_name === "corp.docs"));
  const results = payloads.filter((p) => p.hook_event_name === "tool.execute.after");
  assert.equal(results.length, 3);
  assert.equal(results[0].tool_response.output.exit, 0);
  assert.equal(results[0].tool_response.opencode_v2_status, "completed");
  assert.equal(results[1].tool_response.opencode_v2_status, "error");
  assert.equal(results[2].tool_response.opencode_v2_status, "unknown");
  assert(payloads.some((p) => p.session_id === "ses_child" && p.parent_session_id === "ses_parent"));
  assert(!payloads.some((p) => p.session_id === "ses_foreign"));
  assert(payloads.some((p) => p.hook_event_name === "session.status" && p.session_id === "ses_child"));
  assert(payloads.some((p) => p.hook_event_name === "session.error" && p.session_id === "ses_child"));
  assert(payloads.some((p) => p.hook_event_name === "session.idle" && p.session_id === "ses_child"));
  await cleanup();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(disposed, 2);
  assert.equal(hooks.size, 0);
  assert(streamStopped);
  console.log("OpenCode v2 contract: ok");
}
