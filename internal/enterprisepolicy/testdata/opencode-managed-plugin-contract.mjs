// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Contract for the managed OpenCode plugin: every event goes through the
// administrator-owned hook binary beside it, and every failure blocks the
// tool call except after uninstall.
//
//   node opencode-managed-plugin-contract.mjs <plugin> <fake-dir>
//
// <plugin> is <root>/share/opencode/defenseclaw.js; <root>/bin/defenseclaw-hook
// is a fake that logs its argv and stdin to <fake-dir>/calls.jsonl and answers
// from <fake-dir>/event.json (per-event calls) or <fake-dir>/guard.json
// (--foreign-hook-check): {"stdout": "...", "exit": N}.

import assert from "node:assert/strict";
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

const [pluginPath, fakeDir] = process.argv.slice(2);
if (!pluginPath || !fakeDir) throw new Error("expected <plugin> <fake-dir>");
const hookBinary = join(pluginPath, "..", "..", "..", "bin", "defenseclaw-hook");
const hookSource = readFileSync(hookBinary);

let serial = 0;

function answer(file, stdout, exit = 0) {
  writeFileSync(join(fakeDir, file), JSON.stringify({ stdout, exit }));
}

function calls() {
  try {
    return readFileSync(join(fakeDir, "calls.jsonl"), "utf8").trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
  } catch (err) {
    if (err.code === "ENOENT") return [];
    throw err;
  }
}

// The per-event calls; the startup guard runs concurrently with load.
function eventCalls() {
  return calls().filter((call) => call.args.includes("--enterprise-managed"));
}

function resetCalls() {
  rmSync(join(fakeDir, "calls.jsonl"), { force: true });
}

async function load({ guard = JSON.stringify({ deny: false }), guardExit = 0, origins, mcp, client } = {}) {
  answer("guard.json", guard, guardExit);
  serial += 1;
  const url = pathToFileURL(pluginPath).href + "?instance=" + serial;
  const mod = await import(url);
  assert.deepEqual(Object.keys(mod), ["DefenseClawManaged"]);
  const hooks = await mod.DefenseClawManaged({ client, directory: "/work/repo", worktree: "/work/repo" });
  answer("event.json", JSON.stringify({ action: "allow", mode: "observe", hook_output: { decision: "allow" } }));
  await hooks.config({
    plugin_origins: origins || [{ spec: "file:///other/plugin.js" }, { spec: pluginPath }],
    mcp: mcp || {},
  });
  resetCalls();
  return hooks;
}

async function before(hooks, tool = "bash", args = { command: "ls" }) {
  return hooks["tool.execute.before"](
    { tool, sessionID: "s1", callID: "c1", messageID: "m1", agent: "build" },
    { args },
  );
}

// The load heartbeat, the startup guard and a pre-tool call.
{
  answer("guard.json", JSON.stringify({ deny: false }));
  resetCalls();
  const hooks = await load();
  answer("event.json", JSON.stringify({ action: "allow", mode: "action", hook_output: { decision: "allow" } }));
  await before(hooks);
  const [call] = eventCalls();
  assert.deepEqual(call.args, ["hook", "--connector", "opencode", "--enterprise-managed", "--event", "tool.execute.before"]);
  const payload = JSON.parse(call.stdin);
  assert.equal(payload.hook_event_name, "tool.execute.before");
  assert.equal(payload.tool_name, "bash");
  assert.deepEqual(payload.tool_input, { command: "ls" });
  assert.equal(payload.session_id, "s1");
  assert.equal(payload.tool_call_id, "c1");
  assert.equal(payload.cwd, "/work/repo");
  assert.equal(payload.arguments_authoritative, true, "the managed plugin named last by absolute path is authoritative");
  assert.equal(payload.mcp_identity_status, "not_mcp");
}

// A gateway deny aborts the tool with its reason and says DefenseClaw blocked
// it under the organization's policy; a confirm verdict, which this plugin
// cannot ask about, shows a visible notice, led by the gateway's wording,
// instead of running silently.
{
  const toasts = [];
  const client = { tui: { showToast: async (arg) => { toasts.push(arg && arg.body ? arg.body : arg); return true; } } };
  const hooks = await load({ client });
  answer("event.json", JSON.stringify({ action: "block", mode: "action", hook_output: { decision: "deny", reason: "policy marker rule" } }));
  await assert.rejects(before(hooks), /under your organization's policy, so it did not run: policy marker rule/);
  answer("event.json", JSON.stringify({ action: "alert", raw_action: "confirm", mode: "action", severity: "HIGH", reason: "DefenseClaw flagged this action for review under your organization's policy (rule TEST-MARKER)." }));
  await before(hooks);
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.ok(toasts.some((toast) => toast.variant === "warning" && /^DefenseClaw flagged this action for review .*\(rule TEST-MARKER\)\. OpenCode cannot ask/.test(toast.message)), JSON.stringify(toasts));
}

// Every failure of the hook blocks.
for (const [stdout, exit, pattern] of [
  [JSON.stringify({ hook_output: { decision: "deny", reason: "DefenseClaw hook failed closed" } }), 2, /failed closed/],
  ["", 2, /failed closed \(exit 2\)/],
  ["not json", 0, /failed closed/],
  [JSON.stringify({ action: "allow" }), 3, /failed closed \(exit 3\)/],
]) {
  const hooks = await load();
  answer("event.json", stdout, exit);
  await assert.rejects(before(hooks), pattern);
}

// No output and exit 0 is the uninstalled no-op: allow.
{
  const hooks = await load();
  answer("event.json", "", 0);
  await before(hooks);
}

// Action mode needs authoritative arguments: a plugin after this one could
// still rewrite them.
{
  const hooks = await load({ origins: [{ spec: pathToFileURL(pluginPath).href }, { spec: "file:///later/plugin.js" }] });
  answer("event.json", JSON.stringify({ action: "allow", mode: "action", hook_output: { decision: "allow" } }));
  await assert.rejects(before(hooks), /later plugin argument mutations/);
  answer("event.json", JSON.stringify({ action: "allow", mode: "observe", hook_output: { decision: "allow" } }));
  await before(hooks);
}

// Ambiguous MCP identity is refused in action mode.
{
  const hooks = await load({ mcp: { "a.b": { type: "local" }, "a_b": { type: "local" } } });
  answer("event.json", JSON.stringify({ action: "allow", mode: "action", hook_output: { decision: "allow" } }));
  await assert.rejects(before(hooks, "a_b_tool"), /ambiguous MCP server identity/);
}

// A foreign plugin found at load blocks every call for the process, also
// after its file is removed; each denied call still runs the guard check,
// which the gateway records.
{
  const hooks = await load({ guard: JSON.stringify({ deny: true, reason: "enterprise_foreign_hook_blocked: rewrite.js" }) });
  await assert.rejects(before(hooks), /rewrite\.js/);
  answer("guard.json", JSON.stringify({ deny: false }));
  resetCalls();
  await assert.rejects(before(hooks), /rewrite\.js/);
  const [check, ...rest] = calls();
  assert.equal(rest.length, 0, "a blocked process never forwards the call");
  assert.ok(check && check.args.includes("--foreign-hook-check"), "a denied call runs the guard check");
  assert.equal(JSON.parse(check.stdin).hook_event_name, "tool.execute.before");
}
{
  const hooks = await load({ guard: "garbage" });
  await assert.rejects(before(hooks), /unapproved plugin/);
}
// A failed load-time check holds for the process (OpenCode loads plugins
// once), so the reason says to restart the agent.
{
  const hooks = await load({ guard: "", guardExit: 1 });
  await assert.rejects(before(hooks), /could not check for unapproved plugins when the agent started.*Restart the agent/);
  answer("guard.json", JSON.stringify({ deny: false }));
  await assert.rejects(before(hooks), /Restart the agent/);
}

// Post-tool telemetry and lifecycle events never throw.
{
  const hooks = await load();
  answer("event.json", "", 2);
  await hooks["tool.execute.after"]({ tool: "bash", args: { command: "ls" }, sessionID: "s1" }, { title: "t", output: "o", metadata: {} });
  await hooks.event({ event: { type: "session.idle", properties: { sessionID: "s1" } } });
  await hooks.event({ event: { type: "message.updated", properties: {} } });
  const events = eventCalls().map((call) => call.args[call.args.length - 1]);
  assert.deepEqual(events, ["tool.execute.after", "session.idle"]);
  const after = JSON.parse(eventCalls()[0].stdin);
  assert.deepEqual(after.tool_response, { title: "t", output: "o", metadata: {} });
}

// A hook binary that cannot run blocks while DefenseClaw is installed, and
// allows once uninstall removed this plugin file too.
{
  const hooks = await load();
  // The startup guard runs the binary concurrently with load; let it finish.
  await before(hooks);
  rmSync(hookBinary);
  try {
    await assert.rejects(before(hooks), /failed closed/);
    const pluginSource = readFileSync(pluginPath);
    rmSync(pluginPath);
    try {
      await before(hooks);
    } finally {
      writeFileSync(pluginPath, pluginSource);
    }
  } finally {
    writeFileSync(hookBinary, hookSource, { mode: 0o755 });
  }
}

console.log("managed OpenCode plugin contract: ok");
