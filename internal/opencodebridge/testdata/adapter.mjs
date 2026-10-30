// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const { defenseclawV2Setup } = await import(pathToFileURL(process.argv[2]));
const location = { directory: "/fixture", workspaceID: "fixture" };
let sessionCalls = 0, catalogCalls = 0, foreign = false, unavailable = false, blocked = false;
let servers = [{ name: "corp.docs" }];
const handlers = new Map(), after = [], lifecycle = [];
const ctx = {
  location,
  session: { get: async ({ sessionID }) => {
    sessionCalls++;
    if (unavailable) throw new Error("context unavailable");
    return { id: sessionID, location: foreign ? { ...location, directory: "/other" } : location };
  } },
  mcp: { list: async () => { catalogCalls++; return { location, data: servers }; } },
  tool: { hook: async (name, callback) => {
    handlers.set(name, callback);
    return { dispose: async () => handlers.delete(name) };
  } },
  event: { subscribe: async function* ({ signal }) {
    yield { type: "session.execution.failed", id: "event_fixture", data: { sessionID: "session" } };
    if (!signal.aborted) await new Promise(resolve => signal.addEventListener("abort", resolve, { once: true }));
  } },
};
const cleanup = await defenseclawV2Setup(ctx, async () => ({
  initialize: async () => {},
  "tool.execute.before": async () => { if (blocked) throw new Error("fixture denied"); },
  "tool.execute.after": async (input, output) => { after.push({ input, output }); },
  event: async ({ event }) => { lifecycle.push(event); },
}));
await new Promise(resolve => setImmediate(resolve));
assert.deepEqual(lifecycle.map(event => event.id), ["event_fixture", "event_fixture:idle"]);

const event = (id, overrides = {}) => ({
  id, sessionID: "session", messageID: "message", agent: "build", tool: "corp_docs_search",
  input: { query: "fixture" }, ...overrides,
});
const before = handlers.get("execute.before"), completed = handlers.get("execute.after");
const invokeAfter = invocation => completed({ ...invocation, status: "completed", result: { output: "fixture" } });
const paired = event("paired");
await before(paired);
const reads = [sessionCalls, catalogCalls];
unavailable = true;
servers = [{ name: "corp_docs" }];
await invokeAfter(paired);
assert.deepEqual([sessionCalls, catalogCalls], reads, "paired result must reuse verified context without API calls");
assert.equal(after.at(-1).input.mcpIdentity.name, "corp.docs", "result retains the inspected server identity");
assert.deepEqual(after.at(-1).input.args, paired.input);
unavailable = false;
await invokeAfter(event("unpaired"));
assert.equal(sessionCalls, reads[0] + 1, "unpaired result must resolve fresh bounded context");
assert.equal(after.at(-1).input.mcpIdentity.name, "corp_docs");

for (const field of ["sessionID", "tool", "messageID", "agent"]) {
  const original = event("mismatch-" + field);
  await before(original);
  const count = sessionCalls;
  await invokeAfter({ ...original, [field]: "different" });
  assert.equal(sessionCalls, count + 1, field + " mismatch must not reuse context");
}
// A tool input over 1 MiB is pinned whole and reaches the bridge, whose
// bounded review decides per mode; the adapter never refuses it on size.
const large = event("large", { tool: "write", input: { path: "/fixture/big.txt", content: "x".repeat(3 * 1024 * 1024) } });
await before(large);
assert.equal(Object.isFrozen(large.input), true, "large input is pinned");
assert.equal(large.input.content.length, 3 * 1024 * 1024, "large input reaches the bridge whole");
foreign = true;
await assert.rejects(before(event("foreign")), /verified session location/);
foreign = false;
await before(event("blocked"));
blocked = true;
await assert.rejects(before(event("blocked")), /fixture denied/);
blocked = false;
const blockedReads = sessionCalls;
await invokeAfter(event("blocked"));
assert.equal(sessionCalls, blockedReads + 1, "failed before callback cannot retain stale context");

for (let i = 0; i < 4097; i++) await before(event("bounded-" + i));
let count = sessionCalls;
await invokeAfter(event("bounded-0"));
assert.equal(sessionCalls, count + 1, "incomplete invocations must be evicted at the cache bound");
count = sessionCalls;
await invokeAfter(event("bounded-4096"));
assert.equal(sessionCalls, count, "recent invocation must remain cached");
await cleanup();
assert.equal(handlers.size, 0, "unload disposes every hook");
