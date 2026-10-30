// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Transport tests address the stable gateway event envelope through this
// source-derived V2 host. Every tool call invokes the registered native V2
// callback; the production plugin exports only its default setup definition.
export async function fixtureBridge(module, { directory } = {}) {
  const callbacks = new Map();
  const location = { directory: directory || "/work/repo" };
  let servers = [];
  const queue = [];
  let wake;
  const cleanup = await module.default.setup({
    location,
    session: { get: async ({ sessionID }) => ({ id: sessionID, location }) },
    mcp: { list: async () => ({ location, data: servers }) },
    tool: { hook: async (name, callback) => {
      callbacks.set(name, callback);
      return { dispose: async () => { callbacks.delete(name); } };
    } },
    event: { subscribe: async function* ({ signal }) {
      signal.addEventListener("abort", () => wake?.(), { once: true });
      while (!signal.aborted) {
        if (!queue.length) await new Promise((resolve) => { wake = resolve; });
        const next = queue.shift();
        if (!next) continue;
        try { yield next.event; } finally { next.resolve(); }
      }
    } },
  });
  const native = (input, args) => ({
    tool: input.tool, input: args || {}, sessionID: input.sessionID || "fixture-session",
    messageID: input.messageID, id: input.callID || "fixture-call", agent: input.agent,
  });
  return {
    // Configure only the host's MCP catalog. V2 argument authority comes
    // from the pinned event, independently of plugin registration order.
    config: async ({ mcp = {} } = {}) => {
      servers = Object.entries(mcp).filter(([, value]) => value && value.enabled !== false)
        .map(([name]) => ({ name }));
    },
    "tool.execute.before": (input, output) => callbacks.get("execute.before")(native(input, output?.args)),
    // Resolves to the native event, so a test can read the result the
    // plugin handed back to OpenCode.
    "tool.execute.after": async (input, output) => {
      const event = { ...native(input, input.args), status: "completed", result: output };
      await callbacks.get("execute.after")(event);
      return event;
    },
    event: ({ event }) => new Promise((resolve) => {
      const properties = event.properties || {};
      const sessionID = properties.sessionID || properties.info?.id || "fixture-session";
      queue.push({ event: { type: event.type, location, data: { ...properties, sessionID } }, resolve });
      wake?.();
    }),
    dispose: cleanup,
  };
}
