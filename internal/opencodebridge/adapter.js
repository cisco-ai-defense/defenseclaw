// OpenCode v2 Promise plugin adapter. Reviewed against f669c46c9604ea3d70b8a7ed1f0c10f3a5ac1f61.
// The host awaits execute.before and propagates a rejected Promise before
// executing the tool. No OpenCode SDK package is needed at runtime.

function defenseclawPinV2Event(event) {
  if (!event || typeof event !== "object") throw new Error("DefenseClaw refused an incomplete OpenCode v2 tool event.");
  let nodes = 0;
  let characters = 0;
  const copy = (value, depth) => {
    if (++nodes > 16384 || depth > 64) throw new Error("DefenseClaw refused oversized OpenCode tool arguments.");
    if (typeof value === "string") {
      characters += value.length;
      if (characters > 1048576) throw new Error("DefenseClaw refused oversized OpenCode tool arguments.");
      return value;
    }
    if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) return value;
    if (!value || typeof value !== "object" || (!Array.isArray(value) && Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null)) {
      throw new Error("DefenseClaw refused non-JSON OpenCode tool arguments.");
    }
    const result = Array.isArray(value) ? [] : Object.create(null);
    for (const [key, descriptor] of Object.entries(Object.getOwnPropertyDescriptors(value))) {
      if (Array.isArray(value) && key === "length") continue;
      if (!descriptor.enumerable) continue;
      if (!("value" in descriptor)) throw new Error("DefenseClaw refused accessor tool arguments.");
      characters += key.length;
      if (characters > 1048576) throw new Error("DefenseClaw refused oversized OpenCode tool arguments.");
      Object.defineProperty(result, key, { value: copy(descriptor.value, depth + 1), enumerable: true });
    }
    return Object.freeze(result);
  };
  // Pin both the tool identity and a detached, deeply immutable argument
  // snapshot BEFORE awaiting the verdict. A later hook cannot substitute
  // uninspected arguments, including by retaining the original nested object.
  event.input = copy(event.input, 0);
  Object.freeze(event);
}

async function defenseclawV2Bounded(operation) {
  let timer;
  try {
    return await Promise.race([
      operation(),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error("DefenseClaw could not resolve OpenCode v2 context in time.")), 2000);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function defenseclawV2Context(ctx, event) {
  if (!event || typeof event.tool !== "string" || !event.tool || typeof event.id !== "string" || !event.id || typeof event.sessionID !== "string" || !event.sessionID) {
    throw new Error("DefenseClaw refused an incomplete OpenCode v2 tool event.");
  }
  const [session, response] = await defenseclawV2Bounded(() => Promise.all([
    ctx.session.get({ sessionID: event.sessionID }), ctx.mcp.list(),
  ]));
  const directory = session && session.location && session.location.directory;
  if (session?.id !== event.sessionID || typeof directory !== "string" || !directory || directory !== ctx.location?.directory || session.location.workspaceID !== ctx.location.workspaceID) {
    throw new Error("DefenseClaw refused an OpenCode tool outside this plugin's verified session location.");
  }
  const servers = Array.isArray(response) ? response : response && response.data;
  if (!Array.isArray(servers) || servers.length > 4096 || (response?.location && (response.location.directory !== directory || response.location.workspaceID !== ctx.location.workspaceID))) {
    throw new Error("DefenseClaw could not resolve OpenCode MCP server identity.");
  }
  const names = servers.map((server) => {
    if (!server || typeof server.name !== "string" || !server.name || server.name.length > 4096) throw new Error("DefenseClaw received an invalid OpenCode MCP server identity.");
    return { name: server.name, sanitized: defenseclawSanitizeMCPName(server.name) };
  });
  const candidates = names.filter((server) => event.tool.startsWith(server.sanitized + "_"));
  const mcpIdentity = candidates.length === 0 ? { status: "not_mcp", name: "" }
    : candidates.length === 1 ? { status: "authoritative", name: candidates[0].name }
    : { status: "ambiguous", name: "" };
  return {
    tool: event.tool, args: event.input, sessionID: event.sessionID,
    messageID: event.messageID, callID: event.id, agent: event.agent,
    cwd: directory, mcpIdentity,
  };
}

function defenseclawV2Result(event) {
  if (event.status === "error") return { opencode_v2_status: "error", error: { message: String(event.error?.message || "OpenCode tool failed") } };
  if (event.status !== "completed" || !event.result || typeof event.result !== "object" || Array.isArray(event.result)) return { opencode_v2_status: "unknown" };
  return { ...event.result, opencode_v2_status: "completed" };
}

function defenseclawV2SameLocation(ctx, location) {
  return location?.directory === ctx.location?.directory && location?.workspaceID === ctx.location?.workspaceID;
}

function defenseclawV2Remember(sessions, id, location) {
  if (sessions.size >= 4096 && !sessions.has(id)) sessions.delete(sessions.keys().next().value);
  sessions.set(id, location);
}

async function defenseclawV2Lifecycle(ctx, event, sessions, hooks) {
  const types = {
    "session.created": "session.created", "session.deleted": "session.deleted",
    "session.status": "session.status", "session.idle": "session.idle",
    "session.execution.started": "session.status",
    "session.execution.succeeded": "session.idle",
    "session.execution.failed": "session.error",
    "session.execution.interrupted": "session.idle",
  };
  const type = types[event.type];
  const data = event.data;
  if (!type || !data || typeof data.sessionID !== "string") return;
  // Durable execution events can omit location. Resolve the session rather
  // than attributing every event on the global bus to this plugin's project.
  let location = event.location || data.location || sessions.get(data.sessionID);
  if (!location) {
    const session = await defenseclawV2Bounded(() => ctx.session.get({ sessionID: data.sessionID }));
    if (session?.id !== data.sessionID) return;
    location = session.location;
  }
  if (!defenseclawV2SameLocation(ctx, location)) return;
  defenseclawV2Remember(sessions, data.sessionID, location);
  const properties = { ...data, opencode_event_type: event.type };
  if (event.type === "session.execution.started") properties.status = { type: "busy" };
  await hooks.event({ event: { ...event, type, properties } });
  if (event.type === "session.execution.failed") {
    await hooks.event({ event: { ...event, type: "session.idle", properties } });
  }
  if (type === "session.deleted") sessions.delete(data.sessionID);
}

async function defenseclawV2Setup(ctx, createHooks) {
  // V2 server plugins have no TUI toast API. Preserve notices in the host's
  // log/stderr and return blocking reasons through the rejected tool Promise.
  const client = { tui: { showToast: ({ body }) => { console.warn((body.title || "DefenseClaw") + ": " + body.message); } } };
  const hooks = await createHooks({ client, directory: ctx.location?.directory }, true);
  const registrations = [];
  const sessions = new Map();
  const controller = new AbortController();
  const cleanup = async () => {
    controller.abort();
    sessions.clear();
    await Promise.allSettled(registrations.map((registration) => registration.dispose()));
  };
  try {
    registrations.push(await ctx.tool.hook("execute.before", async (event) => {
      defenseclawPinV2Event(event);
      const input = await defenseclawV2Context(ctx, event);
      defenseclawV2Remember(sessions, input.sessionID, ctx.location);
      await hooks["tool.execute.before"](input, { args: event.input });
    }));
    registrations.push(await ctx.tool.hook("execute.after", async (event) => {
      // A telemetry failure cannot undo an already executed tool.
      try {
        const input = await defenseclawV2Context(ctx, event);
        await hooks["tool.execute.after"](input, defenseclawV2Result(event));
      } catch (_) {}
    }));
    // In v2 authority comes from the pinned event above, independently of
    // registration order. Reuse the v1 verdict/heartbeat path with that fact.
    await hooks.config({ plugin_origins: [{ spec: DC_PLUGIN_URL }], mcp: {} });
    // V2 events use data and location, while the v1 callback uses properties.
    // The subscription belongs to this plugin instance and stops on unload.
    void (async () => {
      try {
        for await (const event of ctx.event.subscribe({ signal: controller.signal })) {
          if (controller.signal.aborted) break;
          try { await defenseclawV2Lifecycle(ctx, event, sessions, hooks); } catch (_) {}
        }
      } catch (_) {}
    })();
    return cleanup;
  } catch (error) {
    await cleanup();
    throw error;
  }
}
