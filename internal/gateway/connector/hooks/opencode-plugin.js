// defenseclaw-managed-plugin v6
// DefenseClaw opencode bridge plugin — DO NOT EDIT.
//
// opencode auto-loads JS/TS plugins from ~/.config/opencode/plugins/ at
// startup (https://opencode.ai/docs/plugins/). This dependency-free
// bridge forwards each tool call to the local DefenseClaw gateway and
// aborts the tool — by throwing, exactly like opencode's own
// .env-protection example — when the gateway returns a block decision.
//
// The gateway address, bearer token, and fail mode are substituted in at
// setup time. The file is written 0o600 (owner-only) because it carries
// the gateway token; it is never executable. DefenseClaw's Teardown
// removes this file (managed-file backup heal).
//
// Wire contract: POST {hook_event_name, tool_name, tool_input, cwd} to
// /api/v1/opencode/hook; the response carries hook_output={decision,
// reason}; decision "deny"/"block" aborts the tool.

// DC_-prefixed constants are values baked in at setup time, not env-var
// reads — the envvars registry gate scans for DEFENSECLAW_* tokens.
const DC_API_ADDR = "{{.APIAddr}}";
const DC_API_TOKEN = "{{.APIToken}}";
const DC_FAIL_MODE = "{{.FailMode}}"; // "open" or "closed"
const DC_TIMEOUT_MS = 10000;

async function defenseclawPost(event, toolName, toolInput, cwd) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), DC_TIMEOUT_MS);
  const headers = { "Content-Type": "application/json", "X-DefenseClaw-Client": "opencode-plugin/1.0" };
  if (DC_API_TOKEN) headers["Authorization"] = "Bearer " + DC_API_TOKEN;
  try {
    const res = await fetch("http://" + DC_API_ADDR + "/api/v1/opencode/hook", {
      method: "POST",
      headers,
      body: JSON.stringify({
        hook_event_name: event,
        tool_name: toolName || "",
        tool_input: toolInput || {},
        cwd: cwd || "",
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      // Gateway answered with a bad status (auth/5xx). Honor fail mode.
      if (DC_FAIL_MODE === "closed") {
        return { reason: "DefenseClaw hook failed closed (HTTP " + res.status + ")" };
      }
      return null;
    }
    const data = await res.json();
    const out = data && data.hook_output;
    if (out && (out.decision === "deny" || out.decision === "block")) {
      return { reason: out.reason || "DefenseClaw blocked this tool call." };
    }
    return null;
  } catch (err) {
    // Transport failure (gateway unreachable / timeout). Honor fail mode:
    // closed → block, open → allow.
    if (DC_FAIL_MODE === "closed") {
      return { reason: "DefenseClaw hook failed closed (" + (err && err.message ? err.message : String(err)) + ")" };
    }
    return null;
  } finally {
    clearTimeout(timer);
  }
}

export const DefenseClaw = async ({ directory, worktree }) => {
  const cwd = directory || worktree || "";
  return {
    // tool.execute.before is opencode's pre-tool hook. Throwing here
    // aborts the tool (same mechanism as the .env-protection example).
    // The decision is resolved BEFORE the throw so a fail-open transport
    // error never turns into an accidental block.
    "tool.execute.before": async (input, output) => {
      const verdict = await defenseclawPost(
        "tool.execute.before",
        input && input.tool,
        output && output.args,
        cwd,
      );
      if (verdict) throw new Error(verdict.reason);
    },
    // tool.execute.after is observe-only telemetry: fire-and-forget so it
    // never adds latency to (or blocks) the tool result.
    "tool.execute.after": async (input, output) => {
      defenseclawPost("tool.execute.after", input && input.tool, output && output.args, cwd).catch(() => {});
    },
  };
};
