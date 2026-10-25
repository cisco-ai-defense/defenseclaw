// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// flakyForeignGuard is a stand-in for the administrator-owned hook binary
// whose foreign-hook check cannot run the first time (for example while an
// upgrade replaces it) and answers allow afterwards. The plugins also run
// this binary for "hook session-facts", synchronously and at a time that
// depends on scheduling; that call gets no answer and leaves the state
// alone, so only the load-time check can take the one failure.
const flakyForeignGuard = `#!/bin/sh
cat >/dev/null
case " $* " in
  *" --foreign-hook-check "*) ;;
  *) exit 1 ;;
esac
if [ ! -f "$0.ran" ]; then
  : > "$0.ran"
  echo "hook binary unavailable" >&2
  exit 1
fi
printf '{"deny":false}\n'
`

func writeFlakyForeignGuard(t *testing.T, root string) string {
	t.Helper()
	guard := filepath.Join(root, "defenseclaw-hook")
	if err := os.WriteFile(guard, []byte(flakyForeignGuard), 0o700); err != nil {
		t.Fatal(err)
	}
	return guard
}

// A failed startup check is transient. Its first call stays closed, then a
// later call must retry the check without restarting the agent. A confirmed
// foreign-plugin denial remains pinned for the life of that process.
func TestPluginStartupGuardFailureSaysToRestart(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	data := openCodePluginTestData(t, openCodeStubGateway(t))
	data.ForeignHookGuardJS = javaScriptStringContent(writeFlakyForeignGuard(t, root))
	data.Managed = true
	lines := runNodeHarness(t, `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const call = async (plugin, id) => {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: id }, { args: { command: "echo marker" } });
    return "allow";
  } catch (error) {
    return "block:" + String(error && error.message || error);
  }
};
const first = await loaded.DefenseClaw({ directory: "", client: {} });
await first.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(first, "C1"));
console.log(await call(first, "C2"));
const restarted = await loaded.DefenseClaw({ directory: "", client: {} });
await restarted.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(restarted, "C3"));
`, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", data))
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "block:") || lines[1] != "allow" || lines[2] != "allow" {
		t.Fatalf("OpenCode verdicts = %q, want first-call block then recovery in the same process", lines)
	}

	ampRoot := testenv.PrivateTempDir(t)
	lines = runNodeHarness(t, `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
for (const id of ["U1", "U2"]) {
  const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: id, tool: "Bash", input: {} }, {});
  console.log(result.action + ":" + (result.message || ""));
}
`, writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
		APIAddr:            "127.0.0.1:18970",
		TokenFileJS:        javaScriptStringContent(filepath.Join(ampRoot, ".hook-amp.token")),
		ForeignHookGuardJS: javaScriptStringContent(writeFlakyForeignGuard(t, ampRoot)),
		FailMode:           "closed",
		Managed:            true,
	}))
	if len(lines) != 2 {
		t.Fatalf("Amp verdicts = %q", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "reject-and-continue:") || !strings.Contains(line, "Restart the agent") {
			t.Fatalf("Amp: a failed load-time check must keep blocking and say to restart: %q", line)
		}
	}
	if _, err := os.Stat(filepath.Join(ampRoot, "defenseclaw-hook.ran")); err != nil {
		t.Fatalf("the guard did not run at load: %v", err)
	}
}

// Amp can run a project plugin's tool.call handler before the managed one.
// A guarded agent.start must cancel the turn before any tool.call handler
// runs, while a plugin the administrator approved lets the turn start.
func TestAmpStandaloneCancelsAProjectPluginBeforeToolCall(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	allow := filepath.Join(root, "allow")
	guard := filepath.Join(root, "defenseclaw-hook")
	script := "#!/bin/sh\ncat >/dev/null\nif [ -f '" + allow + "' ]; then\n  printf '%s\\n' '{\"deny\":false}'\nelse\n" +
		"  printf '%s\\n' '{\"deny\":true,\"reason\":\"enterprise_foreign_hook_blocked: project file .amp/plugins/rewrite.ts\"}'\nfi\n"
	if err := os.WriteFile(guard, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	plugin := writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
		APIAddr:            "127.0.0.1:18970",
		TokenFileJS:        javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
		HookSocketJS:       javaScriptStringContent(filepath.Join(root, "hook.sock")),
		ForeignHookGuardJS: javaScriptStringContent(guard),
		FailMode:           "closed",
		Managed:            true,
	})
	const harness = `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
let cancelled = false;
let notice = "";
loaded.default({
  system: { workspaceRoot: pathToFileURL(process.cwd()).href, executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => new URL(uri).pathname, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const ctx = {
  thread: {
    id: "T",
    agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }),
    cancel: async () => { cancelled = true; },
  },
  ui: { notify: async (message) => { notice = message; } },
};
const result = await handlers["agent.start"]({ thread: { id: "T" }, id: "M", message: "use a tool" }, ctx);
console.log(cancelled ? "cancelled:" + notice + "|" + JSON.stringify(result) : "started");
`
	// The notice fades, so the text also stays in the thread, and it leaves
	// the guard's reason code to the audit.
	if got := strings.Join(runNodeHarness(t, harness, plugin), "\n"); !strings.HasPrefix(got, "cancelled:DefenseClaw") ||
		strings.Contains(got, "enterprise_foreign_hook_blocked") || !strings.HasSuffix(got, `rewrite.ts","display":true}}`) {
		t.Fatalf("Amp must cancel the turn at agent.start when the guard denies, and say so in the thread: %q", got)
	}
	if err := os.WriteFile(allow, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(runNodeHarness(t, harness, plugin), "\n"); got != "started" {
		t.Fatalf("Amp must let the turn start when the guard allows: %q", got)
	}
}

// outageDenyOnceGuard is a stand-in for the administrator-owned hook binary
// whose foreign-hook check answers the guard's outage denial the first time
// (the gateway could not answer for the agent session when the agent
// started) and allows afterwards (the gateway is back).
const outageDenyOnceGuard = `#!/bin/sh
cat >/dev/null
case " $* " in
  *" --foreign-hook-check "*) ;;
  *) exit 1 ;;
esac
if [ ! -f "$0.ran" ]; then
  : > "$0.ran"
  printf '%s\n' '{"deny":true,"reason":"DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running (enterprise_gateway_not_running)."}'
  exit 0
fi
printf '{"deny":false}\n'
`

// G-hooks-upg loop round 2: the gateway outage table says which plugins keep
// a guard block they got at load for the life of the agent process
// (HookOutage.GuardCheckedAtLoad). An Amp or OpenCode agent that starts
// while the gateway cannot answer for its session keeps blocking its tool
// calls after the gateway is back, with a gateway that allows them; a
// restarted agent checks again. Only those plugins run the check at load.
func TestPluginGuardOutageDenialAtLoadHoldsForTheProcess(t *testing.T) {
	registry := NewDefaultRegistry()
	checking := map[string]bool{}
	entries, err := hookFS.ReadDir("hooks")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.Contains(name, "-plugin") || strings.Contains(name, "secure-client") {
			continue // Secure Client has no standalone summary: its guard is a no-op
		}
		body, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "--foreign-hook-check") {
			checking[strings.SplitN(name, "-plugin", 2)[0]] = true
		}
	}
	for _, name := range registry.Names() {
		conn, _ := registry.Get(name)
		if got := ConnectorHookOutage(conn).GuardCheckedAtLoad; got != checking[name] {
			t.Errorf("%s: GuardCheckedAtLoad = %v, but its plugin runs the foreign-hook check: %v", name, got, checking[name])
		}
	}

	gateway := openCodeStubGateway(t)
	root := testenv.PrivateTempDir(t)
	data := openCodePluginTestData(t, gateway)
	guard := filepath.Join(root, "defenseclaw-hook")
	if err := os.WriteFile(guard, []byte(outageDenyOnceGuard), 0o700); err != nil {
		t.Fatal(err)
	}
	data.ForeignHookGuardJS = javaScriptStringContent(guard)
	data.Managed = true
	lines := runNodeHarness(t, `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const call = async (plugin, id) => {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: id }, { args: { command: "echo marker" } });
    return "allow";
  } catch (error) {
    return "block:" + String(error && error.message || error);
  }
};
const first = await loaded.DefenseClaw({ directory: "", client: {} });
await first.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(first, "C1"));
console.log(await call(first, "C2"));
const restarted = await loaded.DefenseClaw({ directory: "", client: {} });
await restarted.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(restarted, "C3"));
`, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", data))
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "block:") ||
		!strings.Contains(lines[0], "enterprise_gateway_not_running") || lines[1] != "allow" || lines[2] != "allow" {
		t.Fatalf("OpenCode verdicts = %q, want outage block then recovery in the same process", lines)
	}

	ampRoot := testenv.PrivateTempDir(t)
	ampToken := filepath.Join(ampRoot, ".hook-amp.token")
	if err := os.WriteFile(ampToken, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ampGuard := filepath.Join(ampRoot, "defenseclaw-hook")
	if err := os.WriteFile(ampGuard, []byte(outageDenyOnceGuard), 0o700); err != nil {
		t.Fatal(err)
	}
	lines = runNodeHarness(t, `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: async () => readFileSync(path, "utf8") }) }) };
const loaded = await import(pathToFileURL(process.argv[1]).href);
const start = () => {
  const handlers = {};
  loaded.default({
    system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
    helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
    on: (event, handler) => { handlers[event] = handler; },
    activeThread: { current: null },
    ui: { notify: async () => {} },
  });
  return handlers;
};
const call = async (handlers, id) => {
  const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: id, tool: "Bash", input: {} }, {});
  return result.action + ":" + (result.message || "");
};
const first = start();
console.log(await call(first, "U1"));
console.log(await call(first, "U2"));
const restarted = start();
console.log(await call(restarted, "U3"));
`, writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", templateData{
		APIAddr:            strings.TrimPrefix(gateway.URL, "http://"),
		TokenFileJS:        javaScriptStringContent(ampToken),
		ForeignHookGuardJS: javaScriptStringContent(ampGuard),
		FailMode:           "closed",
		Managed:            true,
	}))
	if len(lines) != 3 || !strings.HasPrefix(lines[2], "allow:") {
		t.Fatalf("Amp verdicts = %q, want two blocks, then an allow after the restart", lines)
	}
	for _, line := range lines[:2] {
		if !strings.HasPrefix(line, "reject-and-continue:") || !strings.Contains(line, "enterprise_gateway_not_running") {
			t.Fatalf("Amp: the outage denial at load must hold for the process: %q", line)
		}
	}
}
