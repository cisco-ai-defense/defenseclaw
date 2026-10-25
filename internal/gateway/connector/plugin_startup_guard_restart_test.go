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
func TestPluginStartupGuardRetriesWithoutRestart(t *testing.T) {
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
	ampToken := filepath.Join(ampRoot, ".hook-amp.token")
	if err := os.WriteFile(ampToken, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lines = runNodeHarness(t, `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: async () => readFileSync(path, "utf8") }) }) };
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
		APIAddr:            strings.TrimPrefix(openCodeStubGateway(t).URL, "http://"),
		TokenFileJS:        javaScriptStringContent(ampToken),
		ForeignHookGuardJS: javaScriptStringContent(writeFlakyForeignGuard(t, ampRoot)),
		FailMode:           "closed",
		Managed:            true,
	}))
	if len(lines) != 2 {
		t.Fatalf("Amp verdicts = %q", lines)
	}
	if !strings.HasPrefix(lines[0], "reject-and-continue:") || !strings.HasPrefix(lines[1], "allow:") {
		t.Fatalf("Amp: transient startup failure must recover on the next call: %q", lines)
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
  printf '%s\n' '{"deny":true,"reason":"DefenseClaw blocked this tool call: the DefenseClaw gateway service is not running (enterprise_gateway_not_running).","retryable":true}'
  exit 0
fi
printf '{"deny":false}\n'
`

const confirmedDenyOnceGuard = `#!/bin/sh
cat >/dev/null
case " $* " in
  *" --foreign-hook-check "*) ;;
  *) exit 1 ;;
esac
if [ ! -f "$0.ran" ]; then
  : > "$0.ran"
  printf '%s\n' '{"deny":true,"reason":"enterprise_foreign_hook_blocked: project file .amp/plugins/foreign.ts"}'
  exit 0
fi
printf '{"deny":false}\n'
`

// A startup check that denied only because the gateway was down (the
// guard's structured retryable answer) retries on the next call in the same
// agent process. A confirmed foreign-plugin denial
// is covered separately and stays pinned.
func TestPluginGuardOutageDenialRetriesInTheProcess(t *testing.T) {
	testPluginGuardDenialAtLoad(t, outageDenyOnceGuard, "enterprise_gateway_not_running", true)
}

func TestPluginConfirmedForeignDenialAtLoadStaysPinned(t *testing.T) {
	testPluginGuardDenialAtLoad(t, confirmedDenyOnceGuard, "project file", false)
}

func testPluginGuardDenialAtLoad(t *testing.T, guardScript, reason string, retryable bool) {
	t.Helper()
	gateway := openCodeStubGateway(t)
	root := testenv.PrivateTempDir(t)
	data := openCodePluginTestData(t, gateway)
	guard := filepath.Join(root, "defenseclaw-hook")
	if err := os.WriteFile(guard, []byte(guardScript), 0o700); err != nil {
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
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "block:") || !strings.Contains(lines[0], reason) ||
		(retryable && lines[1] != "allow") || (!retryable && !strings.HasPrefix(lines[1], "block:")) || lines[2] != "allow" {
		t.Fatalf("OpenCode verdicts = %q, retryable=%v", lines, retryable)
	}

	ampRoot := testenv.PrivateTempDir(t)
	ampToken := filepath.Join(ampRoot, ".hook-amp.token")
	if err := os.WriteFile(ampToken, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ampGuard := filepath.Join(ampRoot, "defenseclaw-hook")
	if err := os.WriteFile(ampGuard, []byte(guardScript), 0o700); err != nil {
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
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "reject-and-continue:") ||
		!strings.Contains(lines[0], reason) ||
		(retryable && !strings.HasPrefix(lines[1], "allow:")) ||
		(!retryable && !strings.HasPrefix(lines[1], "reject-and-continue:")) || !strings.HasPrefix(lines[2], "allow:") {
		t.Fatalf("Amp verdicts = %q, retryable=%v", lines, retryable)
	}
}

// onceForeignGuard answers its first foreign-hook check with first and
// allows afterwards: a foreign plugin that was found at load and then
// deleted its file (and its session record).
func onceForeignGuard(t *testing.T, root, first string) string {
	t.Helper()
	guard := filepath.Join(root, "defenseclaw-hook")
	script := "#!/bin/sh\ncat >/dev/null\ncase \" $* \" in\n  *\" --foreign-hook-check \"*) ;;\n  *) exit 1 ;;\nesac\n" +
		"if [ ! -f \"$0.ran\" ]; then\n  : > \"$0.ran\"\n  printf '%s\\n' '" + first + "'\n  exit 0\nfi\nprintf '{\"deny\":false}\\n'\n"
	if err := os.WriteFile(guard, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return guard
}

// Loop round 2 review of 06bb83dd (GAP-1180): the plugins retried their
// load-time check when the denial's reason text contained an availability
// phrase, so an unapproved plugin named enterprise_gateway_not_running.ts
// (or any reason quoting "could not check this agent session's hook record")
// cleared the pinned denial and, once it deleted its file, its calls were
// allowed while it stayed loaded. Only the guard's structured retryable
// answer (or a check that could not run) retries now; a confirmed denial
// holds for the process whatever its text.
func TestPluginStartupGuardPinsConfirmedDenialWhateverItsReason(t *testing.T) {
	denials := map[string]string{
		"plugin named like a gateway outage": `{"deny":true,"reason":"enterprise_foreign_hook_blocked: project file .amp/plugins/enterprise_gateway_not_running.ts"}`,
		"plugin named like a managed outage": `{"deny":true,"reason":"enterprise_foreign_hook_blocked: enterprise_managed_gateway_not_running.js"}`,
		"reason quoting the session phrase":  `{"deny":true,"reason":"enterprise_foreign_hook_blocked: could not check this agent session's hook record.ts"}`,
		"reason quoting the check failure":   `{"deny":true,"reason":"DefenseClaw could not check for unapproved plugins.js"}`,
	}
	const retryable = `{"deny":true,"reason":"enterprise_foreign_hook_blocked: DefenseClaw could not check this agent session's hook record with its gateway","retryable":true}`
	cases := map[string]struct {
		first   string
		recover bool
	}{"structured retryable answer": {retryable, true}}
	for name, denial := range denials {
		cases[name] = struct {
			first   string
			recover bool
		}{denial, false}
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			root := testenv.PrivateTempDir(t)
			data := openCodePluginTestData(t, openCodeStubGateway(t))
			data.ForeignHookGuardJS = javaScriptStringContent(onceForeignGuard(t, root, strings.ReplaceAll(tc.first, "'", `'"'"'`)))
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
const plugin = await loaded.DefenseClaw({ directory: "", client: {} });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(plugin, "C1"));
console.log(await call(plugin, "C2"));
`, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", data))
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "block:") || (lines[1] == "allow") != tc.recover {
				t.Fatalf("OpenCode verdicts = %q, want first-call block, then recover=%v", lines, tc.recover)
			}

			ampRoot := testenv.PrivateTempDir(t)
			ampToken := filepath.Join(ampRoot, ".hook-amp.token")
			if err := os.WriteFile(ampToken, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			lines = runNodeHarness(t, `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: async () => readFileSync(path, "utf8") }) }) };
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
				APIAddr:            strings.TrimPrefix(openCodeStubGateway(t).URL, "http://"),
				TokenFileJS:        javaScriptStringContent(ampToken),
				ForeignHookGuardJS: javaScriptStringContent(onceForeignGuard(t, ampRoot, strings.ReplaceAll(tc.first, "'", `'"'"'`))),
				FailMode:           "closed",
				Managed:            true,
			}))
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "reject-and-continue:") ||
				strings.HasPrefix(lines[1], "allow:") != tc.recover {
				t.Fatalf("Amp verdicts = %q, want first-call block, then recover=%v", lines, tc.recover)
			}
		})
	}
}
