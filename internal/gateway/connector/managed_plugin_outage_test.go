// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The managed Amp and OpenCode plugins Setup renders for a standalone install
// (renderPluginArtifact). On Linux and macOS the per-user-route plugin (the
// hook socket) is rendered with DC_FAIL_MODE "closed" whatever the
// administrator chose (HookOutage.ManagedOpenUnixPerUserRoute, the gateway
// outage table), and so is the Windows standalone render outside an
// authenticated Secure Client deployment
// (HookOutage.ManagedPluginOutageClosedEveryOS). The
// machine-policy OpenCode plugin is defenseclaw-hook --enterprise-managed,
// which follows the mode (hookexec
// TestStandaloneManagedOpenCodeAndCopilotFollowTheAdministratorsFailMode).
// This renders both layouts in both installed modes and runs them against a
// stopped gateway.
func TestManagedPluginOutageFollowsHookOutage(t *testing.T) {
	failModeRE := regexp.MustCompile(`const DC_FAIL_MODE(?:: string)? = "([a-z]*)"`)
	plugins := map[string]*hookOnlyConnector{"amp": NewAMPConnector().hookOnlyConnector, "opencode": NewOpenCodeConnector()}
	// blocks is whether an outage blocks name's plugin in layout and mode.
	blocks := func(name, layout, mode string) bool {
		if mode == "closed" {
			return true
		}
		outage := ConnectorHookOutage(plugins[name])
		if layout == "windows" {
			return outage.ManagedPluginOutageClosedEveryOS
		}
		return outage.ManagedOpenUnixPerUserRoute == OutageBlocks
	}
	for name, c := range plugins {
		for _, layout := range []string{"unix", "windows"} {
			for _, mode := range []string{"open", "closed"} {
				opts := managedPluginOutageOpts(t, name, layout, mode, filepath.Join(testenv.PrivateTempDir(t), "defenseclaw-hook"), "127.0.0.1:18970")
				body, err := c.renderPluginArtifact(opts)
				if err != nil {
					t.Fatalf("%s %s %s: render: %v", name, layout, mode, err)
				}
				want := "open"
				if blocks(name, layout, mode) {
					want = "closed"
				}
				if got := failModeRE.FindSubmatch(body); got == nil || string(got[1]) != want {
					t.Errorf("%s %s installed mode %q: rendered %q, want DC_FAIL_MODE %q", name, layout, mode, got, want)
				}
			}
		}
	}

	if runtime.GOOS == "windows" {
		t.Log("the plugin runs below use a shell stand-in for the hook binary; the render checks above cover Windows")
		return
	}
	nodeForTest(t)
	for name, c := range plugins {
		for _, layout := range []string{"unix", "windows"} {
			for _, mode := range []string{"open", "closed"} {
				root := testenv.PrivateTempDir(t)
				guard := filepath.Join(root, "defenseclaw-hook")
				// The foreign-hook check answers allow; any other call of the
				// hook binary (session facts) gets no answer.
				if err := os.WriteFile(guard, []byte("#!/bin/sh\ncat >/dev/null\ncase \" $* \" in\n  *\" --foreign-hook-check \"*) printf '{\"deny\":false}\\n' ;;\n  *) exit 1 ;;\nesac\n"), 0o700); err != nil {
					t.Fatal(err)
				}
				opts := managedPluginOutageOpts(t, name, layout, mode, guard, stoppedGatewayAddr(t))
				body, err := c.renderPluginArtifact(opts)
				if err != nil {
					t.Fatal(err)
				}
				want := "allow"
				if blocks(name, layout, mode) {
					want = "block"
				}
				for _, got := range runManagedPluginOutage(t, name, root, body) {
					if !strings.HasPrefix(got, want) {
						t.Errorf("%s %s installed mode %q, gateway stopped: %q, want %s", name, layout, mode, got, want)
					}
				}
			}
		}
	}
}

// managedPluginOutageOpts are the standalone Setup options of one layout:
// "unix" carries the hook socket and the administrator-owned hook binary
// (enterprise_hooks_standalone_unix.go), "windows" only the foreign-hook
// guard and the TCP gateway (install_windows.go).
func managedPluginOutageOpts(t *testing.T, name, layout, mode, guard, apiAddr string) SetupOpts {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	opts := SetupOpts{
		DataDir:                filepath.Join(root, "defenseclaw"),
		APIAddr:                apiAddr,
		ManagedEnterprise:      true,
		HookFailMode:           mode,
		ForeignHookGuardBinary: guard,
	}
	if layout == "unix" {
		opts.ManagedHookSocket = filepath.Join(root, "hook.sock") // never created: the service is stopped
		opts.ManagedHookBinary = guard
		opts.ManagedServiceUID = os.Getuid()
	}
	token, err := HookAPITokenFilePath(opts.DataDir, name)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return opts
}

// stoppedGatewayAddr is a loopback address nothing listens on.
func stoppedGatewayAddr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return addr
}

// runManagedPluginOutage loads the rendered plugin and sends it one call per
// blockable event, printing "allow" or "block:<reason>" for each.
func runManagedPluginOutage(t *testing.T, name, root string, body []byte) []string {
	t.Helper()
	file := filepath.Join(root, "defenseclaw.mjs")
	harness := managedOpenCodeOutageHarness
	if name == "amp" {
		file, harness = filepath.Join(root, "defenseclaw.mts"), managedAmpOutageHarness
	}
	if err := os.WriteFile(file, body, 0o600); err != nil {
		t.Fatal(err)
	}
	lines := runNodeHarness(t, harness, file)
	if want := map[string]int{"amp": 2, "opencode": 1}[name]; len(lines) != want {
		t.Fatalf("%s: harness printed %q, want %d verdicts", name, lines, want)
	}
	return lines
}

const managedOpenCodeOutageHarness = `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await fixtureBridge(loaded, { directory: "", client: {} });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C1" }, { args: { command: "echo marker" } });
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

const managedAmpOutageHarness = `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
// Amp runs plugins on Bun; the plugin reads its credential with Bun.file.
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
const ctx = { thread: { id: "T", agent: async () => ({ definition: { kind: "builtin-agent", mode: "medium" } }) }, ui: { notify: async () => {} } };
const call = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" } }, ctx);
console.log(call.action === "allow" ? "allow" : "block:" + call.message);
const result = await handlers["tool.result"]({ thread: { id: "T" }, toolUseID: "U1", tool: "Bash", input: { command: "echo marker" }, output: "marker", status: "done" }, ctx);
console.log(result ? "block:" + result.error : "allow");
`
