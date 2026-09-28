// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// openCodeStubGateway answers the plugin's load heartbeat with allow and each
// tool call with the next response.
func openCodeStubGateway(t *testing.T, responses ...string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(body, &payload)
		w.Header().Set("Content-Type", "application/json")
		if payload.Event != "tool.execute.before" {
			_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(responses) == 0 {
			_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
			return
		}
		_, _ = io.WriteString(w, responses[0])
		responses = responses[1:]
	}))
	t.Cleanup(server.Close)
	return server
}

// renderOpenCodePluginTemplate renders the current OpenCode plugin template
// the way Setup does.
func renderOpenCodePluginTemplate(t *testing.T, data templateData) string {
	t.Helper()
	return renderPluginAssetForTest(t, "opencode-plugin.js", data)
}

// renderPluginAssetForTest renders one embedded plugin template.
func renderPluginAssetForTest(t *testing.T, asset string, data templateData) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(tmpl), data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "{{") {
		t.Fatal("rendered plugin retains a template action")
	}
	return rendered
}

func openCodePluginTestData(t *testing.T, server *httptest.Server) templateData {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	token := filepath.Join(root, ".hook-opencode.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return templateData{
		APIAddr:     strings.TrimPrefix(server.URL, "http://"),
		TokenFileJS: javaScriptStringContent(token),
		FailMode:    "closed",
	}
}

// nodeForTest returns the node binary, or skips the test when there is none.
func nodeForTest(t *testing.T) string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the in-agent plugin tests")
	}
	return node
}

// runNodeHarness runs an ES module harness with node and returns its output
// lines. The test fails if node fails.
func runNodeHarness(t *testing.T, harness string, args ...string) []string {
	t.Helper()
	node := nodeForTest(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, append([]string{"--input-type=module", "-e", harness}, args...)...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("node: %v\nstdout=%s\nstderr=%s", err, out, stderr.String())
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// writeRenderedPlugin renders one embedded plugin template into a private
// temporary file named name and returns its path.
func writeRenderedPlugin(t *testing.T, asset, name string, data templateData) string {
	t.Helper()
	path := filepath.Join(testenv.PrivateTempDir(t), name)
	if err := os.WriteFile(path, []byte(renderPluginAssetForTest(t, asset, data)), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// openCodePluginHarness loads a rendered OpenCode plugin with a stub TUI
// client, applies its config hook, runs tool.execute.before `calls` times and
// prints one verdict per call, then the toasts it showed.
const openCodePluginHarness = `
import { pathToFileURL } from "node:url";
const toasts = [];
const client = { tui: { showToast: async (arg) => { toasts.push(arg && arg.body ? arg.body : arg); return true; } } };
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await loaded.DefenseClaw({ directory: "", client });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
for (let i = 0; i < Number(process.argv[2]); i++) {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" + i }, { args: { command: "echo marker" } });
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
await new Promise((resolve) => setTimeout(resolve, 50));
console.log("toasts:" + JSON.stringify(toasts));
`

func runOpenCodePluginHarness(t *testing.T, data templateData, calls int) []string {
	t.Helper()
	return runOpenCodePluginAssetHarness(t, "opencode-plugin.js", data, calls)
}

func runOpenCodePluginAssetHarness(t *testing.T, asset string, data templateData, calls int) []string {
	t.Helper()
	return runNodeHarness(t, openCodePluginHarness, writeRenderedPlugin(t, asset, "defenseclaw.mjs", data), strconv.Itoa(calls))
}

// ampPluginLoadHarness registers a rendered Amp plugin against a minimal
// plugin API and prints the handlers it installed.
const ampPluginLoadHarness = `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = typeof handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
console.log(JSON.stringify(Object.keys(handlers).sort().map((event) => event + ":" + handlers[event])));
`

// The Amp plugin must be a module Amp's runtime can load: a template that
// does not parse leaves every Amp session without DefenseClaw. Node strips
// the TypeScript types the way Bun does. Both the per-user render and the
// Windows standalone render (foreign-hook guard, install marker and listener
// proof) must register every event.
func TestAmpPluginTemplateLoadsAndRegistersEveryEvent(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	want := `["agent.end:function","agent.start:function","session.start:function","tool.call:function","tool.result:function"]`
	for name, data := range map[string]templateData{
		"per-user": {
			APIAddr:     "127.0.0.1:18970",
			TokenFileJS: javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
			FailMode:    "open",
		},
		"windows standalone": {
			APIAddr:            "127.0.0.1:18970",
			TokenFileJS:        javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
			ForeignHookGuardJS: javaScriptStringContent(filepath.Join(root, "missing", "defenseclaw-hook.exe")),
			InstallMarkerJS:    javaScriptStringContent(filepath.Join(root, "DefenseClaw-HookRuntime")),
			ListenerProofJS:    "1",
			FailMode:           "closed",
			Managed:            true,
		},
	} {
		path := writeRenderedPlugin(t, "amp-plugin.ts", strings.ReplaceAll(name, " ", "-")+".mts", data)
		if got := runNodeHarness(t, ampPluginLoadHarness, path); len(got) != 1 || got[0] != want {
			t.Fatalf("%s: registered handlers %q, want %s", name, got, want)
		}
	}
}
