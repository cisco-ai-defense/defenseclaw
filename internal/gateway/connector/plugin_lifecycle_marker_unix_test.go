// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The lifecycle marker is taken before a managed gateway stops. A plugin
// invocation during that window must answer closed without waiting for the
// 10-second foreign-hook check or gateway request.
func TestManagedPluginsAnswerClosedPromptlyDuringLifecycle(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	marker := filepath.Join(root, "lifecycle.active")
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DC_TEST_LIFECYCLE_MARKER", marker)
	guard := filepath.Join(root, "defenseclaw-hook")
	guardCalls := filepath.Join(root, "guard-calls")
	guardScript := "#!/bin/sh\ncase \" $* \" in\n  *\" --foreign-hook-check \"*) ;;\n  *) exit 1 ;;\nesac\nprintf 'called\\n' >> '" + guardCalls + "'\ncat >/dev/null\nprintf '{\"deny\":false}\\n'\n"
	if err := os.WriteFile(guard, []byte(guardScript), 0o700); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"allow","mode":"action"}`))
	}))
	defer server.Close()

	openCode := openCodePluginTestData(t, server)
	openCode.Managed = true
	openCode.ForeignHookGuardJS = javaScriptStringContent(guard)
	openCode.LifecycleMarkerJS = javaScriptStringContent(marker)
	lines := runNodeHarness(t, `
import { pathToFileURL } from "node:url";
import { unlink } from "node:fs/promises";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await fixtureBridge(loaded, { directory: "", client: {} });
await plugin.config({ plugin_origins: [{ spec: pathToFileURL(process.argv[1]).href }], mcp: {} });
const started = Date.now();
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" }, { args: { command: "echo benign" } });
  console.log("ALLOW:" + (Date.now() - started));
} catch (error) {
  console.log("BLOCK:" + (Date.now() - started) + ":" + String(error.message || error));
}
await unlink(process.env.DC_TEST_LIFECYCLE_MARKER);
try {
  await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C2" }, { args: { command: "echo benign" } });
  console.log("ALLOW-AFTER");
} catch (error) {
  console.log("BLOCK-AFTER:" + String(error.message || error));
}
`, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", openCode))
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "BLOCK:") || lines[1] != "ALLOW-AFTER" ||
		!strings.Contains(lines[0], "installed or upgraded") {
		t.Fatalf("OpenCode lifecycle answer = %q", lines)
	}
	fields := strings.SplitN(lines[0], ":", 3)
	if millis, err := strconv.Atoi(fields[1]); err != nil || millis > 1000 {
		t.Fatalf("OpenCode lifecycle answer was late: %q", lines[0])
	}
	if requests.Load() != 1 {
		t.Fatalf("OpenCode gateway requests before and after lifecycle = %d, want one after", requests.Load())
	}
	// The load-time guard and the recovered call run once each; the closed
	// invocation must not launch a third check while the marker is held.
	guardBefore, _ := os.ReadFile(guardCalls)
	if strings.Count(string(guardBefore), "called") != 2 {
		t.Fatalf("OpenCode guard checks across lifecycle = %q", guardBefore)
	}
	if err := os.WriteFile(marker, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	ampToken := filepath.Join(root, ".hook-amp.token")
	if err := os.WriteFile(ampToken, []byte(strings.Repeat("a", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	amp := templateData{
		APIAddr:            strings.TrimPrefix(server.URL, "http://"),
		TokenFileJS:        javaScriptStringContent(ampToken),
		ForeignHookGuardJS: javaScriptStringContent(guard),
		LifecycleMarkerJS:  javaScriptStringContent(marker),
		FailMode:           "closed",
		Managed:            true,
	}
	lines = runNodeHarness(t, `
import { pathToFileURL } from "node:url";
import { readFile, unlink } from "node:fs/promises";
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: () => readFile(path, "utf8") }) }) };
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const started = Date.now();
const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "C", tool: "Bash", input: {} }, {});
console.log(result.action + ":" + (Date.now() - started) + ":" + (result.message || ""));
await unlink(process.env.DC_TEST_LIFECYCLE_MARKER);
const recovered = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: "C2", tool: "Bash", input: {} }, {});
console.log("AFTER:" + recovered.action + ":" + (recovered.message || ""));
`, writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", amp))
	if len(lines) != 2 || !strings.HasPrefix(lines[0], "reject-and-continue:") || lines[1] != "AFTER:allow:" ||
		!strings.Contains(lines[0], "installed or upgraded") {
		t.Fatalf("Amp lifecycle answer = %q", lines)
	}
	fields = strings.SplitN(lines[0], ":", 3)
	if millis, err := strconv.Atoi(fields[1]); err != nil || millis > 1000 {
		t.Fatalf("Amp lifecycle answer was late: %q", lines[0])
	}
	if requests.Load() != 2 {
		t.Fatalf("Amp gateway requests before and after lifecycle = %d, want two total after", requests.Load())
	}
}

func TestManagedPluginLifecycleMarkerIsTheNativeMarker(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		t.Fatal(err)
	}
	got := managedPluginLifecycleMarker(SetupOpts{ManagedEnterprise: true, ManagedHookSocket: layout.HookSocketPath})
	if got != layout.LifecycleMarkerPath {
		t.Fatalf("managed plugin marker = %q, want %q", got, layout.LifecycleMarkerPath)
	}
	if got := managedPluginLifecycleMarker(SetupOpts{ManagedHookSocket: layout.HookSocketPath}); got != "" {
		t.Fatalf("per-user plugin gained a managed marker: %q", got)
	}
}
