// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// ampInstallInFlightHarness runs one Amp tool.call for a command that names
// the marker the test gateway reacts to.
const ampInstallInFlightHarness = `
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
globalThis.Bun = { file: (path) => ({ slice: () => ({ text: () => readFile(path, "utf8") }) }) };
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
const amp = {
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null }, ui: { notify: async () => {} },
};
loaded.default(amp);
const event = { thread: { id: "s-1" }, toolUseID: "c-1", tool: "shell", input: { command: "echo in-flight-marker" } };
const ctx = { thread: { agent: async () => ({ name: "amp" }) }, ui: { confirm: async () => false } };
console.log(JSON.stringify(await handlers["tool.call"](event, ctx)));
`

// GAP-0893: the per-user OpenCode plugin in fail mode open read
// .install.lock once, before its gateway request. An install or upgrade
// that began while the request was out (the installer then stops the
// gateway) left that early read open, and the failure allowed the tool.
// Both in-agent plugins now read the install state when a failure answers:
// a dropped connection, an outage or error status and no verdict. Without
// an install the account's open choice still applies.
func TestPerUserPluginAnswersClosedWhenAnInstallStartsDuringTheCall(t *testing.T) {
	failures := []struct {
		name   string
		answer func(w http.ResponseWriter)
	}{
		{"gateway drops the connection", func(w http.ResponseWriter) {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
		}},
		{"gateway answers HTTP 503", func(w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) }},
		{"gateway answers HTTP 401", func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) }},
		{"gateway answers no verdict", func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"action":"maybe"}`)) }},
	}
	for _, plugin := range []string{"opencode", "amp"} {
		for _, failure := range failures {
			for _, install := range []bool{false, true} {
				name := plugin + "/" + failure.name + "/no install"
				if install {
					name = plugin + "/" + failure.name + "/install starts during the call"
				}
				t.Run(name, func(t *testing.T) {
					dataDir := testenv.PrivateTempDir(t)
					token := filepath.Join(dataDir, "hooks", ".hook-"+plugin+".token")
					if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
						t.Fatal(err)
					}
					var once sync.Once
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						body, _ := io.ReadAll(r.Body)
						if !strings.Contains(string(body), "marker") {
							// Load and lifecycle reports are not the tool call.
							_, _ = w.Write([]byte(`{"action":"allow"}`))
							return
						}
						if install {
							once.Do(func() {
								if err := os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700); err != nil {
									t.Error(err)
								}
							})
						}
						failure.answer(w)
					}))
					t.Cleanup(server.Close)
					data := templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
						TokenFileJS: javaScriptStringContent(token), FailMode: "open"}
					var blocked bool
					var lines []string
					if plugin == "opencode" {
						lines = runOpenCodePluginHarness(t, data, 1)
						blocked = len(lines) > 0 && strings.HasPrefix(lines[0], "block:")
					} else {
						lines = runNodeHarness(t, ampInstallInFlightHarness, writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", data))
						blocked = len(lines) > 0 && strings.Contains(lines[len(lines)-1], `"action":"reject-and-continue"`)
					}
					if blocked != install {
						t.Fatalf("blocks=%v, want %v: %q", blocked, install, lines)
					}
				})
			}
		}
	}
}
