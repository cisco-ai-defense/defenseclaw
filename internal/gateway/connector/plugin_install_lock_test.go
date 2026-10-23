// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Per-user plugins run inside their agents rather than through a shell or
// hookexec. Their open render must still refuse a call while the installer
// owns the account's data directory (GAP-0797/0798).
func TestPerUserInstallLockClosesOpenCodePluginFailures(t *testing.T) {
	for _, failure := range []string{"HTTP 401", "invalid verdict", "gateway stopped"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-opencode.token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if failure == "HTTP 401" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"action":"unknown"}`))
			}))
			t.Cleanup(server.Close)
			if failure == "gateway stopped" {
				server.Close()
			}
			data := templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
				TokenFileJS: javaScriptStringContent(token), FailMode: "open"}
			lines := runOpenCodePluginHarness(t, data, 1)
			if len(lines) == 0 || !strings.HasPrefix(lines[0], "block:") {
				t.Fatalf("install lock allowed OpenCode %s: %q", failure, lines)
			}
		})
	}
}

const ampInstallLockHarness = `
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
const event = { thread: { id: "s-1" }, toolUseID: "c-1", tool: "shell", input: { command: "true" } };
const ctx = { thread: { agent: async () => ({ name: "amp" }) }, ui: { confirm: async () => false } };
console.log(JSON.stringify(await handlers["tool.call"](event, ctx)));
`

func TestPerUserInstallLockClosesAmpPluginFailures(t *testing.T) {
	for _, failure := range []string{"HTTP 401", "invalid verdict", "gateway stopped"} {
		t.Run(failure, func(t *testing.T) {
			dataDir := testenv.PrivateTempDir(t)
			token := filepath.Join(dataDir, "hooks", ".hook-amp.token")
			if err := os.MkdirAll(filepath.Dir(token), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dataDir, ".install.lock"), 0o700); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if failure == "HTTP 401" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				_, _ = w.Write([]byte(`{"action":"unknown"}`))
			}))
			t.Cleanup(server.Close)
			if failure == "gateway stopped" {
				server.Close()
			}
			data := templateData{APIAddr: strings.TrimPrefix(server.URL, "http://"),
				TokenFileJS: javaScriptStringContent(token), FailMode: "open"}
			path := writeRenderedPlugin(t, "amp-plugin.ts", "defenseclaw.mts", data)
			lines := runNodeHarness(t, ampInstallLockHarness, path)
			if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], `"action":"reject-and-continue"`) {
				t.Fatalf("install lock allowed Amp %s: %q", failure, lines)
			}
		})
	}
}
