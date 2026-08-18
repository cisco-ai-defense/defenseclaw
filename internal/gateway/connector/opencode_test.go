// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestManagedPluginTokenPathJavaScriptEscapingIsCrossPlatform(t *testing.T) {
	for _, path := range []string{
		`C:\Users\Alice O'Brien\DefenseClaw\hooks\.hook-opencode.token`,
		`/Users/alice/${workspace}/Defense"Claw/hooks/.hook-amp.token`,
	} {
		escaped := javaScriptStringContent(path)
		var decoded string
		if err := json.Unmarshal([]byte(`"`+escaped+`"`), &decoded); err != nil {
			t.Fatalf("escaped JavaScript path %q is not a valid JSON string: %v", escaped, err)
		}
		if decoded != path {
			t.Fatalf("escaped path round trip = %q, want %q", decoded, path)
		}
	}
}

// TestOpenCodeSetup_WritesBridgePlugin pins the plugin-artifact install
// path: Setup renders the embedded bridge template (gateway addr, stable
// scoped-token path, and fail mode substituted) and writes it owner-only into opencode's
// auto-load plugin directory — with no template placeholders left behind
// and no executable bit. Teardown removes the managed file.
func TestOpenCodeSetup_WritesBridgePlugin(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, ".config", "opencode", "plugins", "defenseclaw.js")
	prev := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prev })

	conn := NewOpenCodeConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-opencode-123",
		HookFailMode: "closed",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent after setup: %v", err)
	}
	if !present {
		t.Fatal("OwnedHooksPresent after setup = false, want true")
	}

	raw, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read plugin after setup: %v", err)
	}
	body := string(raw)
	tokenPath, err := HookAPITokenFilePath(opts.DataDir, "opencode")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	tokenPath, err = filepath.Abs(tokenPath)
	if err != nil {
		t.Fatalf("absolute hook token path: %v", err)
	}
	for _, want := range []string{
		"127.0.0.1:18970",                  // APIAddr substituted
		javaScriptStringContent(tokenPath), // stable token path safely embedded
		`DC_FAIL_MODE = "closed"`,          // fail mode honored (SupportsFailClosed=true)
		"/api/v1/opencode/hook",            // gateway endpoint
		`const DC_MAX_TOKEN_FILE_BYTES = 4096`,
		`await open(DC_TOKEN_FILE, "r")`,
		`if (offset > DC_MAX_TOKEN_FILE_BYTES)`,
		`/^[0-9a-f]{64}$/`,
		`if (actionable) return { reason: "DefenseClaw hook credential is unavailable." }`,
		"tool.execute.before",         // block hook wired
		"input && input.args",         // after-hook preserves exact executed args
		"tool_response: toolResponse", // after-hook forwards the result
		"await defenseclawPost(",      // success is persisted before the next call
	} {
		if !strings.Contains(body, want) {
			t.Errorf("plugin missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "{{.") {
		t.Errorf("plugin still contains unrendered template placeholders:\n%s", body)
	}
	if strings.Contains(body, opts.APIToken) {
		t.Fatal("plugin embeds the connector-scoped credential instead of loading its sidecar")
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(pluginPath)
		if err != nil {
			t.Fatalf("stat plugin: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("plugin mode = %o, want 600 (managed policy bridge, never executable)", perm)
		}
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("plugin still present after teardown (err=%v)", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Errorf("VerifyClean after teardown: %v", err)
	}
}

func TestOpenCodePluginReloadsScopedTokenAndFailsCredentialErrorsClosed(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the OpenCode plugin rotation test")
	}
	aToken := strings.Repeat("a", 64)
	bToken := strings.Repeat("b", 64)
	authorizations := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizations <- r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"hook_output":{"decision":"allow"}}`))
	}))
	defer server.Close()

	root := t.TempDir()
	pluginPath := filepath.Join(root, "plugins", "defenseclaw.mjs")
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "dc"),
		APIAddr:      strings.TrimPrefix(server.URL, "http://"),
		APIToken:     aToken,
		HookFailMode: "open",
	}
	tokenPath, err := HookAPITokenFilePath(opts.DataDir, "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(tokenPath, []byte(aToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn := NewOpenCodeConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = conn.Teardown(context.Background(), opts) })

	pluginBytes, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{aToken, bToken} {
		if strings.Contains(string(pluginBytes), secret) {
			t.Fatal("rendered OpenCode plugin contains a rotation credential")
		}
	}
	harness := `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.DefenseClaw({ directory: "" });
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const _ of lines) {
  try {
    await plugin["tool.execute.before"](
      { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
      { args: { command: "printf test" } },
    );
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
`
	processCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(processCtx, node, "--input-type=module", "-e", harness, pluginPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	scanner := bufio.NewScanner(stdout)
	for index, token := range []string{aToken, bToken, aToken} {
		if index > 0 {
			if err := atomicWriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := fmt.Fprintln(stdin, "evaluate"); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("read OpenCode evaluation %d: %v; stderr=%s", index, scanner.Err(), stderr.String())
		}
		if got := scanner.Text(); got != "allow" {
			t.Fatalf("OpenCode evaluation %d = %q, want allow", index, got)
		}
	}
	if err := atomicWriteFile(tokenPath, []byte("malformed-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(stdin, "evaluate-invalid"); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() {
		t.Fatalf("read OpenCode credential failure: %v; stderr=%s", scanner.Err(), stderr.String())
	}
	if got := scanner.Text(); got != "block:DefenseClaw hook credential is unavailable." {
		t.Fatalf("OpenCode credential failure = %q, want redacted unconditional block", got)
	}
	if err := atomicWriteFile(tokenPath, []byte(strings.Repeat("x", 4097)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintln(stdin, "evaluate-oversized"); err != nil {
		t.Fatal(err)
	}
	if !scanner.Scan() {
		t.Fatalf("read OpenCode oversized credential failure: %v; stderr=%s", scanner.Err(), stderr.String())
	}
	if got := scanner.Text(); got != "block:DefenseClaw hook credential is unavailable." {
		t.Fatalf("OpenCode oversized credential failure = %q, want redacted unconditional block", got)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("OpenCode rotation process: %v; stderr=%s", err, stderr.String())
	}

	for index, want := range []string{"Bearer " + aToken, "Bearer " + bToken, "Bearer " + aToken} {
		if got := <-authorizations; got != want {
			t.Fatalf("OpenCode authorization %d = %q, want restored generation", index, got)
		}
	}
	pluginAfter, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(pluginAfter) != string(pluginBytes) {
		t.Fatal("sidecar rotation rewrote the stable OpenCode plugin")
	}
}

func TestOpenCodeOwnedHookContractRequiresExactRegularFileMarker(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, ".config", "opencode", "plugins", "defenseclaw.js")
	prev := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prev })

	conn := NewOpenCodeConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-opencode-marker-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	rendered, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read rendered plugin: %v", err)
	}
	lfRendered := bytes.ReplaceAll(rendered, []byte("\r\n"), []byte("\n"))
	crlfRendered := bytes.ReplaceAll(lfRendered, []byte("\n"), []byte("\r\n"))
	if err := os.WriteFile(pluginPath, crlfRendered, 0o600); err != nil {
		t.Fatalf("write CRLF-rendered plugin: %v", err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("CRLF marker present=%v err=%v, want true/nil", present, err)
	}
	if err := os.WriteFile(pluginPath, rendered, 0o600); err != nil {
		t.Fatalf("restore rendered plugin: %v", err)
	}

	foreignFirstLine := append([]byte("// operator-owned plugin\n"), rendered...)
	if err := os.WriteFile(pluginPath, foreignFirstLine, 0o600); err != nil {
		t.Fatalf("write marker lookalike: %v", err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("marker below first line present=%v err=%v, want false/nil", present, err)
	}

	if err := os.Remove(pluginPath); err != nil {
		t.Fatalf("remove plugin: %v", err)
	}
	if err := os.Mkdir(pluginPath, 0o700); err != nil {
		t.Fatalf("replace plugin with directory: %v", err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err == nil || present {
		t.Fatalf("directory present=%v err=%v, want false/error", present, err)
	}
	if err := os.Remove(pluginPath); err != nil {
		t.Fatalf("remove plugin directory: %v", err)
	}

	target := filepath.Join(dir, "operator-plugin.js")
	if err := os.WriteFile(target, rendered, 0o600); err != nil {
		t.Fatalf("write symlink target: %v", err)
	}
	if err := os.Symlink(target, pluginPath); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if present, err := conn.ownedHookContractPresent(opts); err == nil || present {
		t.Fatalf("symlink present=%v err=%v, want false/error", present, err)
	}
}

// TestOpenCodeSetup_FailModeDefaultsClosed asserts an unset HookFailMode
// renders the bridge in fail-closed mode, matching defaultHookFailMode
// (deny by default; see normalizeHookFailMode).
func TestOpenCodeSetup_FailModeDefaultsClosed(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "plugins", "defenseclaw.js")
	prev := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prev })

	conn := NewOpenCodeConnector()
	if err := conn.Setup(context.Background(), SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970"}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	raw, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read plugin: %v", err)
	}
	if !strings.Contains(string(raw), `DC_FAIL_MODE = "closed"`) {
		t.Errorf("default fail mode should be closed:\n%s", string(raw))
	}
}

// TestOpenCode_OpenClaw_NoCollision pins the isolation between the two
// confusingly-similar plugin installs: opencode (the third-party agent,
// bridge plugin at ~/.config/opencode/plugins/defenseclaw.js) and
// openclaw (DefenseClaw's own proxy connector, extension bundle under
// ~/.openclaw/). They are separate by construction — different roots,
// different override vars, managed backups keyed by connector name —
// but nothing else enforces it, so a future path/key refactor could
// silently let one clobber the other. Three guarantees:
//
//  1. opencode Setup writes only its own plugin path and never creates
//     anything under the openclaw home;
//  2. the managed-backup records are keyed per connector
//     (connector_backups/opencode vs connector_backups/openclaw);
//  3. tearing down opencode leaves an installed openclaw tree
//     byte-identical (cross-teardown safety).
//
// The openclaw half needs the embedded extension bundle (built via
// `make extensions`); when it is absent the openclaw assertions are
// logged-and-skipped while the opencode half still runs.
func TestOpenCode_OpenClaw_NoCollision(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "dc")
	pluginPath := filepath.Join(dir, "opencode-home", ".config", "opencode", "plugins", "defenseclaw.js")
	openclawHome := filepath.Join(dir, "openclaw-home", ".openclaw")

	prevPlugin := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prevPlugin })
	prevHome := OpenClawHomeOverride
	OpenClawHomeOverride = openclawHome
	t.Cleanup(func() { OpenClawHomeOverride = prevHome })

	opencode := NewOpenCodeConnector()
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-isolation"}
	if err := opencode.Setup(context.Background(), opts); err != nil {
		t.Fatalf("opencode Setup: %v", err)
	}
	if _, err := os.Stat(pluginPath); err != nil {
		t.Fatalf("opencode plugin missing after Setup: %v", err)
	}
	// Guarantee 1: nothing materialized under the openclaw home.
	if _, err := os.Stat(filepath.Dir(openclawHome)); !os.IsNotExist(err) {
		t.Fatalf("opencode Setup touched the openclaw home root: stat err=%v", err)
	}
	// Guarantee 2: backups are keyed per connector.
	if _, err := os.Stat(managedFileBackupPath(dataDir, "opencode", "config")); err != nil {
		t.Fatalf("opencode backup record missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "connector_backups", "openclaw")); !os.IsNotExist(err) {
		t.Fatalf("opencode Setup created a backup record under the openclaw key: stat err=%v", err)
	}

	if runtime.GOOS == "windows" || !OpenClawExtensionAvailable() {
		// Still prove opencode teardown cleans its own file before
		// skipping the cross-connector half.
		if err := opencode.Teardown(context.Background(), opts); err != nil {
			t.Fatalf("opencode Teardown: %v", err)
		}
		if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
			t.Fatalf("opencode plugin still present after Teardown: stat err=%v", err)
		}
		t.Skipf("openclaw cross-teardown half skipped: extension bundle unavailable on this host (GOOS=%s, bundled=%v)", runtime.GOOS, OpenClawExtensionAvailable())
	}

	openclaw := NewOpenClawConnector()
	if err := openclaw.Setup(context.Background(), opts); err != nil {
		t.Fatalf("openclaw Setup: %v", err)
	}
	before := snapshotTree(t, openclawHome)
	if len(before) == 0 {
		t.Fatalf("openclaw Setup produced no files under %s", openclawHome)
	}

	// Guarantee 3: tearing down opencode leaves openclaw byte-identical.
	if err := opencode.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("opencode Teardown: %v", err)
	}
	if _, err := os.Stat(pluginPath); !os.IsNotExist(err) {
		t.Fatalf("opencode plugin still present after Teardown: stat err=%v", err)
	}
	after := snapshotTree(t, openclawHome)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("openclaw tree changed across opencode Teardown:\nbefore: %v\nafter:  %v", treeKeys(before), treeKeys(after))
	}
}

// snapshotTree records every file under root as relpath → contents.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		files[rel] = string(data)
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return files
}

func treeKeys(files map[string]string) []string {
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// TestOpenCodeProfileRespond pins opencode's wire shape: block renders
// {decision:"deny", reason} (the bridge throws on it); every other action
// is observe-only (nil body). opencode flows through the shared
// hookOnlyProfileRespond switch.
func TestOpenCodeProfileRespond(t *testing.T) {
	cases := []struct {
		name     string
		action   string
		expected map[string]interface{}
	}{
		{"block_renders_decision_deny", "block", map[string]interface{}{"decision": "deny", "reason": "matched policy: deny-rm-rf"}},
		{"allow_is_nil", "allow", nil},
		{"alert_is_nil", "alert", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileRespond(HookRespondInput{
				Req:       HookProfileRequest{ConnectorName: "opencode", HookEventName: "tool.execute.before", ToolName: "bash"},
				Action:    tc.action,
				RawAction: tc.action,
				Reason:    "matched policy: deny-rm-rf",
			})
			if out.FieldName != "hook_output" {
				t.Errorf("FieldName=%q want hook_output", out.FieldName)
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}
