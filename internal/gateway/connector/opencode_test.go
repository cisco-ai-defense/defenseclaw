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
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestOpenCodeAuthenticateRequiresScopedBearer(t *testing.T) {
	conn := NewOpenCodeConnector()
	conn.SetCredentials("connector-token", "gateway-master-key")

	for _, tc := range []struct {
		name       string
		remoteAddr string
		token      string
		want       bool
	}{
		{name: "scoped loopback", remoteAddr: "127.0.0.1:49152", token: "connector-token", want: true},
		{name: "scoped non-loopback", remoteAddr: "192.0.2.10:49152", token: "connector-token", want: true},
		{name: "missing loopback", remoteAddr: "127.0.0.1:49152", want: false},
		{name: "wrong loopback", remoteAddr: "127.0.0.1:49152", token: "wrong", want: false},
		{name: "master key rejected", remoteAddr: "127.0.0.1:49152", token: "gateway-master-key", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/opencode/hook", nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = tc.remoteAddr
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			if got := conn.Authenticate(req); got != tc.want {
				t.Fatalf("Authenticate() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOpenCodeCompatibilityBoundary(t *testing.T) {
	outsideReviewedRange := HookCompatibilityUnknown
	defaultForUnversioned := false
	if runtime.GOOS == "windows" {
		outsideReviewedRange = HookCompatibilityKnown
		defaultForUnversioned = true
	}
	for _, tc := range []struct {
		version string
		want    string
	}{
		{version: "1.16.1", want: outsideReviewedRange},
		{version: "1.16.2", want: HookCompatibilityKnown},
		{version: "1.18.10", want: HookCompatibilityKnown},
		{version: "1.18.11", want: outsideReviewedRange},
		{version: "1.19.0", want: outsideReviewedRange},
		{version: "", want: HookCompatibilityUnversioned},
	} {
		t.Run(tc.version, func(t *testing.T) {
			got := ResolveHookContract("opencode", tc.version)
			if got.Status != tc.want {
				t.Fatalf("ResolveHookContract(%q).Status = %q, want %q (%s)", tc.version, got.Status, tc.want, got.Reason)
			}
			if tc.version == "" && got.Contract.DefaultForUnversioned != defaultForUnversioned {
				t.Fatalf("unversioned OpenCode default=%v want %v", got.Contract.DefaultForUnversioned, defaultForUnversioned)
			}
		})
	}
}

func TestOpenCodeReviewedEventUnionIsComplete(t *testing.T) {
	contract := ResolveHookContract("opencode", "1.18.10").Contract
	got := make(map[string]bool, len(contract.Events))
	for _, event := range contract.Events {
		got[event] = true
	}
	// @opencode-ai/sdk Event union at the reviewed v1.18.10 tag, plus
	// permission.asked observed on the runtime bus and the two direct tool
	// hooks used by the DefenseClaw policy bridge. Windows retains PR #655's
	// narrower reviewed event overlay.
	reviewedEvents := []string{
		"server.instance.disposed",
		"installation.updated", "installation.update-available",
		"lsp.client.diagnostics", "lsp.updated",
		"message.updated", "message.removed", "message.part.updated", "message.part.removed",
		"permission.updated", "permission.asked", "permission.replied",
		"session.status", "session.idle", "session.compacted", "session.created",
		"session.updated", "session.deleted", "session.diff", "session.error",
		"file.edited", "file.watcher.updated", "todo.updated", "command.executed",
		"vcs.branch.updated", "tui.prompt.append", "tui.command.execute", "tui.toast.show",
		"pty.created", "pty.updated", "pty.exited", "pty.deleted", "server.connected",
		"tool.execute.before", "tool.execute.after",
	}
	if runtime.GOOS == "windows" {
		reviewedEvents = []string{
			"session.created", "session.updated", "session.status", "session.idle",
			"session.compacted", "session.error", "session.deleted",
			"tool.execute.before", "tool.execute.after",
		}
	}
	for _, event := range reviewedEvents {
		if !got[event] {
			t.Errorf("reviewed OpenCode event %q is absent from the contract", event)
		}
	}
	if contract.Capabilities.CanAskNative {
		t.Fatal("generic permission events must not be promoted to native ask semantics")
	}
	if !reflect.DeepEqual(contract.Capabilities.BlockEvents, []string{"tool.execute.before"}) {
		t.Fatalf("only awaited pre-tool may block; got %v", contract.Capabilities.BlockEvents)
	}
}

// TestOpenCodeSetup_WritesBridgePlugin pins the plugin-artifact install
// path: Setup renders the embedded bridge template (gateway addr, token,
// and fail mode substituted) and writes it owner-only into opencode's
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

	raw, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatalf("read plugin after setup: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"127.0.0.1:18970",         // APIAddr substituted
		"tok-opencode-123",        // APIToken embedded
		`DC_FAIL_MODE = "closed"`, // fail mode honored (SupportsFailClosed=true)
		"/api/v1/opencode/hook",   // gateway endpoint
		"tool.execute.before",     // block hook wired
	} {
		if !strings.Contains(body, want) {
			t.Errorf("plugin missing %q\n%s", want, body)
		}
	}
	if strings.Contains(body, "{{.") {
		t.Errorf("plugin still contains unrendered template placeholders:\n%s", body)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(pluginPath)
		if err != nil {
			t.Fatalf("stat plugin: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("plugin mode = %o, want 600 (carries the gateway token, never executable)", perm)
		}
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("OwnedHooksPresent: %v", err)
	}
	if !present {
		t.Fatal("managed OpenCode plugin was not recognized after Setup")
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

func TestOpenCodeManagedPluginCustodyAndTamperDetection(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, ".config", "opencode", "plugins", "defenseclaw.js")
	prev := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prev })

	conn := NewOpenCodeConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "token", HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || !present {
		t.Fatalf("managed plugin not recognized: present=%v err=%v", present, err)
	}
	if paths := conn.AgentPaths(opts); len(paths.HookScripts) != 0 {
		t.Fatalf("whole-file plugin incorrectly reported shell hooks: %v", paths.HookScripts)
	}
	if err := os.WriteFile(pluginPath, []byte("// tampered\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := OwnedHooksPresent(conn, opts); err != nil || present {
		t.Fatalf("tampered plugin not detected: present=%v err=%v", present, err)
	}
}

func TestOpenCodeTeardownRestoresPreexistingPluginExactly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("OpenCode plugin write and custody are unsupported on Windows")
	}
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, ".config", "opencode", "plugins", "defenseclaw.js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	original := []byte("// operator-owned preexisting plugin\nexport const x = 1;\n")
	if err := os.WriteFile(pluginPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	prev := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = prev })

	conn := NewOpenCodeConnector()
	opts := SetupOpts{DataDir: filepath.Join(dir, "dc"), APIAddr: "127.0.0.1:18970", APIToken: "token", HookFailMode: "closed"}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("teardown did not restore exact bytes: got %q want %q", got, original)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(pluginPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o640 {
			t.Fatalf("restored mode=%o want 640", info.Mode().Perm())
		}
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

func TestOpenCodeBridgeDistinguishesBlockingAndObserveOnlyHooks(t *testing.T) {
	body, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatalf("read bridge: %v", err)
	}
	text := string(body)
	beforeStart := strings.Index(text, `"tool.execute.before": async`)
	beforeAwait := strings.Index(text, `const verdict = await defenseclawPost(`)
	beforeThrow := strings.Index(text, `if (verdict) throw new Error(verdict.reason);`)
	if beforeStart < 0 || beforeAwait < beforeStart || beforeThrow < beforeAwait {
		t.Fatal("tool.execute.before must await the gateway verdict and throw synchronously on block")
	}
	afterStart := strings.Index(text, `"tool.execute.after": async`)
	afterPost := strings.Index(text[afterStart:], `"tool.execute.after",`)
	if afterStart < 0 || afterPost < 0 {
		t.Fatal("tool.execute.after observe path is missing")
	}
	afterBody := text[afterStart:]
	afterEnd := strings.Index(afterBody, "\n    },")
	if afterEnd < 0 {
		t.Fatal("tool.execute.after body terminator is missing")
	}
	if strings.Contains(afterBody[:afterEnd], "await defenseclawPost") {
		t.Fatal("tool.execute.after must remain best-effort and observe-only")
	}
	for _, field := range []string{"output.title", "output.output", "output.metadata"} {
		if !strings.Contains(afterBody[:afterEnd], field) {
			t.Fatalf("tool.execute.after omits official result field %q", field)
		}
	}
	if !strings.Contains(afterBody[:afterEnd], "input && input.args") {
		t.Fatal("tool.execute.after must read tool args from the official input object")
	}
	if strings.Contains(afterBody[:afterEnd], "output.args") {
		t.Fatal("tool.execute.after must not read before-hook args from its result object")
	}
	if !strings.Contains(text, "payload.tool_result = toolResult") {
		t.Fatal("tool.execute.after result must use the gateway's inspectable tool_result field")
	}
	if !strings.Contains(text, "OpenCode does not await this hook dispatch") {
		t.Fatal("lifecycle hook must document best-effort upstream dispatch")
	}
	if !strings.Contains(text, `source_event_id: event.id || ""`) {
		t.Fatal("lifecycle hook must preserve OpenCode's official event ID")
	}
	spec := DefaultCorrelationSpec("opencode")
	source, ok := spec.HookValue(
		map[string]interface{}{"source_event_id": "event-123"},
		CorrelationTargetSourceEvent,
	)
	if !ok || source.Value != "event-123" || source.IDKind != "source_event" {
		t.Fatalf("source event correlation = (%+v, %v), want event-123", source, ok)
	}
}

func TestOpenCodeOwnedHooksPresentRejectsManagedPluginDrift(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "OpenCode Config", "plugins", "defenseclaw.js")
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })
	conn := NewOpenCodeConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, ".defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-opencode-receipt",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		t.Fatalf("healthy plugin present=%v err=%v", present, err)
	}
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pluginPath, append(data, []byte("\n// operator edit\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	present, err = OwnedHooksPresent(conn, opts)
	if err != nil {
		t.Fatalf("drift inspection: %v", err)
	}
	if present {
		t.Fatal("digest-drifted OpenCode plugin was accepted as owned and healthy")
	}
}

func TestOpenCodePluginPathHonorsConfigDir(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "OpenCode Config")
	t.Setenv("OPENCODE_CONFIG_DIR", configDir)
	previous := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = ""
	t.Cleanup(func() { OpenCodePluginPathOverride = previous })

	got := opencodePluginPath(SetupOpts{})
	want := filepath.Join(configDir, "plugins", "defenseclaw.js")
	if got != want {
		t.Fatalf("opencodePluginPath() = %q, want %q", got, want)
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
