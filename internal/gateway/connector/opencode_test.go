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
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

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
		"127.0.0.1:18970",                  // APIAddr substituted
		"tok-opencode-123",                 // APIToken embedded
		`DC_FAIL_MODE = "closed"`,          // fail mode honored (SupportsFailClosed=true)
		"/api/v1/opencode/hook",            // gateway endpoint
		"tool.execute.before",              // block hook wired
		"input && input.args",              // after-hook preserves exact executed args
		"payload.tool_result = toolResult", // after-hook forwards the result
		"await defenseclawPost(",           // success is persisted before the next call
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
	current, err := OpenCodeRegistrationCurrent(opts)
	if err != nil || !current {
		t.Fatalf("OpenCode registration publication = %v, %v; want plugin plus custody receipt", current, err)
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

func TestOpenCodeHookContractLockIncludesManagedPluginDigest(t *testing.T) {
	dir := t.TempDir()
	pluginPath := filepath.Join(dir, "plugins", "defenseclaw.js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	pluginBody := []byte("// defenseclaw-managed-plugin v7\nconst route = \"/api/v1/opencode/hook\";\n")
	if err := os.WriteFile(pluginPath, pluginBody, 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previousPath })

	entry := NewHookContractLockEntry(
		SetupOpts{DataDir: filepath.Join(dir, "dc")},
		NewOpenCodeConnector(),
		"test-build",
	)
	wantPluginDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(pluginBody))
	if got := entry.HookScriptDigests[filepath.Base(pluginPath)]; got != wantPluginDigest {
		t.Fatalf("OpenCode lock plugin digest = %q, want %q", got, wantPluginDigest)
	}
}

func TestOpenCodeSetupRollsBackPluginAndReceiptWhenFinalPublicationFails(t *testing.T) {
	dir := testenv.PrivateTempDir(t)
	pluginPath := filepath.Join(dir, "plugins", "defenseclaw.js")
	if err := os.MkdirAll(filepath.Dir(pluginPath), 0o700); err != nil {
		t.Fatal(err)
	}
	pristine := []byte("// operator-owned plugin\n")
	if err := os.WriteFile(pluginPath, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	previousPath := OpenCodePluginPathOverride
	OpenCodePluginPathOverride = pluginPath
	t.Cleanup(func() { OpenCodePluginPathOverride = previousPath })

	previousWriter := openCodeWritePluginFile
	openCodeWritePluginFile = func(path string, body []byte, mode os.FileMode) error {
		backup, err := loadManagedFileBackupPath(
			managedFileBackupPath(filepath.Join(dir, "dc"), "opencode", "config"),
		)
		if err != nil {
			t.Fatalf("custody receipt was not finalized before plugin publication: %v", err)
		}
		if backup.PostSHA256 != managedFileSnapshotHash(body, true) {
			t.Fatalf("receipt post hash = %q, want rendered plugin digest", backup.PostSHA256)
		}
		return errors.New("injected final plugin publication failure")
	}
	t.Cleanup(func() { openCodeWritePluginFile = previousWriter })

	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-opencode-rollback",
	}
	err := NewOpenCodeConnector().Setup(context.Background(), opts)
	if err == nil || !strings.Contains(err.Error(), "injected final plugin publication failure") {
		t.Fatalf("Setup error = %v, want injected publication failure", err)
	}
	body, readErr := os.ReadFile(pluginPath)
	if readErr != nil || !reflect.DeepEqual(body, pristine) {
		t.Fatalf("plugin rollback = %q, %v; want exact pristine bytes", body, readErr)
	}
	backupPath := managedFileBackupPath(opts.DataDir, "opencode", "config")
	if _, statErr := os.Stat(backupPath); !os.IsNotExist(statErr) {
		t.Fatalf("failed setup left a backup receipt: %v", statErr)
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
	beforeThrow := strings.Index(text, `if (verdict && verdict.reason) throw new Error(verdict.reason);`)
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
	if !strings.Contains(afterBody[:afterEnd], "await defenseclawPost") {
		t.Fatal("tool.execute.after must await delivery so the result is attributed to the exact call")
	}
	if strings.Contains(afterBody[:afterEnd], "const verdict") || strings.Contains(afterBody[:afterEnd], "throw new Error") {
		t.Fatal("tool.execute.after must ignore the advisory verdict and remain observe-only")
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

func TestOpenCodeBridgePinsPluginOrderMCPIdentityAndHeartbeat(t *testing.T) {
	body, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(body)
	for _, want := range []string{
		"defenseclaw-managed-plugin v7",
		"const DC_PLUGIN_URL = import.meta.url",
		"Array.isArray(config.plugin_origins)",
		"DC_ARGUMENTS_AUTHORITATIVE = ownIndex >= 0 && DC_LATER_PLUGIN_COUNT === 0",
		`replace(/[^a-zA-Z0-9_-]/g, "_")`,
		`mcp[name].enabled !== false`,
		`return { status: "ambiguous", name: "" }`,
		"payload.mcp_server_name = mcpIdentity.name",
		`verdict.mode === "action" && mcpIdentity.status === "ambiguous"`,
		`verdict.mode === "action" && !DC_ARGUMENTS_AUTHORITATIVE`,
		`hook_event_name: "defenseclaw.plugin.loaded"`,
		`load_heartbeat: true`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("OpenCode bridge is missing audited v1.18.10-v1.18.11 behavior %q", want)
		}
	}
	if strings.Contains(text, "mcp__") || strings.Contains(text, "mcp:") {
		t.Fatal("OpenCode bridge must not fall back to another connector's MCP naming grammar")
	}
}

func TestOpenCodeProfileMapsAmbiguousMCPIdentityByMode(t *testing.T) {
	profile := NewOpenCodeConnector().HookProfile(SetupOpts{})
	for _, tc := range []struct {
		name           string
		mode           string
		status         string
		wantAction     string
		wantWouldBlock bool
	}{
		{name: "ambiguous observe", mode: "observe", status: "ambiguous", wantAction: "allow", wantWouldBlock: true},
		{name: "ambiguous action", mode: "action", status: "ambiguous", wantAction: "block", wantWouldBlock: false},
		{name: "authoritative action", mode: "action", status: "authoritative", wantAction: "allow", wantWouldBlock: false},
		{name: "non-MCP action", mode: "action", status: "not_mcp", wantAction: "allow", wantWouldBlock: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := profile.MapVerdict(HookVerdictInput{
				RawAction: "allow",
				Event:     "tool.execute.before",
				Mode:      tc.mode,
				Caps:      profile.Capabilities,
				Payload:   map[string]interface{}{"mcp_identity_status": tc.status},
			})
			if out.Action != tc.wantAction || out.WouldBlock != tc.wantWouldBlock {
				t.Fatalf("verdict = %+v, want action=%q would_block=%v", out, tc.wantAction, tc.wantWouldBlock)
			}
			response := profile.Respond(HookRespondInput{
				Req: HookProfileRequest{
					ConnectorName: "opencode",
					HookEventName: "tool.execute.before",
					ToolName:      "alpha_beta_list",
				},
				Action: out.Action,
				Caps:   profile.Capabilities,
			})
			if tc.wantAction == "block" {
				if response.Output["decision"] != "deny" {
					t.Fatalf("action ambiguity response = %#v, want synchronous deny", response.Output)
				}
			} else if response.Output != nil {
				t.Fatalf("non-blocking ambiguity response = %#v, want no OpenCode mutation", response.Output)
			}
		})
	}
}

func TestOpenCodeBridgeExecutableMCPIdentityAndFailurePosture(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the executable OpenCode plugin contract")
	}
	body, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	render := func(failMode string) []byte {
		t.Helper()
		text := strings.NewReplacer(
			"{{.APIAddr}}", "127.0.0.1:18970",
			"{{.APIToken}}", "provided by test runtime",
			"{{.FailMode}}", failMode,
		).Replace(string(body))
		if strings.Contains(text, "{{.") {
			t.Fatalf("rendered %s plugin retains a template placeholder", failMode)
		}
		return []byte(text)
	}
	dir := t.TempDir()
	openPlugin := filepath.Join(dir, "opencode-open.mjs")
	closedPlugin := filepath.Join(dir, "opencode-closed.mjs")
	if err := os.WriteFile(openPlugin, render("open"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(closedPlugin, render("closed"), 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	harness := filepath.Join("testdata", "opencode-plugin-contract.mjs")
	output, err := exec.CommandContext(ctx, node, harness, openPlugin, closedPlugin).CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("executable OpenCode plugin contract timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("executable OpenCode plugin contract: %v\n%s", err, output)
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
