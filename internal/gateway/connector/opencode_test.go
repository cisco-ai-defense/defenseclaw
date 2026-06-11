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
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
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
