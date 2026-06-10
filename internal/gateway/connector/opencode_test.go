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
