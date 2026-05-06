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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHookOnlyConnector_CapabilityMatrix(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir()}
	cases := []struct {
		conn       *hookOnlyConnector
		canAsk     bool
		failClosed bool
		scope      string
		configBase string
	}{
		{NewHermesConnector(), false, false, "user", "config.yaml"},
		{NewCursorConnector(), true, true, "user", "hooks.json"},
		{NewWindsurfConnector(), false, false, "user", "hooks.json"},
		{NewGeminiCLIConnector(), false, true, "user", "settings.json"},
		{NewCopilotConnector(), true, false, "workspace", "defenseclaw.json"},
	}
	for _, tc := range cases {
		t.Run(tc.conn.Name(), func(t *testing.T) {
			caps := tc.conn.HookCapabilities(opts)
			if !caps.CanBlock {
				t.Fatal("CanBlock = false, want true")
			}
			if caps.CanAskNative != tc.canAsk {
				t.Fatalf("CanAskNative = %v, want %v", caps.CanAskNative, tc.canAsk)
			}
			if caps.SupportsFailClosed != tc.failClosed {
				t.Fatalf("SupportsFailClosed = %v, want %v", caps.SupportsFailClosed, tc.failClosed)
			}
			if caps.Scope != tc.scope {
				t.Fatalf("Scope = %q, want %q", caps.Scope, tc.scope)
			}
			if filepath.Base(caps.ConfigPath) != tc.configBase {
				t.Fatalf("ConfigPath = %q, want basename %q", caps.ConfigPath, tc.configBase)
			}
		})
	}
}

func TestHookOnlyConnector_SurfaceCapabilities(t *testing.T) {
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: t.TempDir(), APIAddr: "127.0.0.1:18970"}
	cases := []struct {
		conn             *hookOnlyConnector
		codeGuardTargets []string
		nativeOTLP       bool
		pluginsSupported bool
	}{
		{NewHermesConnector(), []string{"skill"}, false, true},
		{NewCursorConnector(), []string{"skill", "rule"}, false, false},
		{NewWindsurfConnector(), []string{"rule"}, false, false},
		{NewGeminiCLIConnector(), []string{"skill"}, true, true},
		{NewCopilotConnector(), []string{"skill", "rule"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.conn.Name(), func(t *testing.T) {
			caps := tc.conn.Capabilities(opts)
			if !caps.MCP.Supported {
				t.Fatal("MCP.Supported = false, want true")
			}
			if caps.CodeGuard.Supported != (len(tc.codeGuardTargets) > 0) {
				t.Fatalf("CodeGuard.Supported = %v", caps.CodeGuard.Supported)
			}
			if strings.Join(caps.CodeGuard.InstallTargets, ",") != strings.Join(tc.codeGuardTargets, ",") {
				t.Fatalf("CodeGuard.InstallTargets = %v, want %v", caps.CodeGuard.InstallTargets, tc.codeGuardTargets)
			}
			if caps.CodeGuard.AutoInstall {
				t.Fatal("CodeGuard.AutoInstall = true, want explicit opt-in")
			}
			if caps.Telemetry.NativeOTLP != tc.nativeOTLP {
				t.Fatalf("Telemetry.NativeOTLP = %v, want %v", caps.Telemetry.NativeOTLP, tc.nativeOTLP)
			}
			if caps.Plugins.Supported != tc.pluginsSupported {
				t.Fatalf("Plugins.Supported = %v, want %v", caps.Plugins.Supported, tc.pluginsSupported)
			}
		})
	}
}

func TestHookOnlyConnector_SetupTeardown_BackupRestore(t *testing.T) {
	dir := t.TempDir()
	configDir := t.TempDir()
	overrides := map[string]*string{
		"hermes":    &HermesConfigPathOverride,
		"cursor":    &CursorHooksPathOverride,
		"windsurf":  &WindsurfHooksPathOverride,
		"geminicli": &GeminiSettingsPathOverride,
		"copilot":   &CopilotHooksPathOverride,
	}
	connectors := []*hookOnlyConnector{
		NewHermesConnector(),
		NewCursorConnector(),
		NewWindsurfConnector(),
		NewGeminiCLIConnector(),
		NewCopilotConnector(),
	}
	for _, conn := range connectors {
		t.Run(conn.Name(), func(t *testing.T) {
			cfgPath := filepath.Join(configDir, conn.Name(), "config")
			if conn.Name() == "hermes" {
				cfgPath += ".yaml"
			} else {
				cfgPath += ".json"
			}
			ptr := overrides[conn.Name()]
			prev := *ptr
			*ptr = cfgPath
			t.Cleanup(func() { *ptr = prev })

			opts := SetupOpts{DataDir: filepath.Join(dir, conn.Name()), APIAddr: "127.0.0.1:18970", APIToken: "tok-test", WorkspaceDir: t.TempDir()}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			data, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatalf("read config after setup: %v", err)
			}
			if !strings.Contains(string(data), conn.scriptName) {
				t.Fatalf("config after setup does not reference %s:\n%s", conn.scriptName, string(data))
			}
			if err := conn.Teardown(context.Background(), opts); err != nil {
				t.Fatalf("Teardown: %v", err)
			}
			if _, err := os.Stat(cfgPath); err == nil {
				t.Fatalf("config file still exists after teardown of previously missing config: %s", cfgPath)
			} else if !os.IsNotExist(err) {
				t.Fatalf("stat config after teardown: %v", err)
			}
		})
	}
}

func TestGeminiSetup_PatchesNativeTelemetryPathToken(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read gemini settings: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, `"target": "otlp"`) || !strings.Contains(text, `/otlp/geminicli/tok-test`) {
		t.Fatalf("gemini settings missing managed telemetry path-token config:\n%s", text)
	}
	if !strings.Contains(text, `"managedBy": "defenseclaw"`) {
		t.Fatalf("gemini settings missing managed marker:\n%s", text)
	}
}

func TestGeminiTeardown_DriftedConfigRemovesManagedTelemetry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "settings.json")
	prev := GeminiSettingsPathOverride
	GeminiSettingsPathOverride = cfgPath
	t.Cleanup(func() { GeminiSettingsPathOverride = prev })

	conn := NewGeminiCLIConnector()
	opts := SetupOpts{
		DataDir:  filepath.Join(dir, "dc"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "tok-test",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read setup config: %v", err)
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("parse setup config: %v", err)
	}
	cfg["userSetting"] = "keep"
	telemetry, _ := cfg["telemetry"].(map[string]interface{})
	if telemetry == nil {
		t.Fatal("setup did not create telemetry object")
	}
	telemetry["userTelemetrySetting"] = "keep"
	drifted, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal drifted config: %v", err)
	}
	if err := os.WriteFile(cfgPath, append(drifted, '\n'), 0o600); err != nil {
		t.Fatalf("write drifted config: %v", err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	restored, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config after teardown: %v", err)
	}
	text := string(restored)
	for _, forbidden := range []string{"geminicli-hook.sh", "/otlp/geminicli/", `"managedBy": "defenseclaw"`} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("teardown left managed Gemini residue %q:\n%s", forbidden, text)
		}
	}
	for _, want := range []string{`"userSetting": "keep"`, `"userTelemetrySetting": "keep"`} {
		if !strings.Contains(text, want) {
			t.Fatalf("teardown did not preserve user edit %q:\n%s", want, text)
		}
	}
}

func TestHookOnlyTeardown_UsesBackedUpConfigPathWhenWorkspaceChanges(t *testing.T) {
	dir := t.TempDir()
	prevHooks := CopilotHooksPathOverride
	prevWorkspace := CopilotWorkspaceDirOverride
	CopilotHooksPathOverride = ""
	CopilotWorkspaceDirOverride = ""
	t.Cleanup(func() {
		CopilotHooksPathOverride = prevHooks
		CopilotWorkspaceDirOverride = prevWorkspace
	})

	oldWorkspace := filepath.Join(dir, "old-workspace")
	newWorkspace := filepath.Join(dir, "new-workspace")
	conn := NewCopilotConnector()
	setupOpts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: oldWorkspace,
	}
	if err := conn.Setup(context.Background(), setupOpts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	oldPath := filepath.Join(oldWorkspace, ".github", "hooks", "defenseclaw.json")
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("expected old workspace hook config after setup: %v", err)
	}

	teardownOpts := setupOpts
	teardownOpts.WorkspaceDir = newWorkspace
	if err := conn.Teardown(context.Background(), teardownOpts); err != nil {
		t.Fatalf("Teardown with changed workspace: %v", err)
	}
	if _, err := os.Stat(oldPath); err == nil {
		t.Fatalf("old workspace hook config survived teardown: %s", oldPath)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat old workspace hook config: %v", err)
	}
}

func TestCursorHooks_FailClosedOnlyWhenExplicit(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "hooks.json")
	prev := CursorHooksPathOverride
	CursorHooksPathOverride = cfgPath
	t.Cleanup(func() { CursorHooksPathOverride = prev })

	conn := NewCursorConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(dir, "dc"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		HookFailMode: "closed",
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read cursor hooks: %v", err)
	}
	if !strings.Contains(string(data), `"failClosed": true`) {
		t.Fatalf("cursor hooks did not enable failClosed when explicitly requested:\n%s", string(data))
	}
}

func TestHookOnlyHookScripts_RespectFailClosedCapability(t *testing.T) {
	cases := []struct {
		name         string
		connector    *hookOnlyConnector
		wantFailMode string
	}{
		{name: "cursor_supports_fail_closed", connector: NewCursorConnector(), wantFailMode: "closed"},
		{name: "geminicli_supports_fail_closed", connector: NewGeminiCLIConnector(), wantFailMode: "closed"},
		{name: "hermes_downgrades_to_fail_open", connector: NewHermesConnector(), wantFailMode: "open"},
		{name: "copilot_downgrades_to_fail_open", connector: NewCopilotConnector(), wantFailMode: "open"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			opts := SetupOpts{
				DataDir:      filepath.Join(dir, "dc"),
				APIAddr:      "127.0.0.1:18970",
				APIToken:     "tok-test",
				HookFailMode: "closed",
				WorkspaceDir: dir,
			}
			if err := WriteHookScriptsForConnectorObjectWithOpts(filepath.Join(dir, "hooks"), opts, tc.connector); err != nil {
				t.Fatalf("WriteHookScriptsForConnectorObjectWithOpts: %v", err)
			}
			body, err := os.ReadFile(filepath.Join(dir, "hooks", tc.connector.scriptName))
			if err != nil {
				t.Fatalf("read hook script: %v", err)
			}
			want := `FAIL_MODE="${DEFENSECLAW_FAIL_MODE:-` + tc.wantFailMode + `}"`
			if !strings.Contains(string(body), want) {
				t.Fatalf("hook script missing %s:\n%s", want, string(body))
			}
		})
	}
}
