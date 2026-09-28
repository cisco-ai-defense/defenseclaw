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

//go:build !windows

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func sandboxArtifactsFor(t *testing.T, provider SandboxArtifactProvider, version string) SandboxArtifacts {
	t.Helper()
	artifacts, err := provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: version})
	if err != nil {
		t.Fatalf("SandboxArtifacts: %v", err)
	}
	return artifacts
}

func sandboxFile(t *testing.T, artifacts SandboxArtifacts, path string) SandboxFile {
	t.Helper()
	for _, f := range artifacts.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("%s artifacts lack %s", artifacts.Connector, path)
	return SandboxFile{}
}

func TestHookOnlySandboxArtifactsRefuseConnectorsWithoutVariant(t *testing.T) {
	// A hook-only connector that never registered a sandbox renderer.
	for _, conn := range []*hookOnlyConnector{{name: "nosandbox"}} {
		_, err := conn.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.0.0"})
		if err == nil || !strings.Contains(err.Error(), "no OpenShell sandbox variant") {
			t.Fatalf("%s: err = %v", conn.Name(), err)
		}
		if SandboxArtifactsSupported(conn) {
			t.Fatalf("%s reports a sandbox variant it cannot render", conn.Name())
		}
	}
	for _, conn := range []Connector{NewCursorConnector(), NewDevinConnector(), NewCopilotConnector(), NewOpenCodeConnector(), NewKiroConnector(), NewAMPConnector(), &ClaudeCodeConnector{}, &CodexConnector{}} {
		if !SandboxArtifactsSupported(conn) {
			t.Fatalf("%s renders sandbox artifacts but reports no variant", conn.Name())
		}
	}
}

// TestRegisterHookOnlySandboxRendererRefusesDuplicates keeps each
// <name>_sandbox.go the only renderer of its connector.
func TestRegisterHookOnlySandboxRendererRefusesDuplicates(t *testing.T) {
	for _, name := range []string{"amp", "copilot", "cursor", "devin", "opencode"} {
		if _, ok := hookOnlySandboxRenderers[name]; !ok {
			t.Fatalf("%s has no registered sandbox renderer", name)
		}
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("a second %s renderer registered", name)
				}
			}()
			registerHookOnlySandboxRenderer(name, hookOnlySandboxRenderers[name])
		}()
	}
}

func TestHookOnlySandboxArtifactsRefuseUnreviewedVersions(t *testing.T) {
	cases := []struct {
		name     string
		provider SandboxArtifactProvider
		version  string
		want     string
	}{
		// The community base image ships OpenCode 1.2.18 and Copilot 1.0.16.
		{"opencode-base-image", NewOpenCodeConnector(), "1.2.18", "no reviewed Linux hook contract"},
		{"opencode-above-range", NewOpenCodeConnector(), "1.19.0", "no reviewed Linux hook contract"},
		{"copilot-base-image", NewCopilotConnector(), "1.0.16", "no reviewed Linux hook contract"},
		{"amp-below-floor", NewAMPConnector(), "0.0.1785301270-g4f08a3", "no reviewed Linux hook contract"},
		{"amp-missing-version", NewAMPConnector(), "", "pinned harness version"},
		{"copilot-fail-open", NewCopilotConnector(), "1.0.88", "fail closed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := SandboxRenderTarget{IngressPort: 18971, AgentVersion: tc.version}
			if tc.name == "copilot-fail-open" {
				target.FailMode = "open"
			}
			_, err := tc.provider.SandboxArtifacts(target)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SandboxArtifacts error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCopilotSandboxPolicyShape(t *testing.T) {
	artifacts := sandboxArtifactsFor(t, NewCopilotConnector(), "1.0.88")
	if artifacts.HookContract != "copilot-hooks-v2" || artifacts.TamperTier != SandboxTamperTierManaged {
		t.Fatalf("contract %s tier %s", artifacts.HookContract, artifacts.TamperTier)
	}
	if artifacts.Env["COPILOT_AUTO_UPDATE"] != "false" {
		t.Fatalf("env = %v", artifacts.Env)
	}
	policy := sandboxFile(t, artifacts, CopilotSandboxPolicyPath)
	if policy.Owner != SandboxOwnerRoot || policy.Mode != 0o644 {
		t.Fatalf("policy %v %v", policy.Owner, policy.Mode)
	}
	var doc struct {
		Version int `json:"version"`
		Hooks   map[string][]struct {
			Type       string `json:"type"`
			Bash       string `json:"bash"`
			TimeoutSec int    `json:"timeoutSec"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(policy.Data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Version != 1 || len(doc.Hooks) != len(copilotCurrentHookEvents) {
		t.Fatalf("version %d, %d events", doc.Version, len(doc.Hooks))
	}
	for _, event := range copilotCurrentHookEvents {
		entries := doc.Hooks[event]
		want := "'" + SandboxHookDir + "/copilot-hook.sh' --event '" + event + "'"
		if len(entries) != 1 || entries[0].Type != "command" || entries[0].Bash != want || entries[0].TimeoutSec != 30 {
			t.Fatalf("%s entries = %+v, want bash %q", event, entries, want)
		}
	}
	managed := sandboxFile(t, artifacts, CopilotSandboxManagedSettingsPath)
	var settings map[string]interface{}
	if err := json.Unmarshal(managed.Data, &settings); err != nil || !reflect.DeepEqual(settings, map[string]interface{}{"allowManagedHooksOnly": true}) {
		t.Fatalf("managed settings = %s (%v)", managed.Data, err)
	}
	preseed := sandboxFile(t, artifacts, SandboxHomeDir+"/.copilot/config.json")
	if preseed.Owner != SandboxOwnerUser || !bytes.Contains(preseed.Data, []byte(`"/work"`)) {
		t.Fatalf("preseed = %s", preseed.Data)
	}
	hook := sandboxFile(t, artifacts, SandboxHookDir+"/copilot-hook.sh")
	for _, want := range []string{
		"#!/bin/bash -p\n",
		`. "${HOOK_DIR}/_sandbox.sh"`,
		`FAIL_MODE="closed"`,
		"defenseclaw_sandbox_require_token copilot copilot-hook",
		`defenseclaw_sandbox_post "/api/v1/copilot/hook"`,
		`-H "X-DefenseClaw-Copilot-Event: ${COPILOT_HOOK_EVENT}"`,
	} {
		if !bytes.Contains(hook.Data, []byte(want)) {
			t.Errorf("sandbox copilot hook lacks %q", want)
		}
	}
	for _, forbidden := range []string{"exit 0\n  ;;", "allowing copilot tool", `FAIL_MODE="open"`, ".hook-copilot.token"} {
		if bytes.Contains(hook.Data, []byte(forbidden)) {
			t.Errorf("sandbox copilot hook still contains host fail-open %q", forbidden)
		}
	}
}

func TestVerifyCopilotSandboxPolicyRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("copilot", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.0.88"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := renderCopilotSandboxPolicy(rt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCopilotSandboxPolicy(good, rt); err != nil {
		t.Fatalf("rendered policy rejected: %v", err)
	}
	mutate := func(f func(doc map[string]interface{})) []byte {
		var doc map[string]interface{}
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc)
		out, _ := json.Marshal(doc)
		return out
	}
	hooks := func(doc map[string]interface{}) map[string]interface{} { return doc["hooks"].(map[string]interface{}) }
	for name, body := range map[string][]byte{
		"missing-event": mutate(func(doc map[string]interface{}) { delete(hooks(doc), "preToolUse") }),
		"extra-event":   mutate(func(doc map[string]interface{}) { hooks(doc)["futureEvent"] = hooks(doc)["preToolUse"] }),
		"second-handler": mutate(func(doc map[string]interface{}) {
			h := hooks(doc)
			h["preToolUse"] = append(h["preToolUse"].([]interface{}), h["postToolUse"].([]interface{})...)
		}),
		"foreign-command": mutate(func(doc map[string]interface{}) {
			hooks(doc)["preToolUse"].([]interface{})[0].(map[string]interface{})["bash"] = "/bin/true"
		}),
		"short-timeout": mutate(func(doc map[string]interface{}) {
			hooks(doc)["preToolUse"].([]interface{})[0].(map[string]interface{})["timeoutSec"] = 1
		}),
		"version-2":   mutate(func(doc map[string]interface{}) { doc["version"] = 2 }),
		"unknown-key": mutate(func(doc map[string]interface{}) { doc["disableAllHooks"] = true }),
	} {
		if err := verifyCopilotSandboxPolicy(body, rt); err == nil {
			t.Errorf("%s: tampered policy accepted", name)
		}
	}
}

func TestOpenCodeSandboxArtifactsShape(t *testing.T) {
	artifacts := sandboxArtifactsFor(t, NewOpenCodeConnector(), "1.18.31")
	// The registration is managed, but plugins and custom tools the user or
	// a project adds load into the same process, so the tier is user.
	if artifacts.HookContract != "opencode-hooks-v1" || artifacts.TamperTier != SandboxTamperTierUser {
		t.Fatalf("contract %s tier %s", artifacts.HookContract, artifacts.TamperTier)
	}
	if len(artifacts.Files) != 2 || !reflect.DeepEqual(artifacts.Binaries, []SandboxBinary{{Name: "opencode", Role: SandboxBinaryHarness}}) {
		t.Fatalf("files %d binaries %v", len(artifacts.Files), artifacts.Binaries)
	}
	managed := sandboxFile(t, artifacts, OpenCodeSandboxManagedConfigPath)
	var cfg map[string]interface{}
	if err := json.Unmarshal(managed.Data, &cfg); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(cfg["plugin"], []interface{}{"file://" + OpenCodeSandboxPluginPath}) || cfg["autoupdate"] != false || cfg["share"] != "disabled" {
		t.Fatalf("managed config = %s", managed.Data)
	}
	plugin := sandboxFile(t, artifacts, OpenCodeSandboxPluginPath)
	if plugin.Owner != SandboxOwnerRoot || plugin.Mode != 0o644 {
		t.Fatalf("plugin %v %v", plugin.Owner, plugin.Mode)
	}
	for _, want := range []string{
		`const DC_API_ADDR = "host.openshell.internal:18971";`,
		`const DC_FAIL_MODE = "closed";`,
		"process.env.DEFENSECLAW_SANDBOX_TOKEN",
		`"X-DefenseClaw-Hook-Idempotency-Key": key`,
		"const DC_TIMEOUT_MS = 9000;",
		"const DC_RETRY_TIMEOUT_MS = 12000;",
		`"tool.execute.before": async`,
	} {
		if !bytes.Contains(plugin.Data, []byte(want)) {
			t.Errorf("sandbox OpenCode plugin lacks %q", want)
		}
	}
}

func TestVerifyOpenCodeSandboxManagedConfigRejectsTampering(t *testing.T) {
	for name, body := range map[string]string{
		"no-plugin":      `{"plugin":[],"autoupdate":false,"share":"disabled"}`,
		"extra-plugin":   `{"plugin":["file://` + OpenCodeSandboxPluginPath + `","file:///tmp/x.js"],"autoupdate":false,"share":"disabled"}`,
		"autoupdate":     `{"plugin":["file://` + OpenCodeSandboxPluginPath + `"],"share":"disabled"}`,
		"share-enabled":  `{"plugin":["file://` + OpenCodeSandboxPluginPath + `"],"autoupdate":false,"share":"auto"}`,
		"not-json":       `plugin = []`,
		"foreign-plugin": `{"plugin":["file:///sandbox/defenseclaw.js"],"autoupdate":false,"share":"disabled"}`,
	} {
		if err := verifyOpenCodeSandboxManagedConfig([]byte(body)); err == nil {
			t.Errorf("%s: tampered managed config accepted", name)
		}
	}
}

func TestAmpSandboxArtifactsShape(t *testing.T) {
	artifacts := sandboxArtifactsFor(t, NewAMPConnector(), "0.0.1785334225-g9abe75")
	if artifacts.HookContract != "amp-plugin-v1" || artifacts.TamperTier != SandboxTamperTierUser {
		t.Fatalf("contract %s tier %s", artifacts.HookContract, artifacts.TamperTier)
	}
	plugin := sandboxFile(t, artifacts, AmpSandboxPluginPath)
	if plugin.Owner != SandboxOwnerUser || plugin.Mode != 0o600 || len(artifacts.Files) != 1 {
		t.Fatalf("plugin %v %v, %d files", plugin.Owner, plugin.Mode, len(artifacts.Files))
	}
	for _, want := range []string{
		`const DC_API_ADDR = "host.openshell.internal:18971"`,
		`const DC_FAIL_MODE: string = "closed"`,
		"process.env.DEFENSECLAW_SANDBOX_TOKEN",
		`"X-DefenseClaw-Hook-Idempotency-Key": key`,
		`amp.on("tool.call"`,
		`amp.on("tool.result"`,
	} {
		if !bytes.Contains(plugin.Data, []byte(want)) {
			t.Errorf("sandbox Amp plugin lacks %q", want)
		}
	}
	if artifacts.Env["AMP_SKIP_UPDATE_CHECK"] != "1" {
		t.Fatalf("env = %v", artifacts.Env)
	}
}

func TestRenderSandboxPluginRejectsHostInputs(t *testing.T) {
	rt, err := resolveSandboxTarget("opencode", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.18.31"})
	if err != nil {
		t.Fatal(err)
	}
	// A template that is not a sandbox bridge (the host render path) must
	// never pass as one.
	for _, asset := range []string{"claude-code-hook.sh", "inspect-tool.sh"} {
		if _, err := renderSandboxPlugin(asset, rt); err == nil {
			t.Fatalf("%s rendered as a sandbox plugin", asset)
		}
	}
	for _, asset := range []string{"opencode-plugin.js", "amp-plugin.ts"} {
		body, err := renderSandboxPlugin(asset, rt)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		for _, marker := range sandboxPluginHostOnlyMarkers {
			if bytes.Contains(body, []byte(marker)) {
				t.Fatalf("%s carries host-only %q", asset, marker)
			}
		}
	}
}

// TestSandboxPluginsExecutableContract runs the rendered sandbox plugins
// under node against a stubbed fetch: env token, idempotency key, one retry
// on relay failures, fail closed on everything else.
func TestSandboxPluginsExecutableContract(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the executable sandbox plugin contract")
	}
	dir := t.TempDir()
	harness, err := filepath.Abs(filepath.Join("testdata", "sandbox-plugin-contract.mjs"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		kind     string
		provider SandboxArtifactProvider
		version  string
		path     string
		file     string
	}{
		{"opencode", NewOpenCodeConnector(), "1.18.31", OpenCodeSandboxPluginPath, "opencode-sandbox.mjs"},
		{"amp", NewAMPConnector(), "0.0.1785334225-g9abe75", AmpSandboxPluginPath, "amp-sandbox.ts"},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if tc.kind == "amp" {
				probe := exec.Command(node, "-e", "process.exit(process.features && process.features.typescript ? 0 : 1)")
				if probe.Run() != nil {
					t.Skip("node without TypeScript stripping cannot load the Amp plugin")
				}
			}
			artifacts := sandboxArtifactsFor(t, tc.provider, tc.version)
			plugin := filepath.Join(dir, tc.file)
			if err := os.WriteFile(plugin, sandboxFile(t, artifacts, tc.path).Data, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, node, harness, tc.kind, plugin)
			cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir, "NODE_NO_WARNINGS=1"}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s sandbox plugin contract: %v\n%s", tc.kind, err, out)
			}
			t.Logf("%s", bytes.TrimSpace(out))
		})
	}
}
