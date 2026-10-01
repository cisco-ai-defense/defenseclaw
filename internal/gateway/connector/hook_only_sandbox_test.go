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
	"regexp"
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

// tampered decodes good with unmarshal, applies fn, and encodes the result
// with marshal.
func tampered(t *testing.T, good []byte, unmarshal func([]byte, interface{}) error, marshal func(interface{}) ([]byte, error), fn func(map[string]interface{})) []byte {
	t.Helper()
	doc := map[string]interface{}{}
	if err := unmarshal(good, &doc); err != nil {
		t.Fatal(err)
	}
	fn(doc)
	out, err := marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// assertTamperRejected requires verify to accept the rendered good document
// and to reject every tampered one.
func assertTamperRejected(t *testing.T, verify func([]byte) error, good []byte, cases map[string][]byte) {
	t.Helper()
	if err := verify(good); err != nil {
		t.Fatalf("rendered document rejected: %v", err)
	}
	for name, body := range cases {
		if err := verify(body); err == nil {
			t.Errorf("%s: tampered document accepted", name)
		}
	}
}

// TestSandboxArtifactsTamperTiers pins each overlay's tamper tier: managed
// only where root-owned files alone carry the hooks; user where the workload
// can load code into the process beside them (OpenCode and Amp plugins, the
// Hermes home) or the harness reads them from HOME (Kiro, Devin, OpenHands,
// agy).
func TestSandboxArtifactsTamperTiers(t *testing.T) {
	managed := map[string]bool{"claudecode": true, "codex": true, "copilot": true, "cursor": true, "omnigent": true}
	for _, tc := range sandboxGoldenTargets {
		want := SandboxTamperTierUser
		if managed[tc.connector] {
			want = SandboxTamperTierManaged
		}
		if got := renderSandboxGolden(t, tc.provider, tc.version).TamperTier; got != want {
			t.Errorf("%s tamper tier %s, want %s", tc.connector, got, want)
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

// TestSandboxArtifactsRefuseUnreviewedHarness: only a pinned harness release
// inside a reviewed Linux hook contract, and a valid ingress port, render.
func TestSandboxArtifactsRefuseUnreviewedHarness(t *testing.T) {
	const noContract = "no reviewed Linux hook contract"
	for _, tc := range []struct {
		name     string
		provider SandboxArtifactProvider
		target   SandboxRenderTarget
		want     string // a substring of the error; any error when empty
	}{
		{"claude-missing-version", &ClaudeCodeConnector{}, SandboxRenderTarget{}, "pinned harness version"},
		{"claude-below-contract", &ClaudeCodeConnector{}, SandboxRenderTarget{AgentVersion: "2.1.100"}, noContract},
		{"claude-garbage-version", &ClaudeCodeConnector{}, SandboxRenderTarget{AgentVersion: "latest"}, noContract},
		{"codex-base-image-0.117", &CodexConnector{}, SandboxRenderTarget{AgentVersion: "codex-cli 0.117.0"}, noContract},
		{"codex-pin-mismatch", &CodexConnector{}, SandboxRenderTarget{AgentVersion: "0.146.0", HookContractID: "codex-hooks-v3"}, "not the pinned codex-hooks-v3"},
		{"port-zero", &CodexConnector{}, SandboxRenderTarget{AgentVersion: "0.146.0"}, "out of range"},
		{"port-too-large", &ClaudeCodeConnector{}, SandboxRenderTarget{IngressPort: 70000, AgentVersion: "2.1.156"}, "out of range"},
		// The community base image ships OpenCode 1.2.18 and Copilot 1.0.16.
		{"opencode-base-image", NewOpenCodeConnector(), SandboxRenderTarget{AgentVersion: "1.2.18"}, noContract},
		{"opencode-above-range", NewOpenCodeConnector(), SandboxRenderTarget{AgentVersion: "1.19.0"}, noContract},
		{"copilot-base-image", NewCopilotConnector(), SandboxRenderTarget{AgentVersion: "1.0.16"}, noContract},
		{"amp-below-floor", NewAMPConnector(), SandboxRenderTarget{AgentVersion: "0.0.1785301270-g4f08a3"}, noContract},
		{"amp-missing-version", NewAMPConnector(), SandboxRenderTarget{}, "pinned harness version"},
		{"cursor-newer-build", NewCursorConnector(), SandboxRenderTarget{AgentVersion: "2026.09.26-dd393fe"}, ""},
		{"cursor-desktop-version", NewCursorConnector(), SandboxRenderTarget{AgentVersion: "2.3.0"}, ""},
		{"cursor-desktop-major", NewCursorConnector(), SandboxRenderTarget{AgentVersion: "4.0.0"}, ""},
		{"devin-newer", NewDevinConnector(), SandboxRenderTarget{AgentVersion: "3000.12.0"}, ""},
		{"kiro-unpinned", NewKiroConnector(), SandboxRenderTarget{}, ""},
		{"omnigent-newer", NewOmnigentConnector(), SandboxRenderTarget{AgentVersion: "0.14.0"}, ""},
		{"omnigent-older", NewOmnigentConnector(), SandboxRenderTarget{AgentVersion: "0.6.0"}, ""},
		{"omnigent-unpinned", NewOmnigentConnector(), SandboxRenderTarget{}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.target.IngressPort == 0 && tc.name != "port-zero" {
				tc.target.IngressPort = 18971
			}
			if _, err := tc.provider.SandboxArtifacts(tc.target); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SandboxArtifacts error = %v, want %q", err, tc.want)
			}
		})
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
	mutate := func(fn func(map[string]interface{})) []byte {
		return tampered(t, good, json.Unmarshal, json.Marshal, fn)
	}
	hooks := func(doc map[string]interface{}) map[string]interface{} { return doc["hooks"].(map[string]interface{}) }
	assertTamperRejected(t, func(b []byte) error { return verifyCopilotSandboxPolicy(b, rt) }, good, map[string][]byte{
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
	})
	// Only the managed hooks run.
	managed := sandboxFile(t, sandboxArtifactsFor(t, NewCopilotConnector(), "1.0.88"), CopilotSandboxManagedSettingsPath)
	var settings map[string]interface{}
	if err := json.Unmarshal(managed.Data, &settings); err != nil || !reflect.DeepEqual(settings, map[string]interface{}{"allowManagedHooksOnly": true}) {
		t.Fatalf("managed settings = %s (%v)", managed.Data, err)
	}
}

func TestVerifyOpenCodeSandboxManagedConfigRejectsTampering(t *testing.T) {
	plugin := `"plugin":["file://` + OpenCodeSandboxPluginPath + `"]`
	good := sandboxFile(t, sandboxArtifactsFor(t, NewOpenCodeConnector(), "1.18.31"), OpenCodeSandboxManagedConfigPath).Data
	assertTamperRejected(t, verifyOpenCodeSandboxManagedConfig, good, map[string][]byte{
		"no-plugin":      []byte(`{"plugin":[],"autoupdate":false,"share":"disabled"}`),
		"extra-plugin":   []byte(`{"plugin":["file://` + OpenCodeSandboxPluginPath + `","file:///tmp/x.js"],"autoupdate":false,"share":"disabled"}`),
		"autoupdate":     []byte(`{` + plugin + `,"share":"disabled"}`),
		"share-enabled":  []byte(`{` + plugin + `,"autoupdate":false,"share":"auto"}`),
		"not-json":       []byte(`plugin = []`),
		"foreign-plugin": []byte(`{"plugin":["file:///sandbox/defenseclaw.js"],"autoupdate":false,"share":"disabled"}`),
	})
}

// TestRenderSandboxPluginRejectsHostInputs: a template that is not a sandbox
// bridge (the host render path) never passes as one, and the sandbox plugins
// carry no host-only input and always fail closed.
func TestRenderSandboxPluginRejectsHostInputs(t *testing.T) {
	rt, err := resolveSandboxTarget("opencode", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "1.18.31"})
	if err != nil {
		t.Fatal(err)
	}
	for _, asset := range []string{"claude-code-hook.sh", "inspect-tool.sh"} {
		if _, err := renderSandboxPlugin(asset, rt); err == nil {
			t.Fatalf("%s rendered as a sandbox plugin", asset)
		}
	}
	closed := regexp.MustCompile(`const DC_FAIL_MODE(: string)? = "closed"`)
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
		if !closed.Match(body) || !bytes.Contains(body, []byte("process.env.DEFENSECLAW_SANDBOX_TOKEN")) {
			t.Fatalf("%s does not fail closed on the binding token", asset)
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
	for _, tc := range []struct {
		kind     string
		provider SandboxArtifactProvider
		version  string
		path     string
		file     string
	}{
		{"opencode", NewOpenCodeConnector(), "1.18.31", OpenCodeSandboxPluginPath, "opencode-sandbox.mjs"},
		{"amp", NewAMPConnector(), "0.0.1785334225-g9abe75", AmpSandboxPluginPath, "amp-sandbox.ts"},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			if tc.kind == "amp" {
				probe := exec.Command(node, "-e", "process.exit(process.features && process.features.typescript ? 0 : 1)")
				if probe.Run() != nil {
					t.Skip("node without TypeScript stripping cannot load the Amp plugin")
				}
			}
			plugin := filepath.Join(dir, tc.file)
			if err := os.WriteFile(plugin, sandboxFile(t, sandboxArtifactsFor(t, tc.provider, tc.version), tc.path).Data, 0o600); err != nil {
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
