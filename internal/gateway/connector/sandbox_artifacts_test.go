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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

const sandboxGoldenDir = "testdata/sandbox"

var sandboxGoldenTargets = []struct {
	connector string
	provider  SandboxArtifactProvider
	version   string
}{
	{"claudecode", &ClaudeCodeConnector{}, "2.1.156"},
	{"codex", &CodexConnector{}, "0.146.0"},
	{"amp", NewAMPConnector(), "0.0.1785334225-g9abe75"},
	{"copilot", NewCopilotConnector(), "1.0.88"},
	{"cursor", NewCursorConnector(), "2026.07.23-e383d2b"},
	{"devin", NewDevinConnector(), "3000.4.25"},
	{"kiro", NewKiroConnector(), "2.24.1"},
	{"opencode", NewOpenCodeConnector(), "1.18.31"},
	{"antigravity", NewAntigravityConnector(), "1.2.12"},
	{"hermes", NewHermesConnector(), "0.19.0"},
	{"openhands", NewOpenHandsConnector(), "1.16.0"},
}

type sandboxGoldenManifest struct {
	Connector    string                         `json:"connector"`
	HookContract string                         `json:"hook_contract"`
	TamperTier   string                         `json:"tamper_tier"`
	Env          map[string]string              `json:"env"`
	Binaries     []SandboxBinary                `json:"binaries"`
	Files        map[string]sandboxGoldenFileID `json:"files"`
}

type sandboxGoldenFileID struct {
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
	SHA256 string `json:"sha256"`
}

func renderSandboxGolden(t *testing.T, provider SandboxArtifactProvider, version string) SandboxArtifacts {
	t.Helper()
	artifacts, err := provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: version})
	if err != nil {
		t.Fatalf("SandboxArtifacts: %v", err)
	}
	return artifacts
}

// TestSandboxArtifactsGolden pins every byte, mode and owner of the overlay
// artifacts, plus the create-time env and required binaries. Regenerate
// deliberately with DEFENSECLAW_UPDATE_GOLDEN=1.
func TestSandboxArtifactsGolden(t *testing.T) {
	update := os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1"
	for _, tc := range sandboxGoldenTargets {
		t.Run(tc.connector, func(t *testing.T) {
			artifacts := renderSandboxGolden(t, tc.provider, tc.version)
			manifest := sandboxGoldenManifest{
				Connector:    artifacts.Connector,
				HookContract: artifacts.HookContract,
				TamperTier:   artifacts.TamperTier,
				Env:          artifacts.Env,
				Binaries:     artifacts.Binaries,
				Files:        map[string]sandboxGoldenFileID{},
			}
			root := filepath.Join(sandboxGoldenDir, tc.connector)
			for _, file := range artifacts.Files {
				sum := sha256.Sum256(file.Data)
				manifest.Files[file.Path] = sandboxGoldenFileID{
					Mode:   file.Mode.String(),
					Owner:  string(file.Owner),
					SHA256: hex.EncodeToString(sum[:]),
				}
				if filepath.Base(file.Path) == "_hardening.sh" {
					// Derived from the host helper; asserted separately.
					continue
				}
				goldenPath := filepath.Join(root, filepath.FromSlash(file.Path)) + ".golden"
				if update {
					if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(goldenPath, file.Data, 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(goldenPath)
				if err != nil {
					t.Fatalf("read golden %s (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", goldenPath, err)
				}
				if !bytes.Equal(want, file.Data) {
					t.Errorf("%s drifted from %s", file.Path, goldenPath)
				}
			}
			encoded, err := json.MarshalIndent(manifest, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			encoded = append(encoded, '\n')
			manifestPath := filepath.Join(sandboxGoldenDir, tc.connector+".manifest.json")
			if update {
				if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatalf("read golden manifest: %v", err)
			}
			if !bytes.Equal(want, encoded) {
				t.Errorf("manifest drifted from %s:\n%s", manifestPath, encoded)
			}
		})
	}
}

func TestSandboxArtifactsAreDeterministic(t *testing.T) {
	for _, tc := range sandboxGoldenTargets {
		first := renderSandboxGolden(t, tc.provider, tc.version)
		second := renderSandboxGolden(t, tc.provider, tc.version)
		if len(first.Files) != len(second.Files) {
			t.Fatalf("%s: file count changed between renders", tc.connector)
		}
		for i := range first.Files {
			if first.Files[i].Path != second.Files[i].Path || !bytes.Equal(first.Files[i].Data, second.Files[i].Data) {
				t.Fatalf("%s: %s is not deterministic", tc.connector, first.Files[i].Path)
			}
		}
	}
}

func TestSandboxArtifactsRefuseUnreviewedHarness(t *testing.T) {
	cases := []struct {
		name     string
		provider SandboxArtifactProvider
		target   SandboxRenderTarget
		want     string
	}{
		{"claude-missing-version", &ClaudeCodeConnector{}, SandboxRenderTarget{IngressPort: 18971}, "pinned harness version"},
		{"claude-below-contract", &ClaudeCodeConnector{}, SandboxRenderTarget{IngressPort: 18971, AgentVersion: "2.1.100"}, "no reviewed Linux hook contract"},
		{"claude-garbage-version", &ClaudeCodeConnector{}, SandboxRenderTarget{IngressPort: 18971, AgentVersion: "latest"}, "no reviewed Linux hook contract"},
		{"codex-base-image-0.117", &CodexConnector{}, SandboxRenderTarget{IngressPort: 18971, AgentVersion: "codex-cli 0.117.0"}, "no reviewed Linux hook contract"},
		{"codex-pin-mismatch", &CodexConnector{}, SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.146.0", HookContractID: "codex-hooks-v3"}, "not the pinned codex-hooks-v3"},
		{"port-zero", &CodexConnector{}, SandboxRenderTarget{AgentVersion: "0.146.0"}, "out of range"},
		{"port-too-large", &ClaudeCodeConnector{}, SandboxRenderTarget{IngressPort: 70000, AgentVersion: "2.1.156"}, "out of range"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.provider.SandboxArtifacts(tc.target)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("SandboxArtifacts error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRenderSandboxHookFilesRefusesConnectorsWithoutVariant(t *testing.T) {
	rt, err := resolveSandboxTarget("codex", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.146.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"geminicli", "openclaw", "windsurf", ""} {
		if _, err := renderSandboxHookFiles(name, rt); err == nil {
			t.Fatalf("connector %q rendered sandbox hooks without a sandbox template variant", name)
		}
	}
}

func TestSandboxHookScriptsCarryNoHostInputs(t *testing.T) {
	for _, tc := range sandboxGoldenTargets {
		artifacts := renderSandboxGolden(t, tc.provider, tc.version)
		for _, file := range artifacts.Files {
			if !strings.HasPrefix(file.Path, SandboxHookDir+"/") || !strings.HasSuffix(file.Path, ".sh") {
				continue
			}
			base := filepath.Base(file.Path)
			if base == "_hardening.sh" || base == "_sandbox.sh" {
				continue
			}
			body := string(file.Data)
			if !strings.HasPrefix(body, "#!/bin/bash -p\n") {
				t.Errorf("%s: sandbox hook must run under bash -p", file.Path)
			}
			for _, forbidden := range []string{"127.0.0.1", "DEFENSECLAW_GATEWAY_TOKEN:-", "DEFENSECLAW_FAIL_MODE:-", ".hookcfg"} {
				if strings.Contains(body, forbidden) {
					t.Errorf("%s: contains host-only %q", file.Path, forbidden)
				}
			}
			if strings.Contains(body, "/api/v1/") && !strings.Contains(body, "defenseclaw_sandbox_post") && base != codexSandboxNotifyScript {
				t.Errorf("%s: posts to the ingress without the retrying sandbox transport", file.Path)
			}
		}
	}
}

func TestSandboxHardeningBakesOnlyThePath(t *testing.T) {
	host, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	sandbox, err := renderSandboxHardening()
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(string(host), `DEFENSECLAW_BAKED_HOOK_PATH=""`, `DEFENSECLAW_BAKED_HOOK_PATH="`+SandboxHookPATH+`"`, 1)
	if string(sandbox) != want {
		t.Fatal("sandbox _hardening.sh differs from the host helper by more than the baked PATH")
	}
}

func TestClaudeCodeSandboxDropInShape(t *testing.T) {
	artifacts := renderSandboxGolden(t, &ClaudeCodeConnector{}, "2.1.156")
	var dropIn map[string]interface{}
	for _, file := range artifacts.Files {
		if file.Path == ClaudeCodeSandboxDropInPath {
			if err := json.Unmarshal(file.Data, &dropIn); err != nil {
				t.Fatal(err)
			}
		}
	}
	if dropIn == nil {
		t.Fatal("drop-in missing")
	}
	// Every key and value shape is reviewed against the Claude Code 2.1.156
	// settings schema and proven live by the image's hook-fire probe.
	allowed := map[string]bool{
		"allowManagedHooksOnly": true, "skipDangerousModePermissionPrompt": true, "otelHeadersHelper": true,
		"hooks": true, "env": true, "sandbox": true,
		"apiKeyHelper": true, "awsAuthRefresh": true, "awsCredentialExport": true, "gcpAuthRefresh": true,
	}
	for key := range dropIn {
		if !allowed[key] {
			t.Errorf("drop-in carries unreviewed key %q (Claude drops a whole drop-in with one invalid field)", key)
		}
	}
	// The auth helpers are schema strings; "" makes Claude run none of them.
	for _, key := range []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh"} {
		if got, ok := dropIn[key].(string); !ok || got != "" {
			t.Errorf("drop-in %s = %#v, want \"\"", key, dropIn[key])
		}
	}
	// Claude's own sandbox cannot nest inside OpenShell: pinned off, with
	// no other sandbox key (each one is a schema risk).
	if sandbox, ok := dropIn["sandbox"].(map[string]interface{}); !ok || len(sandbox) != 1 || sandbox["enabled"] != false {
		t.Errorf("drop-in sandbox = %#v, want exactly {\"enabled\": false}", dropIn["sandbox"])
	}
	env := dropIn["env"].(map[string]interface{})
	for key, want := range map[string]string{
		"CLAUDE_CODE_SIMPLE":           "0",
		"DISABLE_AUTOUPDATER":          "1",
		"OTEL_EXPORTER_OTLP_ENDPOINT":  "http://host.openshell.internal:18971",
		"OTEL_LOG_TOOL_CONTENT":        "0",
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		// Claude runs shell-form hooks, Bash tool commands and stdio MCP
		// servers through CLAUDE_CODE_SHELL_PREFIX; a settings file that set
		// it would replace every managed hook.
		"CLAUDE_CODE_SHELL_PREFIX":                "",
		"CLAUDE_CODE_SHELL":                       "",
		"SHELL":                                   "/bin/bash",
		"CLAUDE_CODE_STOP_HOOK_BLOCK_CAP":         "",
		"CLAUDE_CODE_SESSIONEND_HOOKS_TIMEOUT_MS": "",
		"LD_PRELOAD":                              "",
		"LD_LIBRARY_PATH":                         "",
		"LD_AUDIT":                                "",
		"BASH_ENV":                                "",
		"ENV":                                     "",
	} {
		if got, ok := env[key].(string); !ok || got != want {
			t.Errorf("env[%s] = %#v, want %q", key, env[key], want)
		}
	}
	for _, key := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "DEFENSECLAW_FAIL_MODE"} {
		if _, present := env[key]; present {
			t.Errorf("env must not carry %s", key)
		}
	}
	// Managed env outranks sandbox create --env: a provider pin in the static
	// image would override every run's provider (Bedrock Mantle, mocks,
	// custom gateways). The manager pins the run's provider per sandbox.
	for _, key := range []string{
		"ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS",
		"CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
	} {
		if _, present := env[key]; present {
			t.Errorf("env must not pin provider selection (%s): it would override the per-run provider", key)
		}
	}
	hooks := dropIn["hooks"].(map[string]interface{})
	contract, ok := hookContractByID("claudecode", artifacts.HookContract)
	if !ok {
		t.Fatal("unknown contract")
	}
	if len(hooks) != len(contract.Events) {
		t.Fatalf("drop-in registers %d events, contract has %d", len(hooks), len(contract.Events))
	}
}

func TestVerifyClaudeCodeSandboxDropInRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("claudecode", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "2.1.156"})
	if err != nil {
		t.Fatal(err)
	}
	good, err := renderClaudeCodeSandboxDropIn(rt)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyClaudeCodeSandboxDropIn(good, rt); err != nil {
		t.Fatalf("rendered drop-in rejected: %v", err)
	}
	mutate := func(fn func(map[string]interface{})) []byte {
		var doc map[string]interface{}
		if err := json.Unmarshal(good, &doc); err != nil {
			t.Fatal(err)
		}
		fn(doc)
		out, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := map[string][]byte{
		"disable-all-hooks":  mutate(func(d map[string]interface{}) { d["disableAllHooks"] = true }),
		"not-managed-only":   mutate(func(d map[string]interface{}) { d["allowManagedHooksOnly"] = false }),
		"missing-pretooluse": mutate(func(d map[string]interface{}) { delete(d["hooks"].(map[string]interface{}), "PreToolUse") }),
		"wrong-command": mutate(func(d map[string]interface{}) {
			d["hooks"].(map[string]interface{})["PreToolUse"] = []interface{}{map[string]interface{}{
				"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "/tmp/x.sh", "timeout": 30}},
			}}
		}),
		"invalid-json": []byte(`{"hooks":`),
		"shell-prefix-unpinned": mutate(func(d map[string]interface{}) {
			delete(d["env"].(map[string]interface{}), "CLAUDE_CODE_SHELL_PREFIX")
		}),
		"shell-prefix-set": mutate(func(d map[string]interface{}) {
			d["env"].(map[string]interface{})["CLAUDE_CODE_SHELL_PREFIX"] = "/sandbox/wrap.sh"
		}),
		"shell-unpinned":          mutate(func(d map[string]interface{}) { delete(d["env"].(map[string]interface{}), "SHELL") }),
		"simple-mode-on":          mutate(func(d map[string]interface{}) { d["env"].(map[string]interface{})["CLAUDE_CODE_SIMPLE"] = "1" }),
		"env-block-missing":       mutate(func(d map[string]interface{}) { delete(d, "env") }),
		"own-sandbox-unpinned":    mutate(func(d map[string]interface{}) { delete(d, "sandbox") }),
		"own-sandbox-on":          mutate(func(d map[string]interface{}) { d["sandbox"] = map[string]interface{}{"enabled": true} }),
		"own-sandbox-string":      mutate(func(d map[string]interface{}) { d["sandbox"] = map[string]interface{}{"enabled": "false"} }),
		"api-key-helper-unpinned": mutate(func(d map[string]interface{}) { delete(d, "apiKeyHelper") }),
		"aws-export-set":          mutate(func(d map[string]interface{}) { d["awsCredentialExport"] = "/sandbox/export.sh" }),
		"gcp-refresh-not-string":  mutate(func(d map[string]interface{}) { d["gcpAuthRefresh"] = false }),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if err := verifyClaudeCodeSandboxDropIn(body, rt); err == nil {
				t.Fatal("tampered drop-in accepted")
			}
		})
	}
}

func TestCodexSandboxRequirementsShape(t *testing.T) {
	artifacts := renderSandboxGolden(t, &CodexConnector{}, "0.146.0")
	var requirements, managed map[string]interface{}
	for _, file := range artifacts.Files {
		switch file.Path {
		case CodexSandboxRequirementsPath:
			if err := toml.Unmarshal(file.Data, &requirements); err != nil {
				t.Fatal(err)
			}
		case CodexSandboxManagedConfigPath:
			if err := toml.Unmarshal(file.Data, &managed); err != nil {
				t.Fatal(err)
			}
		}
	}
	if requirements["allow_managed_hooks_only"] != true {
		t.Fatal("allow_managed_hooks_only not pinned")
	}
	if requirements["features"].(map[string]interface{})["hooks"] != true {
		t.Fatal("features.hooks not pinned true")
	}
	hooks := requirements["hooks"].(map[string]interface{})
	if hooks["managed_dir"] != SandboxHookDir {
		t.Fatalf("managed_dir = %v", hooks["managed_dir"])
	}
	contract, _ := hookContractByID("codex", "codex-hooks-v4")
	for _, event := range contract.Events {
		groups, ok := hooks[event].([]interface{})
		if !ok || len(groups) != 1 {
			t.Fatalf("event %s groups = %#v", event, hooks[event])
		}
		handler := groups[0].(map[string]interface{})["hooks"].([]interface{})[0].(map[string]interface{})
		want := SandboxHookDir + "/codex-hook.sh --event " + event + " --hook-contract codex-hooks-v4"
		if handler["command"] != want {
			t.Fatalf("event %s command = %v, want %s", event, handler["command"], want)
		}
	}
	if _, present := hooks["state"]; present {
		t.Fatal("hooks.state must be absent")
	}
	if managed["check_for_update_on_startup"] != false {
		t.Fatal("update check not disabled")
	}
}

func TestVerifyCodexSandboxPolicyRejectsTampering(t *testing.T) {
	rt, err := resolveSandboxTarget("codex", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.146.0"})
	if err != nil {
		t.Fatal(err)
	}
	requirements, err := renderCodexSandboxRequirements(rt)
	if err != nil {
		t.Fatal(err)
	}
	managed, err := renderCodexSandboxManagedConfig(rt, "openshell")
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCodexSandboxPolicy(requirements, managed, rt, "openshell"); err != nil {
		t.Fatalf("rendered policy rejected: %v", err)
	}
	edit := func(doc []byte, fn func(map[string]interface{})) []byte {
		cfg := map[string]interface{}{}
		if err := toml.Unmarshal(doc, &cfg); err != nil {
			t.Fatal(err)
		}
		fn(cfg)
		out, err := toml.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	cases := []struct {
		name                  string
		requirements, managed []byte
	}{
		{"hooks-feature-off", edit(requirements, func(c map[string]interface{}) { c["features"] = map[string]interface{}{"hooks": false} }), managed},
		{"user-hooks-allowed", edit(requirements, func(c map[string]interface{}) { c["allow_managed_hooks_only"] = false }), managed},
		{"missing-event", edit(requirements, func(c map[string]interface{}) { delete(c["hooks"].(map[string]interface{}), "PreToolUse") }), managed},
		{"wrong-managed-dir", edit(requirements, func(c map[string]interface{}) { c["hooks"].(map[string]interface{})["managed_dir"] = "/tmp" }), managed},
		{"update-check-on", requirements, edit(managed, func(c map[string]interface{}) { c["check_for_update_on_startup"] = true })},
		{"plugins-on", requirements, edit(managed, func(c map[string]interface{}) { c["features"].(map[string]interface{})["plugins"] = true })},
		{"static-auth-header", requirements, edit(managed, func(c map[string]interface{}) {
			exporter := c["otel"].(map[string]interface{})["exporter"].(map[string]interface{})["otlp-http"].(map[string]interface{})
			exporter["headers"].(map[string]interface{})["authorization"] = "Bearer x"
		})},
		{"foreign-notify", requirements, edit(managed, func(c map[string]interface{}) { c["notify"] = []interface{}{"/tmp/n.sh"} })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyCodexSandboxPolicy(tc.requirements, tc.managed, rt, "openshell"); err == nil {
				t.Fatal("tampered policy accepted")
			}
		})
	}
}
