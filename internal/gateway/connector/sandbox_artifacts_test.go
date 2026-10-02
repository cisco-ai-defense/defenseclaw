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
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

// sandboxGoldenDir holds one manifest per harness: the create-time env, the
// required binaries and the mode, owner, size and SHA-256 of every overlay
// file. The rendered bytes are not checked in; set sandboxRenderDirEnv to
// write them out for review.
const sandboxGoldenDir = "testdata/sandbox"

// sandboxRenderDirEnv names a directory TestSandboxArtifactsGolden writes each
// harness's rendered overlay under (<dir>/<connector>/<in-image path>), so a
// drift can be read by diffing the trees two revisions render.
const sandboxRenderDirEnv = "DEFENSECLAW_SANDBOX_RENDER_DIR"

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
	{"omnigent", NewOmnigentConnector(), "0.13.0"},
}

type sandboxGoldenManifest struct {
	Connector    string                         `json:"connector"`
	HookContract string                         `json:"hook_contract"`
	TamperTier   string                         `json:"tamper_tier"`
	Env          map[string]string              `json:"env"`
	Binaries     []string                       `json:"binaries"`
	Files        map[string]sandboxGoldenFileID `json:"files"`
}

type sandboxGoldenFileID struct {
	Mode   string `json:"mode"`
	Owner  string `json:"owner"`
	Size   int    `json:"size"`
	SHA256 string `json:"sha256"`
}

// sandboxGoldenBinary mirrors SandboxBinary: the conversion in
// sandboxManifestOf stops compiling when SandboxBinary gains a field the
// manifest's "name (role)" entries would not record.
type sandboxGoldenBinary struct {
	Name string
	Role SandboxBinaryRole
}

func sandboxManifestOf(artifacts SandboxArtifacts) sandboxGoldenManifest {
	manifest := sandboxGoldenManifest{
		Connector:    artifacts.Connector,
		HookContract: artifacts.HookContract,
		TamperTier:   artifacts.TamperTier,
		Env:          artifacts.Env,
		Binaries:     []string{},
		Files:        map[string]sandboxGoldenFileID{},
	}
	for _, binary := range artifacts.Binaries {
		b := sandboxGoldenBinary(binary)
		manifest.Binaries = append(manifest.Binaries, b.Name+" ("+string(b.Role)+")")
	}
	for _, file := range artifacts.Files {
		sum := sha256.Sum256(file.Data)
		manifest.Files[file.Path] = sandboxGoldenFileID{
			Mode:   file.Mode.String(),
			Owner:  string(file.Owner),
			Size:   len(file.Data),
			SHA256: hex.EncodeToString(sum[:]),
		}
	}
	return manifest
}

// entries flattens a manifest to one value per named entry, so a drift report
// can name each file, env key and binary that moved.
func (m sandboxGoldenManifest) entries() map[string]string {
	out := map[string]string{"connector": m.Connector, "hook_contract": m.HookContract, "tamper_tier": m.TamperTier}
	for key, value := range m.Env {
		out["env "+key] = value
	}
	for _, binary := range m.Binaries {
		out["binary "+binary] = "required"
	}
	for path, f := range m.Files {
		out[path] = fmt.Sprintf("%s %s %d bytes sha256:%s", f.Mode, f.Owner, f.Size, f.SHA256)
	}
	return out
}

func diffSandboxManifests(want, got sandboxGoldenManifest) []string {
	before, after := want.entries(), got.entries()
	var diffs []string
	for key, value := range after {
		if old, ok := before[key]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: new, %q", key, value))
		} else if old != value {
			diffs = append(diffs, fmt.Sprintf("%s: %q -> %q", key, old, value))
		}
	}
	for key, old := range before {
		if _, ok := after[key]; !ok {
			diffs = append(diffs, fmt.Sprintf("%s: gone, was %q", key, old))
		}
	}
	sort.Strings(diffs)
	return diffs
}

func writeSandboxRendering(t *testing.T, dir, connector string, files []SandboxFile) {
	t.Helper()
	for _, file := range files {
		path := filepath.Join(dir, connector, filepath.FromSlash(file.Path))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, file.Data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func renderSandboxGolden(t *testing.T, provider SandboxArtifactProvider, version string) SandboxArtifacts {
	t.Helper()
	artifacts, err := provider.SandboxArtifacts(SandboxRenderTarget{IngressPort: 18971, AgentVersion: version})
	if err != nil {
		t.Fatalf("SandboxArtifacts: %v", err)
	}
	return artifacts
}

// TestSandboxArtifactsGolden pins the SHA-256, size, mode and owner of every
// overlay artifact, plus the create-time env and required binaries.
// Regenerate deliberately with DEFENSECLAW_UPDATE_GOLDEN=1.
func TestSandboxArtifactsGolden(t *testing.T) {
	update := os.Getenv("DEFENSECLAW_UPDATE_GOLDEN") == "1"
	renderDir := os.Getenv(sandboxRenderDirEnv)
	for _, tc := range sandboxGoldenTargets {
		t.Run(tc.connector, func(t *testing.T) {
			artifacts := renderSandboxGolden(t, tc.provider, tc.version)
			if renderDir != "" {
				writeSandboxRendering(t, renderDir, tc.connector, artifacts.Files)
			}
			manifest := sandboxManifestOf(artifacts)
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
				t.Fatalf("read golden manifest (regenerate with DEFENSECLAW_UPDATE_GOLDEN=1): %v", err)
			}
			if bytes.Equal(want, encoded) {
				return
			}
			var wantManifest sandboxGoldenManifest
			if err := json.Unmarshal(want, &wantManifest); err != nil {
				t.Fatalf("parse %s: %v", manifestPath, err)
			}
			diffs := diffSandboxManifests(wantManifest, manifest)
			if len(diffs) == 0 {
				diffs = []string{"no entry changed: the binaries' order or count, or the manifest encoding, did"}
			}
			t.Errorf("%s rendering drifted from %s:\n  %s\n"+
				"The rendered bytes are not checked in: review the template change with git diff, or "+
				"write both revisions' renderings out with %s=<dir> and diff -ru the two trees. "+
				"Then regenerate with DEFENSECLAW_UPDATE_GOLDEN=1.",
				tc.connector, manifestPath, strings.Join(diffs, "\n  "), sandboxRenderDirEnv)
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

func TestRenderSandboxHookFilesRefusesConnectorsWithoutVariant(t *testing.T) {
	rt, err := resolveSandboxTarget("codex", SandboxRenderTarget{IngressPort: 18971, AgentVersion: "0.146.0"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"openclaw", "nosandbox", ""} {
		if _, err := renderSandboxHookFiles(name, rt); err == nil {
			t.Fatalf("connector %q rendered sandbox hooks without a sandbox template variant", name)
		}
	}
}

// TestSandboxHookScriptsCarryNoHostInputs: every sandbox hook runs under
// bash -p, reads no host address, token, fail mode or config, and posts only
// through the retrying sandbox transport.
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
			for _, forbidden := range []string{"127.0.0.1", "DEFENSECLAW_GATEWAY_TOKEN:-", "DEFENSECLAW_FAIL_MODE:-", ".hookcfg", `FAIL_MODE="open"`, ".hook-" + tc.connector + ".token"} {
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

// TestClaudeCodeSandboxDropInShape pins what the drop-in carries beyond the
// controls verifyClaudeCodeSandboxDropIn enforces: only keys reviewed against
// the Claude Code 2.1.156 settings schema (Claude drops a whole drop-in with
// one invalid field), the telemetry settings, and no provider selection
// (managed env outranks sandbox create --env, so a pin in the static image
// would override every run's provider; the manager pins it per sandbox).
func TestClaudeCodeSandboxDropInShape(t *testing.T) {
	var dropIn map[string]interface{}
	artifacts := renderSandboxGolden(t, &ClaudeCodeConnector{}, "2.1.156")
	if err := json.Unmarshal(sandboxFile(t, artifacts, ClaudeCodeSandboxDropInPath).Data, &dropIn); err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{
		"allowManagedHooksOnly": true, "skipDangerousModePermissionPrompt": true, "otelHeadersHelper": true,
		"hooks": true, "env": true, "sandbox": true,
		"apiKeyHelper": true, "awsAuthRefresh": true, "awsCredentialExport": true, "gcpAuthRefresh": true,
	}
	for key := range dropIn {
		if !allowed[key] {
			t.Errorf("drop-in carries unreviewed key %q", key)
		}
	}
	if sandbox, ok := dropIn["sandbox"].(map[string]interface{}); !ok || len(sandbox) != 1 {
		t.Errorf("drop-in sandbox = %#v, want exactly {\"enabled\": false}", dropIn["sandbox"])
	}
	env := dropIn["env"].(map[string]interface{})
	for key, want := range map[string]string{
		"DISABLE_AUTOUPDATER": "1", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://host.openshell.internal:18971",
		"OTEL_LOG_TOOL_CONTENT": "0", "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
	} {
		if got, ok := env[key].(string); !ok || got != want {
			t.Errorf("env[%s] = %#v, want %q", key, env[key], want)
		}
	}
	for _, key := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "DEFENSECLAW_FAIL_MODE", "ANTHROPIC_BASE_URL", "ANTHROPIC_API_URL",
		"ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_CUSTOM_HEADERS", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX"} {
		if _, present := env[key]; present {
			t.Errorf("env must not carry %s", key)
		}
	}
	if contract, ok := hookContractByID("claudecode", artifacts.HookContract); !ok || len(dropIn["hooks"].(map[string]interface{})) != len(contract.Events) {
		t.Fatalf("drop-in registers %d events for contract %s", len(dropIn["hooks"].(map[string]interface{})), artifacts.HookContract)
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
	mutate := func(fn func(map[string]interface{})) []byte {
		return tampered(t, good, json.Unmarshal, json.Marshal, fn)
	}
	env := func(d map[string]interface{}) map[string]interface{} { return d["env"].(map[string]interface{}) }
	assertTamperRejected(t, func(b []byte) error { return verifyClaudeCodeSandboxDropIn(b, rt) }, good, map[string][]byte{
		"disable-all-hooks":  mutate(func(d map[string]interface{}) { d["disableAllHooks"] = true }),
		"not-managed-only":   mutate(func(d map[string]interface{}) { d["allowManagedHooksOnly"] = false }),
		"missing-pretooluse": mutate(func(d map[string]interface{}) { delete(d["hooks"].(map[string]interface{}), "PreToolUse") }),
		"wrong-command": mutate(func(d map[string]interface{}) {
			d["hooks"].(map[string]interface{})["PreToolUse"] = []interface{}{map[string]interface{}{
				"matcher": "*", "hooks": []interface{}{map[string]interface{}{"type": "command", "command": "/tmp/x.sh", "timeout": 30}},
			}}
		}),
		"invalid-json":            []byte(`{"hooks":`),
		"shell-prefix-unpinned":   mutate(func(d map[string]interface{}) { delete(env(d), "CLAUDE_CODE_SHELL_PREFIX") }),
		"shell-prefix-set":        mutate(func(d map[string]interface{}) { env(d)["CLAUDE_CODE_SHELL_PREFIX"] = "/sandbox/wrap.sh" }),
		"shell-unpinned":          mutate(func(d map[string]interface{}) { delete(env(d), "SHELL") }),
		"simple-mode-on":          mutate(func(d map[string]interface{}) { env(d)["CLAUDE_CODE_SIMPLE"] = "1" }),
		"loader-set":              mutate(func(d map[string]interface{}) { env(d)["LD_PRELOAD"] = "/sandbox/x.so" }),
		"env-block-missing":       mutate(func(d map[string]interface{}) { delete(d, "env") }),
		"own-sandbox-unpinned":    mutate(func(d map[string]interface{}) { delete(d, "sandbox") }),
		"own-sandbox-on":          mutate(func(d map[string]interface{}) { d["sandbox"] = map[string]interface{}{"enabled": true} }),
		"own-sandbox-string":      mutate(func(d map[string]interface{}) { d["sandbox"] = map[string]interface{}{"enabled": "false"} }),
		"api-key-helper-unpinned": mutate(func(d map[string]interface{}) { delete(d, "apiKeyHelper") }),
		"aws-export-set":          mutate(func(d map[string]interface{}) { d["awsCredentialExport"] = "/sandbox/export.sh" }),
		"gcp-refresh-not-string":  mutate(func(d map[string]interface{}) { d["gcpAuthRefresh"] = false }),
	})
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
		return tampered(t, doc, toml.Unmarshal, toml.Marshal, fn)
	}
	type policy struct{ requirements, managed []byte }
	cases := map[string]policy{
		"hooks-feature-off":  {edit(requirements, func(c map[string]interface{}) { c["features"] = map[string]interface{}{"hooks": false} }), managed},
		"user-hooks-allowed": {edit(requirements, func(c map[string]interface{}) { c["allow_managed_hooks_only"] = false }), managed},
		"missing-event":      {edit(requirements, func(c map[string]interface{}) { delete(c["hooks"].(map[string]interface{}), "PreToolUse") }), managed},
		"wrong-managed-dir":  {edit(requirements, func(c map[string]interface{}) { c["hooks"].(map[string]interface{})["managed_dir"] = "/tmp" }), managed},
		"update-check-on":    {requirements, edit(managed, func(c map[string]interface{}) { c["check_for_update_on_startup"] = true })},
		"plugins-on":         {requirements, edit(managed, func(c map[string]interface{}) { c["features"].(map[string]interface{})["plugins"] = true })},
		"static-auth-header": {requirements, edit(managed, func(c map[string]interface{}) {
			exporter := c["otel"].(map[string]interface{})["exporter"].(map[string]interface{})["otlp-http"].(map[string]interface{})
			exporter["headers"].(map[string]interface{})["authorization"] = "Bearer x"
		})},
		"foreign-notify": {requirements, edit(managed, func(c map[string]interface{}) { c["notify"] = []interface{}{"/tmp/n.sh"} })},
	}
	// The commands Codex runs must not inherit what the launcher set for
	// Codex alone: the OTLP header variables carry the binding token.
	for _, key := range codexSandboxLauncherOnlyEnv {
		cases["shell-env-"+key] = policy{requirements, edit(managed, func(c map[string]interface{}) {
			delete(c["shell_environment_policy"].(map[string]interface{})["set"].(map[string]interface{}), key)
		})}
	}
	for name, tc := range cases {
		if err := verifyCodexSandboxPolicy(tc.requirements, tc.managed, rt, "openshell"); err == nil {
			t.Errorf("%s: tampered policy accepted", name)
		}
	}
}
