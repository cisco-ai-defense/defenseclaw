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

package harness

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

func TestRegistry(t *testing.T) {
	if got := Names(); !reflect.DeepEqual(got, []string{"claudecode", "codex"}) {
		t.Fatalf("Names() = %v", got)
	}
	for _, name := range Names() {
		spec, ok := Get(name)
		if !ok || spec.Name != name || spec.Provider == nil {
			t.Fatalf("Get(%s) = %#v, %t", name, spec, ok)
		}
		if err := CheckContract(name, spec.DefaultVersion); err != nil {
			t.Fatalf("%s default pin %s: %v", name, spec.DefaultVersion, err)
		}
		if spec.LauncherPath() != LauncherDir+"/"+name+"-launch" || spec.Launcher().Path != spec.LauncherPath() {
			t.Fatalf("%s launcher path = %s", name, spec.LauncherPath())
		}
		if spec.Launcher().Owner != connector.SandboxOwnerRoot || spec.Launcher().Mode != 0o755 {
			t.Fatalf("%s launcher must be root-owned 0755", name)
		}
		if spec.InstallRoot() != InstallRootBase+"/"+name {
			t.Fatalf("%s install root = %s", name, spec.InstallRoot())
		}
		if len(spec.PreseedRefreshSteps()) == 0 || len(spec.UserCustomization()) == 0 {
			t.Fatalf("%s is missing preseed or customization metadata", name)
		}
		for _, c := range spec.UserCustomization() {
			if filepath.IsAbs(c.Host) || strings.Contains(c.Host, "..") || !strings.HasPrefix(c.Sandbox, connector.SandboxHomeDir+"/") {
				t.Fatalf("%s customization %#v escapes home", name, c)
			}
		}
	}
	if _, ok := Get("opencode"); ok {
		t.Fatal("phase 1 registers claudecode and codex only")
	}
}

func TestInstallStepsPinContract(t *testing.T) {
	cases := []struct {
		name    string
		spec    *Spec
		version string
		want    string
		wantErr error
	}{
		{"claude-base-relocate", ClaudeCode, "", "readlink -f /usr/local/bin/claude", nil},
		{"claude-npm-pin", ClaudeCode, "2.1.160", "@anthropic-ai/claude-code@2.1.160", nil},
		{"claude-below-contract", ClaudeCode, "2.1.100", "", ErrUnknownContract},
		{"codex-pin", Codex, "", "@openai/codex@0.146.0", nil},
		{"codex-base-0.117", Codex, "0.117.0", "", ErrUnknownContract},
		{"codex-not-exact", Codex, "latest", "", nil},
		{"codex-range", Codex, ">=0.146", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps, err := tc.spec.InstallSteps(tc.version)
			if tc.want == "" {
				if err == nil {
					t.Fatal("install steps rendered for an unreviewed version")
				}
				if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
					t.Fatalf("error = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			joined := ""
			for _, step := range steps {
				joined += step.Run + "\n"
			}
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("install steps lack %q:\n%s", tc.want, joined)
			}
			if !strings.Contains(joined, "--version") || !strings.Contains(joined, tc.spec.InstallRoot()) {
				t.Fatalf("install steps must verify the pinned version inside %s", tc.spec.InstallRoot())
			}
		})
	}
}

func TestLaunchArgv(t *testing.T) {
	cases := []struct {
		name string
		spec *Spec
		opts LaunchOptions
		want []string
	}{
		{"claude-interactive-yolo", ClaudeCode, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{ClaudeCodeLauncherPath, "--dangerously-skip-permissions"}},
		{"claude-interactive-safe", ClaudeCode, LaunchOptions{Mode: Interactive, Args: []string{"--model", "opus"}},
			[]string{ClaudeCodeLauncherPath, "--model", "opus"}},
		{"claude-headless", ClaudeCode, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix the tests", Args: []string{"--output-format", "json"}},
			[]string{ClaudeCodeLauncherPath, "--dangerously-skip-permissions", "-p", "fix the tests", "--output-format", "json"}},
		{"codex-interactive-yolo", Codex, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{CodexLauncherPath, "--dangerously-bypass-approvals-and-sandbox"}},
		{"codex-interactive-safe", Codex, LaunchOptions{Mode: Interactive},
			[]string{CodexLauncherPath, "-c", `sandbox_mode="danger-full-access"`, "-c", `approval_policy="on-request"`}},
		{"codex-headless-mantle", Codex, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "p", CredentialProfile: profiles.CodexBedrockMantleID, BedrockRegion: "us-west-2", Args: []string{"-m", "openai.gpt-oss-20b"}},
			[]string{CodexLauncherPath, "exec", "--skip-git-repo-check", "--dangerously-bypass-approvals-and-sandbox",
				"-c", `model_provider="mantle"`, "-c", `model_providers.mantle.name="mantle"`,
				"-c", `model_providers.mantle.base_url="https://bedrock-mantle.us-west-2.api.aws/v1"`,
				"-c", `model_providers.mantle.env_key="BEDROCK_MANTLE_API_KEY"`, "-c", `model_providers.mantle.wire_api="responses"`,
				"--disable", "multi_agent", "-c", `web_search="disabled"`, "-m", "openai.gpt-oss-20b", "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.spec.LaunchArgv(tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("argv =\n%q\nwant\n%q", got, tc.want)
			}
		})
	}
	for name, opts := range map[string]LaunchOptions{
		"headless-no-prompt": {Mode: Headless},
		"unknown-mode":       {Mode: "detached"},
		"foreign-profile":    {Mode: Interactive, CredentialProfile: profiles.OpenAIID},
	} {
		if _, err := ClaudeCode.LaunchArgv(opts); err == nil {
			t.Errorf("%s: launch argv rendered", name)
		}
	}
}

func artifactsFor(t *testing.T, spec *Spec) connector.SandboxArtifacts {
	t.Helper()
	a, err := spec.Provider.SandboxArtifacts(connector.SandboxRenderTarget{IngressPort: 18971, AgentVersion: spec.DefaultVersion})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestEnv(t *testing.T) {
	claude := artifactsFor(t, ClaudeCode)
	env, err := ClaudeCode.Env(EnvOptions{
		Artifacts:         claude,
		SandboxID:         "sb-1",
		SandboxName:       "dc-claudecode-myapp-7f3a",
		EgressProxyURL:    "http://b1:secret@host.openshell.internal:18972",
		CredentialProfile: profiles.ClaudeBedrockMantleID,
		BedrockRegion:     "us-east-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"DISABLE_AUTOUPDATER":                    "1",
		"DEFENSECLAW_SANDBOX_ID":                 "sb-1",
		"DEFENSECLAW_SANDBOX_NAME":               "dc-claudecode-myapp-7f3a",
		"HTTPS_PROXY":                            "http://b1:secret@host.openshell.internal:18972",
		"http_proxy":                             "http://b1:secret@host.openshell.internal:18972",
		"NODE_USE_ENV_PROXY":                     "1",
		"ANTHROPIC_BASE_URL":                     "https://bedrock-mantle.us-east-1.api.aws/anthropic",
		"CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS": "1",
		"NO_PROXY":                               "bedrock-mantle.us-east-1.api.aws,host.openshell.internal",
	}
	for key, value := range want {
		if env[key] != value {
			t.Errorf("env[%s] = %q, want %q", key, env[key], value)
		}
	}
	for key := range env {
		if strings.Contains(key, "TOKEN") || strings.Contains(key, "API_KEY") {
			t.Errorf("secret-bearing variable %s must come from a provider, not --env", key)
		}
	}

	strict, err := Codex.Env(EnvOptions{Artifacts: artifactsFor(t, Codex), CredentialProfile: profiles.OpenAIID})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := strict["HTTPS_PROXY"]; ok {
		t.Fatal("strict sandboxes (no proxy URL) must not get proxy env")
	}
	if strict["NO_PROXY"] != "api.openai.com,host.openshell.internal" {
		t.Fatalf("NO_PROXY = %q", strict["NO_PROXY"])
	}

	if _, err := Codex.Env(EnvOptions{Artifacts: claude}); err == nil {
		t.Fatal("foreign artifacts accepted")
	}
	if _, err := ClaudeCode.Env(EnvOptions{Artifacts: claude, EgressProxyURL: "socks5://x"}); err == nil {
		t.Fatal("non-http proxy URL accepted")
	}
	if _, err := ClaudeCode.Env(EnvOptions{Artifacts: claude, CredentialProfile: profiles.OpenAIID}); err == nil {
		t.Fatal("foreign credential profile accepted")
	}
}

func TestCredentialProfilesExistInCatalog(t *testing.T) {
	ids := map[string]bool{}
	for _, id := range profiles.IDs() {
		ids[id] = true
	}
	for _, name := range Names() {
		spec, _ := Get(name)
		for _, cp := range spec.CredentialProfiles("eu-west-1") {
			if !ids[cp.ProfileID] || len(cp.Hosts) == 0 {
				t.Fatalf("%s profile %#v", name, cp)
			}
			for _, h := range cp.Hosts {
				if strings.Contains(h, "{") {
					t.Fatalf("%s unresolved host %s", name, h)
				}
			}
		}
	}
}

// launcherHarness renders a launcher with the pinned binary replaced by a stub
// that records its argv, stdin and selected environment.
func launcherHarness(t *testing.T, spec *Spec, binary string) (launcher, record string) {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	record = filepath.Join(dir, "record")
	stub := filepath.Join(dir, "stub")
	body := "#!/bin/bash\n{ printf 'ARG %s\\n' \"$@\"; printf 'ENV CODEX_API_KEY=%s\\n' \"${CODEX_API_KEY:-}\"; if [ \"${1:-}\" = login ]; then printf 'STDIN %s\\n' \"$(cat)\"; fi; } >>" + record + "\n"
	if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(string(spec.Launcher().Data), binary, stub)
	launcher = filepath.Join(dir, "launch")
	if err := os.WriteFile(launcher, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return launcher, record
}

func TestClaudeLauncherRefreshesKeyApproval(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	launcher, record := launcherHarness(t, ClaudeCode, "/usr/local/bin/claude")
	home := t.TempDir()
	if err := os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{"hasCompletedOnboarding":true,"customApiKeyResponses":{"approved":["old"]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := "openshell:resolve:env:v13503686996004693124_ANTHROPIC_API_KEY"
	cmd := exec.Command(launcher, "--dangerously-skip-permissions", "-p", "hi")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "ANTHROPIC_API_KEY=" + key}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("launcher: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(filepath.Join(home, ".claude.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		HasCompletedOnboarding bool `json:"hasCompletedOnboarding"`
		CustomAPIKeyResponses  struct {
			Approved []string `json:"approved"`
			Rejected []string `json:"rejected"`
		} `json:"customApiKeyResponses"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.HasCompletedOnboarding || !reflect.DeepEqual(cfg.CustomAPIKeyResponses.Approved, []string{key[len(key)-20:], "old"}) || cfg.CustomAPIKeyResponses.Rejected == nil {
		t.Fatalf("config = %s", raw)
	}
	args, _ := os.ReadFile(record)
	if string(args) != "ARG --dangerously-skip-permissions\nARG -p\nARG hi\nENV CODEX_API_KEY=\n" {
		t.Fatalf("claude argv = %q", args)
	}
}

func TestCodexLauncherAddsRuntimeSettings(t *testing.T) {
	launcher, record := launcherHarness(t, Codex, "/usr/local/bin/codex")
	home := t.TempDir()
	run := func(env []string, args ...string) string {
		t.Helper()
		_ = os.Remove(record)
		cmd := exec.Command(launcher, args...)
		cmd.Dir = home
		cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + home}, env...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("launcher: %v\n%s", err, out)
		}
		out, _ := os.ReadFile(record)
		return string(out)
	}
	token := "openshell:resolve:env:v7_DEFENSECLAW_SANDBOX_TOKEN"
	got := run([]string{"DEFENSECLAW_SANDBOX_TOKEN=" + token, "OPENAI_API_KEY=sk-placeholder"}, "exec", "--skip-git-repo-check", "prompt")
	want := "ARG exec\n" +
		"ARG -c\nARG otel.exporter.otlp-http.headers.authorization=\"Bearer " + token + "\"\n" +
		"ARG -c\nARG otel.trace_exporter.otlp-http.headers.authorization=\"Bearer " + token + "\"\n" +
		"ARG -c\nARG otel.metrics_exporter.otlp-http.headers.authorization=\"Bearer " + token + "\"\n" +
		"ARG --skip-git-repo-check\nARG prompt\nENV CODEX_API_KEY=sk-placeholder\n"
	if got != want {
		t.Fatalf("exec argv:\n%s\nwant:\n%s", got, want)
	}

	got = run([]string{"OPENAI_API_KEY=sk-placeholder", "DEFENSECLAW_SANDBOX_TOKEN=bad\"token"}, "--dangerously-bypass-approvals-and-sandbox")
	if !strings.Contains(got, "ARG login\nARG --with-api-key\n") || !strings.Contains(got, "STDIN sk-placeholder\n") {
		t.Fatalf("interactive launch did not refresh the stored login: %s", got)
	}
	if strings.Contains(got, "otel.") {
		t.Fatalf("a malformed token must not reach the argv: %s", got)
	}
	if runtime.GOOS == "linux" {
		// Trust entries are written only under /work or /sandbox.
		if _, err := os.Stat(filepath.Join(home, ".codex", "config.toml")); err == nil {
			t.Fatal("trusted a directory outside /work and /sandbox")
		}
	}
}

func TestLaunchersParse(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	for _, name := range Names() {
		spec, _ := Get(name)
		cmd := exec.Command("/bin/bash", "-n")
		cmd.Stdin = strings.NewReader(string(spec.Launcher().Data))
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s launcher: %v\n%s", name, err, out)
		}
		if !strings.HasPrefix(string(spec.Launcher().Data), "#!/bin/bash -p\n") {
			t.Errorf("%s launcher must run under bash -p", name)
		}
		probe := exec.Command("/bin/sh", "-n")
		probe.Stdin = strings.NewReader(spec.Probe().NetworkBinaries)
		if out, err := probe.CombinedOutput(); err != nil {
			t.Errorf("%s network-binary probe: %v\n%s", name, err, out)
		}
	}
}

func TestProbeVersionPatterns(t *testing.T) {
	for _, tc := range []struct {
		spec *Spec
		out  string
		want string
	}{
		{ClaudeCode, "2.1.156 (Claude Code)\n", "2.1.156"},
		{Codex, "codex-cli 0.146.0\n", "0.146.0"},
	} {
		m := tc.spec.Probe().VersionRE.FindStringSubmatch(tc.out)
		if len(m) != 2 || m[1] != tc.want {
			t.Fatalf("%s version pattern on %q = %v", tc.spec.Name, tc.out, m)
		}
	}
}
