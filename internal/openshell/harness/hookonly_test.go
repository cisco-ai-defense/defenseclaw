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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

// harnessBinaries are the pinned binaries each launcher execs.
var harnessBinaries = map[string]string{
	"antigravity": "/usr/local/bin/agy",
	"claudecode":  "/usr/local/bin/claude",
	"codex":       "/usr/local/bin/codex",
	"hermes":      "/usr/local/bin/hermes",
	"omnigent":    "/usr/local/bin/omnigent",
	"openhands":   "/usr/local/bin/openhands",
}

// hookOnlyLauncher renders spec's launcher with the pinned binary replaced by
// a stub that records its argv and selected environment, and the canonical
// hook file (user-tier harnesses) by a scratch copy.
type hookOnlyLauncher struct {
	path, record, canonical string
}

func newHookOnlyLauncher(t *testing.T, spec *Spec) hookOnlyLauncher {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	l := hookOnlyLauncher{path: filepath.Join(dir, "launch"), record: filepath.Join(dir, "record"), canonical: filepath.Join(dir, "canonical.json")}
	stub := filepath.Join(dir, "stub")
	body := "#!/bin/bash\n{ printf 'ARG %s\\n' \"$@\"; for v in HERMES_DEFENSECLAW_API_KEY HERMES_ACCEPT_HOOKS HERMES_SAFE_MODE HERMES_MANAGED_DIR LLM_API_KEY OPENHANDS_SUPPRESS_BANNER" +
		" OMNIGENT_CONFIG OMNIGENT_CONFIG_HOME OMNIGENT_NO_UPDATE_CHECK OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN OMNIGENT_RUNNER_ENV_PASSTHROUGH HTTPS_PROXY; do printf 'ENV %s=%s\\n' \"$v\" \"${!v:-}\"; done; } >>" + l.record + "\n"
	if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(l.canonical, []byte(`{"reviewed":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	script := strings.ReplaceAll(string(spec.Launcher().Data), harnessBinaries[spec.Name], stub)
	for _, canonical := range []string{connector.OpenHandsSandboxCanonicalHooksPath, connector.AntigravitySandboxCanonicalHooksPath} {
		script = strings.ReplaceAll(script, canonical, l.canonical)
	}
	if err := os.WriteFile(l.path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return l
}

type launcherRun struct {
	exit   int
	output string
	record string
}

func (l hookOnlyLauncher) run(t *testing.T, dir string, env []string, args ...string) launcherRun {
	t.Helper()
	_ = os.Remove(l.record)
	cmd := exec.Command(l.path, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{"PATH=/usr/bin:/bin"}, env...)
	out, err := cmd.CombinedOutput()
	res := launcherRun{output: string(out)}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.exit = exitErr.ExitCode()
	default:
		t.Fatalf("launcher: %v", err)
	}
	rec, _ := os.ReadFile(l.record)
	res.record = string(rec)
	return res
}

func TestHookOnlyInstallStepsPinContract(t *testing.T) {
	cases := []struct {
		name    string
		spec    *Spec
		version string
		want    []string
		wantErr error
	}{
		{"hermes-pin", Hermes, "", []string{"hermes-agent==0.19.0", "uv python install '3.12.13'", "--exclude-newer '2026-09-27T00:00:00Z'", "UV_NO_CONFIG=1", "/opt/defenseclaw-harness/hermes"}, nil},
		{"hermes-below-contract", Hermes, "0.18.2", nil, ErrUnknownContract},
		{"hermes-above-contracts", Hermes, "0.22.0", nil, ErrUnknownContract},
		{"openhands-pin", OpenHands, "", []string{"'openhands==1.16.0'", "/opt/defenseclaw-harness/openhands"}, nil},
		{"openhands-below-contract", OpenHands, "1.11.0", nil, ErrUnknownContract},
		{"antigravity-pin", Antigravity, "", []string{"sha512sum -c", "1.2.12-5784551402897408", "aarch64)", "x86_64)", "/opt/defenseclaw-harness/antigravity"}, nil},
		{"antigravity-below-contract", Antigravity, "1.1.7", nil, ErrUnknownContract},
		{"antigravity-unpinned-build", Antigravity, "1.2.13", nil, nil},
		{"not-exact", Hermes, "latest", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			steps, err := tc.spec.InstallSteps(tc.version)
			if tc.want == nil {
				if err == nil {
					t.Fatal("install steps rendered for an unreviewed or unpinned version")
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
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Fatalf("install steps lack %q:\n%s", want, joined)
				}
			}
			if !strings.Contains(joined, "--version") || !strings.Contains(joined, "is not the pinned") {
				t.Fatalf("install steps must verify the pinned version:\n%s", joined)
			}
			probe := exec.Command("/bin/sh", "-n")
			probe.Stdin = strings.NewReader(joined)
			if out, err := probe.CombinedOutput(); err != nil {
				t.Fatalf("install step does not parse: %v\n%s", err, out)
			}
		})
	}
}

func TestHookOnlyLaunchArgv(t *testing.T) {
	cases := []struct {
		name string
		spec *Spec
		opts LaunchOptions
		want []string
	}{
		{"hermes-interactive-yolo", Hermes, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{HermesLauncherPath, "--yolo"}},
		{"hermes-headless-mantle", Hermes, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", CredentialProfile: profiles.BedrockMantleOpenAIID, Args: []string{"-m", "openai.gpt-oss-20b"}},
			[]string{HermesLauncherPath, "chat", "-q", "fix it", "-Q", "--yolo", "--provider", "defenseclaw", "-m", "openai.gpt-oss-20b"}},
		{"hermes-safe-anthropic", Hermes, LaunchOptions{Mode: Interactive, CredentialProfile: profiles.AnthropicID},
			[]string{HermesLauncherPath, "--provider", "anthropic"}},
		{"openhands-headless-yolo", OpenHands, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "p", CredentialProfile: profiles.OpenAIID},
			[]string{OpenHandsLauncherPath, "--headless", "--exit-without-confirmation", "-t", "p", "--always-approve", "--override-with-envs"}},
		{"openhands-interactive-safe", OpenHands, LaunchOptions{Mode: Interactive},
			[]string{OpenHandsLauncherPath}},
		{"antigravity-headless-yolo", Antigravity, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "p", CredentialProfile: profiles.GeminiID},
			[]string{AntigravityLauncherPath, "-p", "p", "--dangerously-skip-permissions"}},
		{"antigravity-interactive", Antigravity, LaunchOptions{Mode: Interactive, Args: []string{"--model", "gemini-3.1-pro"}},
			[]string{AntigravityLauncherPath, "--model", "gemini-3.1-pro"}},
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
	if _, err := Antigravity.LaunchArgv(LaunchOptions{Mode: Interactive, CredentialProfile: profiles.OpenAIID}); err == nil {
		t.Fatal("antigravity accepted an OpenAI credential profile")
	}
}

func TestHookOnlyEnv(t *testing.T) {
	env, err := Hermes.Env(EnvOptions{Artifacts: artifactsFor(t, Hermes), CredentialProfile: profiles.BedrockMantleOpenAIID, BedrockRegion: "us-west-2"})
	if err != nil {
		t.Fatal(err)
	}
	if env[connector.HermesSandboxProviderBaseURLEnv] != "https://bedrock-mantle.us-west-2.api.aws/v1" ||
		env["NO_PROXY"] != "bedrock-mantle.us-west-2.api.aws,host.openshell.internal" {
		t.Fatalf("hermes env = %v", env)
	}
	env, err = OpenHands.Env(EnvOptions{Artifacts: artifactsFor(t, OpenHands), CredentialProfile: profiles.BedrockMantleOpenAIID})
	if err != nil {
		t.Fatal(err)
	}
	if env["LLM_BASE_URL"] != "https://bedrock-mantle.us-east-1.api.aws/v1" || env["OPENHANDS_SUPPRESS_BANNER"] != "1" {
		t.Fatalf("openhands env = %v", env)
	}
	env, err = Antigravity.Env(EnvOptions{Artifacts: artifactsFor(t, Antigravity), CredentialProfile: profiles.GeminiID})
	if err != nil {
		t.Fatal(err)
	}
	if env["NO_PROXY"] != "generativelanguage.googleapis.com,host.openshell.internal" {
		t.Fatalf("antigravity env = %v", env)
	}
	for _, spec := range []*Spec{Hermes, OpenHands, Antigravity} {
		env, err := spec.Env(EnvOptions{Artifacts: artifactsFor(t, spec)})
		if err != nil {
			t.Fatal(err)
		}
		for key := range env {
			if strings.Contains(key, "API_KEY") || strings.Contains(key, "TOKEN") {
				t.Errorf("%s: secret-bearing variable %s must come from a provider, not --env", spec.Name, key)
			}
		}
	}
}

func TestHermesLauncher(t *testing.T) {
	l := newHookOnlyLauncher(t, Hermes)
	home := t.TempDir()
	key := "openshell:resolve:env:v4_BEDROCK_MANTLE_API_KEY"
	got := l.run(t, home, []string{"HOME=" + home, "BEDROCK_MANTLE_API_KEY=" + key, "HERMES_SAFE_MODE=1", "HERMES_MANAGED_DIR=/tmp/empty"}, "chat", "-q", "hi")
	if got.exit != 0 {
		t.Fatalf("exit %d: %s", got.exit, got.output)
	}
	for _, want := range []string{"ARG chat\nARG -q\nARG hi\n", "ENV HERMES_DEFENSECLAW_API_KEY=" + key + "\n", "ENV HERMES_ACCEPT_HOOKS=1\n", "ENV HERMES_SAFE_MODE=\n", "ENV HERMES_MANAGED_DIR=\n"} {
		if !strings.Contains(got.record, want) {
			t.Fatalf("hermes record lacks %q:\n%s", want, got.record)
		}
	}
	// An explicit key wins over the profile's.
	got = l.run(t, home, []string{"HOME=" + home, "HERMES_DEFENSECLAW_API_KEY=mine", "OPENAI_API_KEY=other"})
	if !strings.Contains(got.record, "ENV HERMES_DEFENSECLAW_API_KEY=mine\n") {
		t.Fatalf("record:\n%s", got.record)
	}
	got = l.run(t, home, []string{"HOME=" + home}, "chat", "--safe-mode", "-q", "hi")
	if got.exit != 2 || got.record != "" || !strings.Contains(got.output, "--safe-mode") {
		t.Fatalf("--safe-mode: exit %d record %q output %q", got.exit, got.record, got.output)
	}
}

func TestOpenHandsLauncher(t *testing.T) {
	l := newHookOnlyLauncher(t, OpenHands)
	home, project := t.TempDir(), t.TempDir()
	hooks := filepath.Join(home, ".openhands", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(hooks), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hooks, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	key := "openshell:resolve:env:v5_OPENAI_API_KEY"
	got := l.run(t, project, []string{"HOME=" + home, "OPENAI_API_KEY=" + key}, "--headless", "-t", "p")
	if got.exit != 0 {
		t.Fatalf("exit %d: %s", got.exit, got.output)
	}
	if raw, _ := os.ReadFile(hooks); string(raw) != `{"reviewed":true}`+"\n" {
		t.Fatalf("user hooks not restored: %q", raw)
	}
	if !strings.Contains(got.record, "ENV LLM_API_KEY="+key+"\n") || !strings.Contains(got.record, "ENV OPENHANDS_SUPPRESS_BANNER=1\n") {
		t.Fatalf("record:\n%s", got.record)
	}
	// Started in HOME, the working directory's hooks file is the user file.
	if got := l.run(t, home, []string{"HOME=" + home}); got.exit != 0 || got.record == "" {
		t.Fatalf("started in HOME: exit %d: %s", got.exit, got.output)
	}
	// A project hooks file would replace DefenseClaw's.
	if err := os.MkdirAll(filepath.Join(project, ".openhands"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, ".openhands", "hooks.json"), []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got = l.run(t, project, []string{"HOME=" + home})
	if got.exit != 2 || got.record != "" || !strings.Contains(got.output, "would replace DefenseClaw's hooks") {
		t.Fatalf("project hooks: exit %d record %q output %q", got.exit, got.record, got.output)
	}
	// ... also when OpenHands is pointed at it through OPENHANDS_WORK_DIR.
	elsewhere := t.TempDir()
	got = l.run(t, elsewhere, []string{"HOME=" + home, "OPENHANDS_WORK_DIR=" + project})
	if got.exit != 2 || got.record != "" {
		t.Fatalf("OPENHANDS_WORK_DIR project hooks: exit %d record %q", got.exit, got.record)
	}
	// A symlinked hooks directory is refused rather than written through.
	linked := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, ".openhands")); err != nil {
		t.Fatal(err)
	}
	got = l.run(t, elsewhere, []string{"HOME=" + linked})
	if got.exit != 2 || got.record != "" {
		t.Fatalf("symlinked ~/.openhands: exit %d record %q", got.exit, got.record)
	}
	// A missing canonical copy fails closed.
	if err := os.Remove(l.canonical); err != nil {
		t.Fatal(err)
	}
	got = l.run(t, elsewhere, []string{"HOME=" + home})
	if got.exit != 2 || got.record != "" {
		t.Fatalf("no canonical hooks: exit %d record %q", got.exit, got.record)
	}
}

func TestAntigravityLauncher(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	l := newHookOnlyLauncher(t, Antigravity)
	home, workspace := t.TempDir(), t.TempDir()
	settings := filepath.Join(home, ".gemini", "antigravity-cli", "settings.json")
	if err := os.MkdirAll(filepath.Dir(settings), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got := l.run(t, workspace, []string{"HOME=" + home, "GEMINI_API_KEY=openshell:resolve:env:v6_GEMINI_API_KEY"}, "-p", "hi")
	if got.exit != 0 || !strings.Contains(got.record, "ARG -p\nARG hi\n") {
		t.Fatalf("exit %d record %q: %s", got.exit, got.record, got.output)
	}
	if raw, _ := os.ReadFile(filepath.Join(home, ".gemini", "config", "hooks.json")); string(raw) != `{"reviewed":true}`+"\n" {
		t.Fatalf("user hooks not restored: %q", raw)
	}
	var cfg map[string]interface{}
	raw, _ := os.ReadFile(settings)
	if err := json.Unmarshal(raw, &cfg); err != nil || cfg["modelProvider"] != "gemini" || cfg["theme"] != "dark" {
		t.Fatalf("settings = %s", raw)
	}
	// Without a key the settings are left alone.
	if err := os.WriteFile(settings, []byte(`{"theme":"dark"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, workspace, []string{"HOME=" + home}); got.exit != 0 {
		t.Fatalf("exit %d", got.exit)
	}
	if raw, _ := os.ReadFile(settings); string(raw) != `{"theme":"dark"}` {
		t.Fatalf("settings rewritten without a key: %s", raw)
	}
	// Workspace hooks may add hooks but not reuse a DefenseClaw key.
	agents := filepath.Join(workspace, ".agents")
	if err := os.MkdirAll(agents, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(agents, "hooks.json"), []byte(`{"lint":{"PostToolUse":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, workspace, []string{"HOME=" + home}); got.exit != 0 {
		t.Fatalf("workspace hooks with their own keys refused: %s", got.output)
	}
	if err := os.WriteFile(filepath.Join(agents, "hooks.json"), []byte(`{"`+connector.AntigravitySandboxHookKeyPrefix+`pretooluse":{"PreToolUse":[]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := l.run(t, workspace, []string{"HOME=" + home}); got.exit != 2 || got.record != "" {
		t.Fatalf("workspace hooks reusing a DefenseClaw key: exit %d record %q", got.exit, got.record)
	}
}

func TestOmniGentLauncher(t *testing.T) {
	l := newHookOnlyLauncher(t, OmniGent)
	home := t.TempDir()
	token := "openshell:resolve:env:v3_DEFENSECLAW_SANDBOX_TOKEN"
	got := l.run(t, home, []string{"HOME=" + home, "DEFENSECLAW_EGRESS_URL=http://10.200.0.1:28772",
		"DEFENSECLAW_SANDBOX_TOKEN=" + token, "OMNIGENT_CONFIG=/tmp/elsewhere.yaml",
		"OMNIGENT_RUNNER_ENV_PASSTHROUGH=MY_TOOL_VAR"}, "run", "-p", "hi")
	if got.exit != 0 {
		t.Fatalf("exit %d: %s", got.exit, got.output)
	}
	for _, want := range []string{
		"ARG run\nARG -p\nARG hi\n",
		"ENV OMNIGENT_CONFIG=\n",
		"ENV OMNIGENT_CONFIG_HOME=" + connector.OmnigentSandboxConfigHome + "\n",
		"ENV OMNIGENT_NO_UPDATE_CHECK=1\n",
		"ENV OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN=" + token + "\n",
		// The runner that executes tool commands keeps the proxy settings,
		// after anything the user already passes through.
		"ENV OMNIGENT_RUNNER_ENV_PASSTHROUGH=MY_TOOL_VAR," + omnigentRunnerProxyPassthrough + "\n",
		"ENV HTTPS_PROXY=http://10.200.0.1:28772\n",
	} {
		if !strings.Contains(got.record, want) {
			t.Fatalf("omnigent record lacks %q:\n%s", want, got.record)
		}
	}
	// Without the egress proxy nothing extra is passed through, and a token
	// that is not a placeholder-shaped value is not copied.
	got = l.run(t, home, []string{"HOME=" + home, "DEFENSECLAW_SANDBOX_TOKEN=bad token"}, "run")
	for _, want := range []string{"ENV OMNIGENT_RUNNER_ENV_PASSTHROUGH=\n", "ENV HTTPS_PROXY=\n", "ENV OMNIGENT_DEFENSECLAW_SANDBOX_TOKEN=\n"} {
		if got.exit != 0 || !strings.Contains(got.record, want) {
			t.Fatalf("exit %d, record lacks %q:\n%s", got.exit, want, got.record)
		}
	}
}

func TestHookOnlyProbeVersionPatterns(t *testing.T) {
	for _, tc := range []struct {
		spec *Spec
		out  string
		want string
	}{
		{Hermes, "Hermes Agent v0.19.0 (2026.7.20)\n", "0.19.0"},
		{OpenHands, "OpenHands CLI 1.16.0\n", "1.16.0"},
		{Antigravity, "1.2.12\n", "1.2.12"},
	} {
		m := tc.spec.Probe().VersionRE.FindStringSubmatch(strings.TrimSpace(tc.out))
		if len(m) != 2 || m[1] != tc.want {
			t.Fatalf("%s version pattern on %q = %v", tc.spec.Name, tc.out, m)
		}
	}
	if !strings.Contains(Hermes.Probe().NetworkBinaries, "/opt/defenseclaw-harness/hermes/tools/hermes-agent/bin/python") {
		t.Fatalf("hermes network binary probe = %s", Hermes.Probe().NetworkBinaries)
	}
}
