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
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
)

func TestRegistry(t *testing.T) {
	if got := Names(); !reflect.DeepEqual(got, []string{"amp", "claudecode", "codex", "copilot", "opencode"}) {
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
		switch spec.TamperTier {
		case connector.SandboxTamperTierManaged, connector.SandboxTamperTierUser:
		default:
			t.Fatalf("%s tamper tier %q", name, spec.TamperTier)
		}
		if a := artifactsFor(t, spec); a.TamperTier != spec.TamperTier {
			t.Fatalf("%s spec tier %s, rendered artifacts %s", name, spec.TamperTier, a.TamperTier)
		}
		switch spec.Verification.Status {
		case Verified, Unverified:
		default:
			t.Fatalf("%s verification status %q", name, spec.Verification.Status)
		}
		if strings.TrimSpace(spec.Verification.Reason) == "" {
			t.Fatalf("%s verification carries no evidence or reason", name)
		}
		if len(spec.CredentialProfiles("")) == 0 {
			t.Fatalf("%s has no credential profile", name)
		}
	}
	if _, ok := Get("cursor"); ok {
		t.Fatal("cursor has no sandbox harness")
	}
}

// TestTamperTiersAndVerification pins what each harness was proven with.
func TestTamperTiersAndVerification(t *testing.T) {
	for _, tc := range []struct {
		spec   *Spec
		tier   string
		status VerificationStatus
	}{
		{ClaudeCode, connector.SandboxTamperTierManaged, Verified},
		{Codex, connector.SandboxTamperTierManaged, Verified},
		// Managed registration, but other plugins load into the same process.
		{OpenCode, connector.SandboxTamperTierUser, Verified},
		{Copilot, connector.SandboxTamperTierManaged, Verified},
		{Amp, connector.SandboxTamperTierUser, Unverified},
	} {
		if tc.spec.TamperTier != tc.tier || tc.spec.Verification.Status != tc.status {
			t.Errorf("%s: tier %s status %s, want %s %s", tc.spec.Name, tc.spec.TamperTier, tc.spec.Verification.Status, tc.tier, tc.status)
		}
	}
	if !strings.Contains(Amp.Verification.Reason, "AMP_API_KEY") {
		t.Fatalf("Amp must say what is missing: %s", Amp.Verification.Reason)
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
		{"opencode-pin", OpenCode, "", "'opencode-ai@1.18.31'", nil},
		{"opencode-base-1.2.18", OpenCode, "1.2.18", "", ErrUnknownContract},
		{"opencode-above-range", OpenCode, "1.19.2", "", ErrUnknownContract},
		// Inside the contract, but DefenseClaw pinned no digests for it.
		{"opencode-unpinned-digest", OpenCode, "1.18.20", "", nil},
		{"copilot-pin", Copilot, "", "'@github/copilot@1.0.88'", nil},
		{"copilot-base-1.0.16", Copilot, "1.0.16", "", ErrUnknownContract},
		{"copilot-unpinned-digest", Copilot, "1.0.90", "", nil},
		{"amp-pin", Amp, "", "'@ampcode/cli@0.0.1785334225-g9abe75'", nil},
		{"amp-below-floor", Amp, "0.0.1785301270-g4f08a3", "", ErrUnknownContract},
		{"amp-no-build-suffix", Amp, "0.0.1785334225", "", nil},
		{"amp-latest", Amp, "latest", "", nil},
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

// TestNpmPinnedInstallChecksDigests pins the checks every npm-installed
// hook-only harness runs: the registry integrity before, the native sha256
// for both Linux architectures after, and the base image copy removed.
func TestNpmPinnedInstallChecksDigests(t *testing.T) {
	for _, tc := range []struct {
		spec *Spec
		pin  npmPin
		base string
	}{
		{OpenCode, openCodePin, "npm uninstall -g 'opencode-ai'"},
		{Copilot, copilotPin, "npm uninstall -g '@github/copilot'"},
		{Amp, ampPin, ""},
	} {
		t.Run(tc.spec.Name, func(t *testing.T) {
			steps, err := tc.spec.InstallSteps("")
			if err != nil {
				t.Fatal(err)
			}
			run := steps[0].Run
			for _, want := range []string{
				`npm view "$pkg" dist.integrity`,
				shellQuote(tc.pin.Integrity),
				`npm install -g --no-fund --no-audit --prefix "$root" "$pkg"`,
				"aarch64) bin=",
				"x86_64) bin=",
				shellQuote(tc.pin.Native["aarch64"].SHA256),
				shellQuote(tc.pin.Native["x86_64"].SHA256),
				`sha256sum "$bin"`,
				"ln -sfn \"$root/bin/" + tc.spec.Command + "\" /usr/local/bin/" + tc.spec.Command,
			} {
				if !strings.Contains(run, want) {
					t.Errorf("install step lacks %q:\n%s", want, run)
				}
			}
			if (tc.base != "") != strings.Contains(run, "npm uninstall -g") || (tc.base != "" && !strings.Contains(run, tc.base)) {
				t.Errorf("base image copy handling: %s", run)
			}
			if _, err := os.Stat("/bin/sh"); err == nil {
				cmd := exec.Command("/bin/sh", "-n")
				cmd.Stdin = strings.NewReader(run)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("install step does not parse: %v\n%s", err, out)
				}
			}
		})
	}
	if err := (npmPin{Package: "x", Integrity: "sha512-short", Native: map[string]npmNative{"aarch64": {Path: "bin/x", SHA256: strings.Repeat("a", 64)}}}).validate(); err == nil {
		t.Fatal("malformed integrity accepted")
	}
	if err := (npmPin{Package: "x", Integrity: openCodePin.Integrity, Native: map[string]npmNative{"aarch64": {Path: "../x", SHA256: strings.Repeat("a", 64)}}}).validate(); err == nil {
		t.Fatal("escaping native path accepted")
	}
	if _, err := openCodePin.installRun("/opt/x", "1.18.20", "opencode", ""); err == nil {
		t.Fatal("a release without pinned digests rendered")
	}
}

func TestCopilotInstallPreExtractsTheRootOwnedPackage(t *testing.T) {
	steps, err := Copilot.InstallSteps("")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`COPILOT_PKG_CACHE_HOME="$cache" /usr/local/bin/copilot --version`,
		"'GitHub Copilot CLI 1.0.88.'",
		"-name .extraction-complete",
		`chown -R root:root "$cache"; chmod -R go-w "$cache"`,
	} {
		if !strings.Contains(steps[0].Run, want) {
			t.Errorf("copilot install lacks %q", want)
		}
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
		{"opencode-interactive-yolo", OpenCode, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{OpenCodeLauncherPath, "--auto"}},
		{"opencode-interactive-safe", OpenCode, LaunchOptions{Mode: Interactive, Args: []string{"-m", "anthropic/claude-haiku-4-5"}},
			[]string{OpenCodeLauncherPath, "-m", "anthropic/claude-haiku-4-5"}},
		{"opencode-headless-mantle", OpenCode, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", CredentialProfile: profiles.OpenCodeBedrockMantleID, Args: []string{"--format", "json"}},
			[]string{OpenCodeLauncherPath, "run", "--auto", "--format", "json", "fix it"}},
		{"copilot-interactive-yolo", Copilot, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{CopilotLauncherPath, "--yolo"}},
		{"copilot-interactive-safe", Copilot, LaunchOptions{Mode: Interactive},
			[]string{CopilotLauncherPath}},
		{"copilot-headless-yolo", Copilot, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"--no-color"}},
			[]string{CopilotLauncherPath, "-p", "fix it", "--yolo", "--no-color"}},
		{"copilot-headless-safe", Copilot, LaunchOptions{Mode: Headless, Prompt: "fix it"},
			[]string{CopilotLauncherPath, "-p", "fix it", "--allow-all-tools"}},
		{"amp-interactive-yolo", Amp, LaunchOptions{Mode: Interactive, Yolo: true},
			[]string{AmpLauncherPath, "--dangerously-allow-all"}},
		{"amp-headless-yolo", Amp, LaunchOptions{Mode: Headless, Yolo: true, Prompt: "fix it", Args: []string{"-m", "high"}},
			[]string{AmpLauncherPath, "--dangerously-allow-all", "-m", "high", "--plugin-ready-timeout", "30", "-x", "fix it"}},
		{"amp-headless-safe", Amp, LaunchOptions{Mode: Headless, Prompt: "fix it"},
			[]string{AmpLauncherPath, "--plugin-ready-timeout", "30", "-x", "fix it"}},
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
		// The names the launchers export the proxy settings from.
		"DEFENSECLAW_EGRESS_URL":    "http://b1:secret@host.openshell.internal:18972",
		"DEFENSECLAW_EGRESS_BYPASS": "bedrock-mantle.us-east-1.api.aws,host.openshell.internal",
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
	for _, key := range []string{"HTTPS_PROXY", openshell.EnvEgressURL} {
		if _, ok := strict[key]; ok {
			t.Fatalf("strict sandboxes (no proxy URL) must not get %s", key)
		}
	}
	if strict["NO_PROXY"] != "api.openai.com,host.openshell.internal" || strict[openshell.EnvEgressBypass] != strict["NO_PROXY"] {
		t.Fatalf("NO_PROXY = %q, %s = %q", strict["NO_PROXY"], openshell.EnvEgressBypass, strict[openshell.EnvEgressBypass])
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

func TestHookOnlyHarnessEnv(t *testing.T) {
	proxy := "http://b1:secret@host.openshell.internal:18972"
	cases := []struct {
		spec    *Spec
		profile string
		want    map[string]string
		noProxy string
	}{
		{OpenCode, profiles.OpenCodeBedrockMantleID, map[string]string{
			"OPENCODE_DISABLE_AUTOUPDATE": "1",
			"OPENCODE_CONFIG_CONTENT":     strings.ReplaceAll(openCodeMantleConfig, bedrockHostToken, "bedrock-mantle.us-west-2.api.aws"),
		}, "bedrock-mantle.us-west-2.api.aws,host.openshell.internal"},
		{OpenCode, profiles.OpenCodeAnthropicID, map[string]string{"OPENCODE_DISABLE_AUTOUPDATE": "1"}, "api.anthropic.com,host.openshell.internal"},
		{Copilot, profiles.CopilotBedrockMantleID, map[string]string{
			"COPILOT_AUTO_UPDATE":         "false",
			"COPILOT_PKG_CACHE_HOME":      CopilotPackageCache,
			"COPILOT_PROVIDER_BASE_URL":   "https://bedrock-mantle.us-west-2.api.aws/anthropic",
			"COPILOT_PROVIDER_TYPE":       "anthropic",
			"COPILOT_OFFLINE":             "true",
			"COPILOT_PROVIDER_MODEL_ID":   "claude-haiku-4.5",
			"COPILOT_PROVIDER_WIRE_MODEL": "anthropic.claude-haiku-4-5",
		}, "bedrock-mantle.us-west-2.api.aws,host.openshell.internal"},
		{Copilot, profiles.CopilotGitHubID, map[string]string{"COPILOT_AUTO_UPDATE": "false"},
			"api.business.githubcopilot.com,api.enterprise.githubcopilot.com,api.github.com,api.githubcopilot.com,api.individual.githubcopilot.com,host.openshell.internal"},
		{Amp, profiles.AmpID, map[string]string{"AMP_SKIP_UPDATE_CHECK": "1"}, "ampcode.com,host.openshell.internal"},
	}
	for _, tc := range cases {
		t.Run(tc.spec.Name+"/"+tc.profile, func(t *testing.T) {
			env, err := tc.spec.Env(EnvOptions{Artifacts: artifactsFor(t, tc.spec), EgressProxyURL: proxy, CredentialProfile: tc.profile, BedrockRegion: "us-west-2"})
			if err != nil {
				t.Fatal(err)
			}
			for key, value := range tc.want {
				if env[key] != value {
					t.Errorf("env[%s] = %q, want %q", key, env[key], value)
				}
			}
			if env["NO_PROXY"] != tc.noProxy || env["HTTPS_PROXY"] != proxy || env[openshell.EnvEgressBypass] != tc.noProxy || env[openshell.EnvEgressURL] != proxy {
				t.Errorf("NO_PROXY %q HTTPS_PROXY %q %s %q %s %q", env["NO_PROXY"], env["HTTPS_PROXY"], openshell.EnvEgressBypass, env[openshell.EnvEgressBypass], openshell.EnvEgressURL, env[openshell.EnvEgressURL])
			}
			if tc.profile != profiles.CopilotGitHubID && env["COPILOT_OFFLINE"] == "" && tc.spec == Copilot {
				t.Error("a Copilot BYOK profile must run offline")
			}
			if tc.profile == profiles.CopilotGitHubID && env["COPILOT_OFFLINE"] != "" {
				t.Error("the GitHub-token profile cannot run offline")
			}
			for key := range env {
				if strings.Contains(key, "TOKEN") || strings.Contains(key, "API_KEY") {
					t.Errorf("secret-bearing variable %s must come from a provider, not --env", key)
				}
			}
		})
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal([]byte(openCodeMantleConfig), &cfg); err != nil {
		t.Fatalf("OpenCode Mantle config is not JSON: %v", err)
	}
	if !strings.Contains(openCodeMantleConfig, `"apiKey":"{env:BEDROCK_MANTLE_API_KEY}"`) {
		t.Fatal("OpenCode Mantle config must read the key placeholder at runtime")
	}
	for _, name := range []string{"opencode", "copilot", "amp"} {
		spec, _ := Get(name)
		for _, cp := range spec.CredentialProfiles("") {
			if (cp.ProfileID == profiles.CopilotGitHubID || cp.ProfileID == profiles.AmpID) != (cp.Unverified != "") {
				t.Errorf("%s: unverified = %q", cp.ProfileID, cp.Unverified)
			}
		}
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

// TestLaunchersExportEgressProxy pins that the launchers restore the proxy
// variables OpenShell strips from the sandbox environment, only from a
// well-formed http:// URL, and in place of the caller's.
func TestLaunchersExportEgressProxy(t *testing.T) {
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	const proxy = "http://dcx-0123456789abcdef:0123abcd@host.openshell.internal:18972"
	for _, tc := range []struct {
		spec   *Spec
		binary string
	}{{ClaudeCode, "/usr/local/bin/claude"}, {Codex, "/usr/local/bin/codex"}} {
		dir := t.TempDir()
		record := filepath.Join(dir, "record")
		stub := filepath.Join(dir, "stub")
		body := "#!/bin/bash\nprintf '%s|%s|%s|%s|%s\\n' \"${HTTPS_PROXY:-}\" \"${http_proxy:-}\" \"${NO_PROXY:-}\" \"${no_proxy:-}\" \"${NODE_USE_ENV_PROXY:-}\" >>" + record + "\n"
		if err := os.WriteFile(stub, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		launcher := filepath.Join(dir, "launch")
		if err := os.WriteFile(launcher, []byte(strings.ReplaceAll(string(tc.spec.Launcher().Data), tc.binary, stub)), 0o755); err != nil {
			t.Fatal(err)
		}
		run := func(env ...string) string {
			t.Helper()
			_ = os.Remove(record)
			cmd := exec.Command(launcher, "exec", "hi")
			cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + dir}, env...)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s launcher: %v\n%s", tc.spec.Name, err, out)
			}
			got, _ := os.ReadFile(record)
			return strings.TrimSpace(string(got))
		}
		bypass := "api.anthropic.com,host.openshell.internal"
		if got, want := run(openshell.EnvEgressURL+"="+proxy, openshell.EnvEgressBypass+"="+bypass),
			proxy+"|"+proxy+"|"+bypass+"|"+bypass+"|1"; got != want {
			t.Fatalf("%s exported %q, want %q", tc.spec.Name, got, want)
		}
		if got := run(openshell.EnvEgressURL + "=http://x y@host:1"); got != "||||" {
			t.Fatalf("%s exported a malformed proxy: %q", tc.spec.Name, got)
		}
		// The DefenseClaw proxy replaces one the caller's environment
		// carries; a malformed one leaves it alone.
		if got := run("HTTPS_PROXY=http://already:set@h:1", openshell.EnvEgressURL+"="+proxy); !strings.HasPrefix(got, proxy+"|") {
			t.Fatalf("%s kept the caller's proxy: %q", tc.spec.Name, got)
		}
		if got := run("HTTPS_PROXY=http://already:set@h:1", openshell.EnvEgressURL+"=http://x y@host:1"); !strings.HasPrefix(got, "http://already:set@h:1|") {
			t.Fatalf("%s replaced the caller's proxy with a malformed one: %q", tc.spec.Name, got)
		}
		if got := run(); got != "||||" {
			t.Fatalf("%s exported a proxy without one: %q", tc.spec.Name, got)
		}
	}
}

// runLauncher renders spec's launcher with the pinned binary replaced by a
// stub that records its argv and the named variables ("<unset>" when
// absent), runs it with env, and returns the exit code and the record.
func runLauncher(t *testing.T, spec *Spec, binary string, vars []string, env []string, args ...string) (int, string) {
	t.Helper()
	return runLauncherIn(t, spec, binary, "", vars, env, args...)
}

// runLauncherIn is runLauncher started in cwd (empty: the stub's temp
// dir, which is also HOME unless env sets it).
func runLauncherIn(t *testing.T, spec *Spec, binary, cwd string, vars []string, env []string, args ...string) (int, string) {
	t.Helper()
	if _, err := os.Stat("/bin/bash"); err != nil {
		t.Skip("/bin/bash is required")
	}
	dir := t.TempDir()
	record := filepath.Join(dir, "record")
	stub := "#!/bin/bash\n{ printf 'ARG %s\\n' \"$@\"; "
	for _, v := range vars {
		stub += "printf 'ENV " + v + "=%s\\n' \"${" + v + "-<unset>}\"; "
	}
	stub += "} >>" + record + "\n"
	stubPath := filepath.Join(dir, "stub")
	if err := os.WriteFile(stubPath, []byte(stub), 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(dir, "launch")
	if err := os.WriteFile(launcher, []byte(strings.ReplaceAll(string(spec.Launcher().Data), binary, stubPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(launcher, args...)
	cmd.Dir = dir
	if cwd != "" {
		cmd.Dir = cwd
	}
	cmd.Env = append([]string{"PATH=/usr/bin:/bin", "HOME=" + dir}, env...)
	out, err := cmd.CombinedOutput()
	code := 0
	if exitErr, ok := err.(*exec.ExitError); ok {
		code = exitErr.ExitCode()
	} else if err != nil {
		t.Fatalf("launcher: %v\n%s", err, out)
	}
	got, _ := os.ReadFile(record)
	return code, string(got) + string(out)
}

func TestOpenCodeLauncherRefusesPluginFreeRuns(t *testing.T) {
	vars := []string{"OPENCODE_PURE", "OPENCODE_TEST_MANAGED_CONFIG_DIR", "OPENCODE_TEST_HOME", "OPENCODE_DISABLE_AUTOUPDATE", "OPENCODE_CONFIG_CONTENT"}
	code, got := runLauncher(t, OpenCode, "/usr/local/bin/opencode", vars,
		[]string{"OPENCODE_PURE=1", "OPENCODE_TEST_MANAGED_CONFIG_DIR=/tmp/x", "OPENCODE_TEST_HOME=/tmp/y", "OPENCODE_CONFIG_CONTENT={}"}, "run", "--auto", "hi")
	want := "ARG run\nARG --auto\nARG hi\nENV OPENCODE_PURE=<unset>\nENV OPENCODE_TEST_MANAGED_CONFIG_DIR=<unset>\nENV OPENCODE_TEST_HOME=<unset>\nENV OPENCODE_DISABLE_AUTOUPDATE=1\nENV OPENCODE_CONFIG_CONTENT={}\n"
	if code != 0 || got != want {
		t.Fatalf("exit %d\n%s\nwant\n%s", code, got, want)
	}
	for _, args := range [][]string{{"--pure"}, {"run", "--pure", "hi"}, {"--pure=true"}} {
		code, got := runLauncher(t, OpenCode, "/usr/local/bin/opencode", nil, nil, args...)
		if code != 2 || strings.Contains(got, "ARG ") || !strings.Contains(got, "DefenseClaw policy plugin") {
			t.Fatalf("%v: exit %d %q", args, code, got)
		}
	}
}

func TestCopilotLauncherPinsThePackage(t *testing.T) {
	vars := []string{"COPILOT_AUTO_UPDATE", "COPILOT_PKG_CACHE_HOME", "COPILOT_CLI_DIST_DIR", "COPILOT_CLI_VERSION", "COPILOT_CACHE_HOME"}
	code, got := runLauncher(t, Copilot, "/usr/local/bin/copilot", vars,
		[]string{"COPILOT_AUTO_UPDATE=true", "COPILOT_PKG_CACHE_HOME=/sandbox/.cache", "COPILOT_CLI_DIST_DIR=/tmp/dist", "COPILOT_CLI_VERSION=9.9.9", "COPILOT_CACHE_HOME=/tmp/c"},
		"-p", "hi", "--yolo")
	want := "ARG -p\nARG hi\nARG --yolo\nENV COPILOT_AUTO_UPDATE=false\nENV COPILOT_PKG_CACHE_HOME=" + CopilotPackageCache +
		"\nENV COPILOT_CLI_DIST_DIR=<unset>\nENV COPILOT_CLI_VERSION=<unset>\nENV COPILOT_CACHE_HOME=<unset>\n"
	if code != 0 || got != want {
		t.Fatalf("exit %d\n%s\nwant\n%s", code, got, want)
	}
}

func TestAmpLauncherLoadsTheImagePlugin(t *testing.T) {
	vars := []string{"HOME", "XDG_CONFIG_HOME", "AMP_DISABLE_PLUGINS", "AMP_PLUGIN_URI", "AMP_PLUGIN_SOURCE_BASE64", "AMP_SETTINGS_FILE", "AMP_SKIP_UPDATE_CHECK"}
	code, got := runLauncher(t, Amp, "/usr/local/bin/amp", vars,
		[]string{"XDG_CONFIG_HOME=/tmp/x", "AMP_DISABLE_PLUGINS=1", "AMP_PLUGIN_URI=file:///tmp/p.ts", "AMP_PLUGIN_SOURCE_BASE64=eA==", "AMP_SETTINGS_FILE=/tmp/s.json"},
		"--dangerously-allow-all", "-x", "hi")
	want := "ARG --dangerously-allow-all\nARG -x\nARG hi\nENV HOME=/sandbox\nENV XDG_CONFIG_HOME=<unset>\nENV AMP_DISABLE_PLUGINS=<unset>\n" +
		"ENV AMP_PLUGIN_URI=<unset>\nENV AMP_PLUGIN_SOURCE_BASE64=<unset>\nENV AMP_SETTINGS_FILE=<unset>\nENV AMP_SKIP_UPDATE_CHECK=1\n"
	if code != 0 || got != want {
		t.Fatalf("exit %d\n%s\nwant\n%s", code, got, want)
	}
	for _, args := range [][]string{{"--settings-file", "/tmp/s.json"}, {"--settings-file=/tmp/s.json"}} {
		code, got := runLauncher(t, Amp, "/usr/local/bin/amp", nil, nil, args...)
		if code != 2 || strings.Contains(got, "ARG ") {
			t.Fatalf("%v: exit %d %q", args, code, got)
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
		{OpenCode, "1.18.31", "1.18.31"},
		// The probe keeps only [A-Za-z0-9 ._()+-] of the first line.
		{Copilot, "GitHub Copilot CLI 1.0.88.", "1.0.88"},
		{Amp, "0.0.1785334225-g9abe75 (released 2026-07-29T141025.000Z 1mo ago)", "0.0.1785334225-g9abe75"},
	} {
		m := tc.spec.Probe().VersionRE.FindStringSubmatch(tc.out)
		if len(m) != 2 || m[1] != tc.want {
			t.Fatalf("%s version pattern on %q = %v", tc.spec.Name, tc.out, m)
		}
	}
}

func TestBypassArgs(t *testing.T) {
	cases := []struct {
		name          string
		spec          *Spec
		args          []string
		kept, dropped []string
	}{
		{"claude flags", ClaudeCode,
			[]string{"--model", "opus", "--dangerously-skip-permissions", "--allow-dangerously-skip-permissions", "-p", "x"},
			[]string{"--model", "opus", "-p", "x"}, []string{"--dangerously-skip-permissions", "--allow-dangerously-skip-permissions"}},
		{"claude permission mode", ClaudeCode,
			[]string{"--permission-mode", "bypassPermissions", "--permission-mode=bypassPermissions", "--permission-mode", "plan"},
			[]string{"--permission-mode", "plan"}, []string{"--permission-mode", "bypassPermissions", "--permission-mode=bypassPermissions"}},
		{"claude after double dash", ClaudeCode,
			[]string{"--", "--dangerously-skip-permissions"}, []string{"--", "--dangerously-skip-permissions"}, nil},
		{"claude inline value on a bare flag", ClaudeCode,
			[]string{"--dangerously-skip-permissions=true"}, []string{"--dangerously-skip-permissions=true"}, nil},
		{"claude trailing valued flag", ClaudeCode,
			[]string{"--permission-mode"}, []string{"--permission-mode"}, nil},
		{"codex flags", Codex,
			[]string{"--dangerously-bypass-approvals-and-sandbox", "--yolo", "-m", "gpt"},
			[]string{"-m", "gpt"}, []string{"--dangerously-bypass-approvals-and-sandbox", "--yolo"}},
		{"codex approval", Codex,
			[]string{"-a", "never", "--ask-for-approval=never", "-a", "on-request", "-c", `approval_policy="never"`, "--config", "approval_policy = 'never'", "-c", `approval_policy="untrusted"`, "-c", `model="x"`},
			[]string{"-a", "on-request", "-c", `approval_policy="untrusted"`, "-c", `model="x"`},
			[]string{"-a", "never", "--ask-for-approval=never", "-c", `approval_policy="never"`, "--config", "approval_policy = 'never'"}},
		{"codex keeps claude flags", Codex,
			[]string{"--dangerously-skip-permissions"}, []string{"--dangerously-skip-permissions"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kept, dropped := tc.spec.BypassArgs(tc.args)
			if !reflect.DeepEqual(kept, tc.kept) || !reflect.DeepEqual(dropped, tc.dropped) {
				t.Fatalf("kept %q dropped %q, want %q / %q", kept, dropped, tc.kept, tc.dropped)
			}
		})
	}
	// Safe launches drop them; yolo launches pass everything through.
	safe, err := ClaudeCode.LaunchArgv(LaunchOptions{Mode: Interactive, Args: []string{"--dangerously-skip-permissions", "--model", "opus"}})
	if err != nil || !reflect.DeepEqual(safe, []string{ClaudeCodeLauncherPath, "--model", "opus"}) {
		t.Fatalf("safe argv = %q, %v", safe, err)
	}
	yolo, err := Codex.LaunchArgv(LaunchOptions{Mode: Interactive, Yolo: true, Args: []string{"-a", "never"}})
	if err != nil || !reflect.DeepEqual(yolo, []string{CodexLauncherPath, "--dangerously-bypass-approvals-and-sandbox", "-a", "never"}) {
		t.Fatalf("yolo argv = %q, %v", yolo, err)
	}
	safeCodex, err := Codex.LaunchArgv(LaunchOptions{Mode: Headless, Prompt: "p", Args: []string{"--dangerously-bypass-approvals-and-sandbox"}})
	if err != nil || strings.Contains(strings.Join(safeCodex, " "), "bypass") {
		t.Fatalf("safe codex argv = %q, %v", safeCodex, err)
	}
}

func TestCodexProfilesPinTheirProvider(t *testing.T) {
	openai, err := Codex.CredentialProfile(profiles.OpenAIID, "")
	if err != nil || openai.ModelProvider == nil || openai.ModelProvider.ID != connector.SandboxModelProviderOpenAI ||
		openai.ModelProvider.BaseURL != "https://api.openai.com/v1" {
		t.Fatalf("openai profile = %+v, %v", openai.ModelProvider, err)
	}
	mantle, err := Codex.CredentialProfile(profiles.CodexBedrockMantleID, "eu-west-1")
	if err != nil || mantle.ModelProvider == nil || mantle.ModelProvider.BaseURL != "https://bedrock-mantle.eu-west-1.api.aws/v1" {
		t.Fatalf("mantle profile = %+v, %v", mantle.ModelProvider, err)
	}
	// The session flags and the managed pin name the same provider.
	joined := strings.Join(mantle.LaunchArgs, " ")
	for _, want := range []string{`model_provider="mantle"`, `model_providers.mantle.base_url="` + mantle.ModelProvider.BaseURL + `"`, `model_providers.mantle.env_key="BEDROCK_MANTLE_API_KEY"`} {
		if !strings.Contains(joined, want) {
			t.Fatalf("mantle launch args %q lack %s", joined, want)
		}
	}
	// The base profile table is not mutated by region resolution.
	if again, _ := Codex.CredentialProfile(profiles.CodexBedrockMantleID, "us-west-2"); again.ModelProvider.BaseURL != "https://bedrock-mantle.us-west-2.api.aws/v1" {
		t.Fatalf("mantle base URL = %s", again.ModelProvider.BaseURL)
	}
	for _, cp := range ClaudeCode.CredentialProfiles("") {
		if cp.ModelProvider != nil {
			t.Fatalf("Claude Code profile %s pins a Codex provider", cp.ProfileID)
		}
	}
}

// TestClaudeLauncherMergesRunMCPServers pins that the launcher adds the
// per-run imported servers to the user-scope registry when the manager
// mounted them, and leaves ~/.claude.json alone when it did not.
func TestClaudeLauncherMergesRunMCPServers(t *testing.T) {
	if _, err := exec.LookPath("/usr/bin/jq"); err != nil {
		t.Skip("/usr/bin/jq is required")
	}
	launcher, _ := launcherHarness(t, ClaudeCode, "/usr/local/bin/claude")
	dir := t.TempDir()
	servers := filepath.Join(dir, "servers.json")
	script, err := os.ReadFile(launcher)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(script), connector.ClaudeCodeSandboxRunMCPServersPath) {
		t.Fatal("the launcher does not read the run MCP servers file")
	}
	if err := os.WriteFile(launcher, []byte(strings.ReplaceAll(string(script), connector.ClaudeCodeSandboxRunMCPServersPath, servers)), 0o755); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	cfg := filepath.Join(home, ".claude.json")
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	launch := func() map[string]interface{} {
		t.Helper()
		cmd := exec.Command(launcher, "-p", "hi")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("launcher: %v\n%s", err, out)
		}
		raw, err := os.ReadFile(cfg)
		if err != nil {
			t.Fatal(err)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%v: %s", err, raw)
		}
		return doc
	}
	write(cfg, `{"hasCompletedOnboarding":true,"mcpServers":{"mine":{"command":"a"},"github":{"command":"old"}}}`)
	if doc := launch(); doc["mcpServers"].(map[string]interface{})["github"].(map[string]interface{})["command"] != "old" {
		t.Fatalf("no run file, yet the registry changed: %v", doc)
	}
	write(servers, `{"mcpServers":{"github":{"type":"stdio","command":"npx","args":["srv"]}}}`)
	doc := launch()
	reg := doc["mcpServers"].(map[string]interface{})
	if reg["mine"] == nil || reg["github"].(map[string]interface{})["command"] != "npx" || doc["hasCompletedOnboarding"] != true {
		t.Fatalf("merged registry = %v", doc)
	}
	write(servers, `not json`)
	if doc := launch(); doc["mcpServers"].(map[string]interface{})["github"].(map[string]interface{})["command"] != "npx" {
		t.Fatalf("a malformed run file changed the registry: %v", doc)
	}
}
