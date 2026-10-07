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

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func stringSliceContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func TestGatewayConfigResolvedToken(t *testing.T) {
	t.Run("explicit token env", func(t *testing.T) {
		t.Setenv("MY_GATEWAY_TOKEN", "from-custom-env")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "should-not-use")
		g := GatewayConfig{TokenEnv: "MY_GATEWAY_TOKEN", Token: "inline"}
		if got := g.ResolvedToken(); got != "from-custom-env" {
			t.Errorf("got %q, want from-custom-env", got)
		}
	})
	t.Run("empty token env uses openclaw env", func(t *testing.T) {
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "from-dotenv-style")
		g := GatewayConfig{TokenEnv: "", Token: ""}
		if got := g.ResolvedToken(); got != "from-dotenv-style" {
			t.Errorf("got %q, want from-dotenv-style", got)
		}
	})
	t.Run("empty token env falls back to inline token", func(t *testing.T) {
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
		g := GatewayConfig{TokenEnv: "", Token: "plain"}
		if got := g.ResolvedToken(); got != "plain" {
			t.Errorf("got %q, want plain", got)
		}
	})
	t.Run("custom token env empty falls through to canonical", func(t *testing.T) {
		// Behavior change: pre-fix, an empty TokenEnv hard-blocked
		// the canonical/legacy checks, which diverged from Python's
		// resolved_token() and broke the very common config state
		// "TokenEnv=OPENCLAW_GATEWAY_TOKEN (stale default) + only
		// DEFENSECLAW_ populated in dotenv". Post-fix the canonical
		// → legacy → inline ladder ALWAYS runs after the named env
		// var miss, so Go and Python can never disagree on which
		// token is live. See ResolvedToken doc comment.
		t.Setenv("MY_GATEWAY_TOKEN", "")
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "from-canonical")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "from-legacy")
		g := GatewayConfig{TokenEnv: "MY_GATEWAY_TOKEN", Token: "inline"}
		if got := g.ResolvedToken(); got != "from-canonical" {
			t.Errorf("got %q, want from-canonical (canonical wins after named miss)", got)
		}
	})
	t.Run("custom token env empty falls through to inline when no env set", func(t *testing.T) {
		// With NO canonical / legacy populated, the chain bottoms
		// out at the inline g.Token — preserves the "honest
		// failure" path so an operator with a fully-empty
		// environment still gets a working literal value.
		t.Setenv("MY_GATEWAY_TOKEN", "")
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
		g := GatewayConfig{TokenEnv: "MY_GATEWAY_TOKEN", Token: "fallback"}
		if got := g.ResolvedToken(); got != "fallback" {
			t.Errorf("got %q, want fallback", got)
		}
	})
	t.Run("defenseclaw env takes priority over openclaw env", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "new-style")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "old-style")
		g := GatewayConfig{TokenEnv: "", Token: ""}
		if got := g.ResolvedToken(); got != "new-style" {
			t.Errorf("got %q, want new-style", got)
		}
	})
	t.Run("empty defenseclaw env falls back to openclaw env", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "")
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "legacy-token")
		g := GatewayConfig{TokenEnv: "", Token: ""}
		if got := g.ResolvedToken(); got != "legacy-token" {
			t.Errorf("got %q, want legacy-token", got)
		}
	})
	t.Run("stale OPENCLAW_ TokenEnv falls through to DEFENSECLAW_ canonical", func(t *testing.T) {
		// The exact user-reported scenario: bootstrap from a prior
		// 0.5.x install left token_env=OPENCLAW_GATEWAY_TOKEN in
		// config.yaml, but the rewritten dotenv only carries
		// DEFENSECLAW_GATEWAY_TOKEN. Pre-fix, Go's ResolvedToken
		// returned g.Token (empty) here while Python found the
		// canonical token via fall-through — every Go caller of
		// ResolvedToken outside the EnsureGatewayToken safety net
		// silently failed. Post-fix, Go matches Python.
		t.Setenv("OPENCLAW_GATEWAY_TOKEN", "")
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "real-live-token")
		g := GatewayConfig{TokenEnv: "OPENCLAW_GATEWAY_TOKEN", Token: ""}
		if got := g.ResolvedToken(); got != "real-live-token" {
			t.Errorf("got %q, want real-live-token (canonical fall-through)", got)
		}
	})
	t.Run("explicit token env wins over canonical fall-through", func(t *testing.T) {
		// Operator intent preserved: when the named env var IS
		// populated, it wins outright. The fall-through only
		// engages when the named var is empty.
		t.Setenv("MY_GATEWAY_TOKEN", "operator-pinned")
		t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "should-not-use")
		g := GatewayConfig{TokenEnv: "MY_GATEWAY_TOKEN", Token: "inline"}
		if got := g.ResolvedToken(); got != "operator-pinned" {
			t.Errorf("got %q, want operator-pinned", got)
		}
	})
}

func TestDefaultDataPath(t *testing.T) {
	dp := DefaultDataPath()
	if !filepath.IsAbs(dp) {
		t.Errorf("DefaultDataPath() returned non-absolute path: %s", dp)
	}
	if filepath.Base(dp) != DefaultDataDirName {
		t.Errorf("expected base dir %q, got %q", DefaultDataDirName, filepath.Base(dp))
	}
}

func TestDefaultDataPath_EnvOverride(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", "/custom/path/.defenseclaw")
	dp := DefaultDataPath()
	if dp != "/custom/path/.defenseclaw" {
		t.Errorf("DefaultDataPath() = %q, want /custom/path/.defenseclaw", dp)
	}
}

func TestConfigPath(t *testing.T) {
	cp := ConfigPath()
	if filepath.Base(cp) != DefaultConfigName {
		t.Errorf("expected config file %q, got %q", DefaultConfigName, filepath.Base(cp))
	}
}

func TestConfigPath_ExplicitEnvOverride(t *testing.T) {
	want := filepath.Join(t.TempDir(), "managed.yaml")
	t.Setenv("DEFENSECLAW_CONFIG", want)
	if got := ConfigPath(); got != want {
		t.Fatalf("ConfigPath() = %q, want %q", got, want)
	}
}

func TestLoadFromFile_ConfigOverrideKeepsRuntimeDataInDefenseClawHome(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	path := filepath.Join(configDir, "managed.yaml")
	t.Setenv(managed.ConfigPathEnv, path)
	t.Setenv("DEFENSECLAW_HOME", dataDir)
	if err := os.WriteFile(path, []byte("config_version: 9\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if cfg.DataDir != dataDir {
		t.Fatalf("DataDir = %q, want DEFENSECLAW_HOME %q", cfg.DataDir, dataDir)
	}
}

// TestLoadFromFileRefusesAnOlderConfigWithOneInstruction pins the single
// runtime answer for a released 0.8.x (config_version 7) file: one error that
// names the repair, whatever released keys the file carries. Nothing is
// half-loaded.
func TestLoadFromFileRefusesAnOlderConfigWithOneInstruction(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	raw := "config_version: 7\nsplunk:\n  enabled: true\notel:\n  enabled: true\n  endpoint: localhost:4317\n" +
		"audit_sinks:\n  - name: siem\n    kind: http_jsonl\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if cfg != nil || err == nil {
		t.Fatalf("LoadFromFile = (%v, %v), want a refusal", cfg, err)
	}
	for _, want := range []string{"config_version 7 is older than 8", "defenseclaw migrate"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("LoadFromFile error = %q, want it to contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "splunk") || strings.Contains(err.Error(), "audit_sinks") {
		t.Fatalf("LoadFromFile error = %q, want one version error, not a per-key legacy error", err)
	}
}

// TestValidateCandidateRefusesReleasedObservabilityKeysInCurrentFile pins that
// the canonical validator, which the config writers, the v9 migration and the
// gateway start run, names a released 0.8.x observability key left in a current
// file instead of ignoring it: the exporter or sink it described would
// otherwise silently stop. The schema alone enforces this; there is no
// per-key legacy check.
func TestValidateCandidateRefusesReleasedObservabilityKeysInCurrentFile(t *testing.T) {
	for _, body := range []string{
		"otel:\n  enabled: true\n",
		"audit_sinks:\n  - name: siem\n    kind: http_jsonl\n",
		"splunk:\n  enabled: true\n",
	} {
		raw := []byte("config_version: 9\nobservability: {}\n" + body)
		if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil {
			t.Fatalf("ValidateCandidate accepted %q; want a schema refusal", body)
		}
	}
}

func TestLoadFromFile_ManagedEnterpriseRejectsUntrustedConfigPath(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatalf("chmod untrusted config dir: %v", err)
		}
	}
	path := filepath.Join(dir, DefaultConfigName)
	data := []byte("config_version: 9\ndeployment_mode: managed_enterprise\ndata_dir: " + dir + "\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := LoadFromFile(path)
	if err == nil {
		t.Fatal("LoadFromFile succeeded for untrusted managed_enterprise config path")
	}
	if !strings.Contains(err.Error(), "managed_enterprise config trust check failed") {
		t.Fatalf("LoadFromFile error = %v, want managed trust check failure", err)
	}
}

func TestLoadFromFile_ManagedEnterpriseEnvPinRejectsUntrustedUnmanagedFile(t *testing.T) {
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatalf("chmod untrusted config dir: %v", err)
		}
	}
	path := filepath.Join(dir, DefaultConfigName)
	if err := os.WriteFile(path, []byte("config_version: 9\ndeployment_mode: unmanaged_byod\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, string(DeploymentModeManagedEnterprise))
	_, err := LoadFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "managed_enterprise config trust check failed") {
		t.Fatalf("LoadFromFile error = %v, want pre-parse managed trust failure", err)
	}
}

func TestDetectEnvironment(t *testing.T) {
	env := DetectEnvironment()
	switch runtime.GOOS {
	case "darwin":
		if env != EnvMacOS {
			t.Errorf("expected macos on darwin, got %s", env)
		}
	case "windows":
		if env != EnvWindows {
			t.Errorf("expected windows on windows, got %s", env)
		}
	case "linux":
		if env != EnvLinux && env != EnvDGXSpark {
			t.Errorf("expected linux or dgx-spark on linux, got %s", env)
		}
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
		return
	}

	if cfg.DataDir == "" {
		t.Error("DataDir is empty")
	}
	if got, want := cfg.AIDiscovery.ConfidencePolicyPath, filepath.Join(cfg.DataDir, "confidence.yaml"); got != want {
		t.Errorf("ai_discovery.confidence_policy_path = %q, want %q", got, want)
	}
	if cfg.AIDiscovery.RequireTrustedBinaryPaths {
		t.Error("ai_discovery.require_trusted_binary_paths = true, want false")
	}
	if cfg.AIDiscovery.LookupModelProvenanceOnline {
		t.Error("ai_discovery.lookup_model_provenance_online = true, want false")
	}
	if len(cfg.AIDiscovery.TrustedBinaryPrefixes) != 0 {
		t.Errorf("ai_discovery.trusted_binary_prefixes = %v, want empty", cfg.AIDiscovery.TrustedBinaryPrefixes)
	}
	if cfg.Claw.Mode != ClawOpenClaw {
		t.Errorf("expected mode %q, got %q", ClawOpenClaw, cfg.Claw.Mode)
	}
	if cfg.Scanners.SkillScanner.Binary != "skill-scanner" {
		t.Errorf("expected skill-scanner binary, got %q", cfg.Scanners.SkillScanner.Binary)
	}
	if cfg.Gateway.Port != 18789 {
		t.Errorf("expected gateway port 18789, got %d", cfg.Gateway.Port)
	}
	if cfg.Gateway.APIPort != 18970 {
		t.Errorf("expected gateway api_port 18970, got %d", cfg.Gateway.APIPort)
	}
	if cfg.Gateway.ConfigReload.Mode != "hot" {
		t.Errorf("expected gateway config_reload.mode hot, got %q", cfg.Gateway.ConfigReload.Mode)
	}
	if !cfg.Gateway.Watcher.Enabled {
		t.Error("expected gateway watcher enabled by default")
	}
	if !cfg.Gateway.Watcher.Skill.Enabled {
		t.Error("expected gateway watcher skill enabled by default")
	}
	if !cfg.Gateway.Watcher.Skill.TakeAction {
		t.Error("expected gateway watcher skill take_action=true by default")
	}
	if cfg.Watch.DebounceMs != 500 {
		t.Errorf("expected debounce 500ms, got %d", cfg.Watch.DebounceMs)
	}
	if !cfg.Watch.RescanEnabled {
		t.Error("expected rescan enabled by default")
	}
	if cfg.Watch.RescanIntervalMin != 60 {
		t.Errorf("expected rescan interval 60 min, got %d", cfg.Watch.RescanIntervalMin)
	}
	if !cfg.Watch.RescanContentGated {
		t.Error("expected rescan content-gated enabled by default")
	}
	if cfg.Scanners.PluginScanner != "defenseclaw" {
		t.Errorf("expected plugin scanner binary %q, got %q", "defenseclaw", cfg.Scanners.PluginScanner)
	}
}

func TestLoadFromFileEnablesOnlineModelProvenanceOnlyWhenConfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	raw := "config_version: 9\ndata_dir: " + dir + "\nai_discovery:\n  enabled: true\n  lookup_model_provenance_online: true\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if !cfg.AIDiscovery.LookupModelProvenanceOnline {
		t.Fatal("lookup_model_provenance_online was not loaded")
	}
}

func TestDefaultGatewayWatcherPluginConfig(t *testing.T) {
	cfg := DefaultConfig()
	p := cfg.Gateway.Watcher.Plugin
	if !p.Enabled {
		t.Errorf("Gateway.Watcher.Plugin.Enabled = %v, want true", p.Enabled)
	}
	if !p.TakeAction {
		t.Errorf("Gateway.Watcher.Plugin.TakeAction = %v, want true", p.TakeAction)
	}
	if len(p.Dirs) != 0 {
		t.Errorf("Gateway.Watcher.Plugin.Dirs = %v, want empty", p.Dirs)
	}
}

func TestDefaultConfigGuardrail(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Guardrail.Enabled {
		t.Error("guardrail should be disabled by default")
	}
	if cfg.Guardrail.Mode != "observe" {
		t.Errorf("expected guardrail mode %q, got %q", "observe", cfg.Guardrail.Mode)
	}
	if cfg.Guardrail.Port != 4000 {
		t.Errorf("expected guardrail port 4000, got %d", cfg.Guardrail.Port)
	}
	if cfg.Guardrail.ScannerMode != "both" {
		t.Errorf("expected guardrail scanner_mode %q, got %q", "both", cfg.Guardrail.ScannerMode)
	}
	if !cfg.Guardrail.HookSelfHeal {
		t.Error("expected guardrail.hook_self_heal enabled by default")
	}
	if cfg.Guardrail.HookSelfHealDebounceMs != 500 {
		t.Errorf("expected guardrail.hook_self_heal_debounce_ms 500, got %d", cfg.Guardrail.HookSelfHealDebounceMs)
	}
	if cfg.Guardrail.BlockMessage != "" {
		t.Errorf("expected empty block_message by default, got %q", cfg.Guardrail.BlockMessage)
	}
	if cfg.Guardrail.HILT.Enabled {
		t.Error("guardrail.hilt.enabled should default false")
	}
	if cfg.Guardrail.HILT.MinSeverity != "HIGH" {
		t.Errorf("guardrail.hilt.min_severity = %q, want HIGH", cfg.Guardrail.HILT.MinSeverity)
	}
	if cfg.Guardrail.Host != "" {
		t.Errorf("expected default guardrail host empty (Viper default), got %q", cfg.Guardrail.Host)
	}
	if got := cfg.Guardrail.EffectiveHost(); got != "127.0.0.1" {
		t.Errorf("EffectiveHost() = %q, want 127.0.0.1 when host is empty", got)
	}
	if !cfg.Guardrail.Judge.Injection {
		t.Error("expected judge.injection true by default")
	}
	if !cfg.Guardrail.Judge.PII {
		t.Error("expected judge.pii true by default")
	}
}

func TestValidateDeploymentMode_EmptyAllowed(t *testing.T) {
	if err := validateDeploymentMode(""); err != nil {
		t.Fatalf("validateDeploymentMode(empty) returned unexpected error: %v", err)
	}
}

func TestValidateDeploymentMode_Valid(t *testing.T) {
	for _, mode := range []string{
		string(DeploymentModeManagedEnterprise),
		string(DeploymentModeUnmanagedBYOD),
		string(DeploymentModeCICD),
		string(DeploymentModeSandboxed),
		string(DeploymentModeServer),
		string(DeploymentModeSaaS),
		"managed",
		"standalone",
		"ci",
		"edge",
	} {
		t.Run(mode, func(t *testing.T) {
			if err := validateDeploymentMode(mode); err != nil {
				t.Fatalf("validateDeploymentMode(%q) returned unexpected error: %v", mode, err)
			}
		})
	}
}

func TestValidateDeploymentMode_Invalid(t *testing.T) {
	if err := validateDeploymentMode("freeform"); err == nil {
		t.Fatal("expected validateDeploymentMode to reject free-form value")
	}
}

func TestManagedEnterpriseListenerBindingsModeMatrix(t *testing.T) {
	tests := []struct {
		name          string
		mode          string
		apiBind       string
		guardrailHost string
		guardrail     bool
		wantErr       string
		wantAPIBind   string
	}{
		{
			name:          "normal mode preserves explicit remote binds",
			mode:          string(DeploymentModeUnmanagedBYOD),
			apiBind:       "0.0.0.0",
			guardrailHost: "192.0.2.10",
			guardrail:     true,
			wantAPIBind:   "0.0.0.0",
		},
		{
			name:          "managed defaults stay loopback",
			mode:          string(DeploymentModeManagedEnterprise),
			guardrailHost: "127.0.0.1",
			guardrail:     true,
			wantAPIBind:   "127.0.0.1",
		},
		{
			name:          "managed API remains IPv4 with independent IPv6 guardrail",
			mode:          string(DeploymentModeManagedEnterprise),
			apiBind:       "127.0.0.1",
			guardrailHost: "[::1]",
			guardrail:     true,
			wantAPIBind:   "127.0.0.1",
		},
		{
			name:    "managed API IPv6 loopback rejected",
			mode:    string(DeploymentModeManagedEnterprise),
			apiBind: "::1",
			wantErr: "gateway API must bind to exact canonical 127.0.0.1",
		},
		{
			name:    "managed API localhost rejected",
			mode:    string(DeploymentModeManagedEnterprise),
			apiBind: "localhost",
			wantErr: "gateway API must bind to exact canonical 127.0.0.1",
		},
		{
			name:    "managed API alternate IPv4 loopback rejected",
			mode:    string(DeploymentModeManagedEnterprise),
			apiBind: "127.99.1.2",
			wantErr: "gateway API must bind to exact canonical 127.0.0.1",
		},
		{
			name:    "managed API whitespace spelling rejected",
			mode:    string(DeploymentModeManagedEnterprise),
			apiBind: " 127.0.0.1 ",
			wantErr: "gateway API must bind to exact canonical 127.0.0.1",
		},
		{
			name:    "managed API wildcard rejected",
			mode:    string(DeploymentModeManagedEnterprise),
			apiBind: "0.0.0.0",
			wantErr: "gateway API must bind to exact canonical 127.0.0.1",
		},
		{
			name:          "managed proxy wildcard rejected",
			mode:          string(DeploymentModeManagedEnterprise),
			apiBind:       "127.0.0.1",
			guardrailHost: "0.0.0.0",
			guardrail:     true,
			wantErr:       "guardrail proxy must bind to loopback",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DeploymentMode = test.mode
			cfg.Gateway.APIBind = test.apiBind
			cfg.Guardrail.Host = test.guardrailHost
			cfg.Guardrail.Enabled = test.guardrail
			err := validateManagedEnterpriseListenerBindings(cfg)
			if test.wantErr == "" && err != nil {
				t.Fatalf("validateManagedEnterpriseListenerBindings: %v", err)
			}
			if test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
			if test.wantErr == "" && cfg.Gateway.APIBind != test.wantAPIBind {
				t.Fatalf(
					"Gateway.APIBind = %q, want %q",
					cfg.Gateway.APIBind,
					test.wantAPIBind,
				)
			}
		})
	}
}

func TestManagedEnterpriseWindowsPeerAuthKnobsAreRejected(t *testing.T) {
	// Runs on all platforms via the same predicate; validator's
	// runtime.GOOS check means only the Windows branch enforces
	// rejection. On non-Windows we still exercise the happy path.
	cases := []struct {
		name          string
		mode          string
		team, sig, id []string
		wantOnWindows string // substring that must appear on Windows
	}{
		{name: "unmanaged_allows_anything", mode: "", team: []string{"team"}, wantOnWindows: ""},
		{name: "managed_empty_allowed", mode: "managed_enterprise", wantOnWindows: ""},
		{name: "managed_team_ids_windows_rejects", mode: "managed_enterprise", team: []string{"team"}, wantOnWindows: "managed.allowed_team_ids"},
		{name: "managed_signing_ids_windows_rejects", mode: "managed_enterprise", sig: []string{"sig"}, wantOnWindows: "managed.allowed_signing_ids"},
		{name: "managed_bundle_ids_windows_rejects", mode: "managed_enterprise", id: []string{"bundle"}, wantOnWindows: "managed.allowed_bundle_ids"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := DefaultConfig()
			cfg.DeploymentMode = c.mode
			cfg.Managed.AllowedTeamIDs = c.team
			cfg.Managed.AllowedSigningIDs = c.sig
			cfg.Managed.AllowedBundleIDs = c.id
			err := validateManagedEnterpriseWindowsPeerAuthKnobs(cfg)
			if runtime.GOOS != "windows" {
				if err != nil {
					t.Fatalf("non-windows: got err=%v, want nil (validator scoped to windows)", err)
				}
				return
			}
			if c.wantOnWindows == "" {
				if err != nil {
					t.Fatalf("windows: got err=%v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.wantOnWindows) {
				t.Fatalf("windows: err = %v, want substring %q", err, c.wantOnWindows)
			}
		})
	}
}

func TestIsLoopbackListenerHost(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "127.99.1.2", "::1", "[::1]", "localhost", " LOCALHOST "} {
		if !isLoopbackListenerHost(host) {
			t.Errorf("isLoopbackListenerHost(%q) = false, want true", host)
		}
	}
	for _, host := range []string{"", "0.0.0.0", "::", "192.0.2.10", "example.test", "localhost.example"} {
		if isLoopbackListenerHost(host) {
			t.Errorf("isLoopbackListenerHost(%q) = true, want false", host)
		}
	}
}

func TestValidateGatewayConfigReloadMode(t *testing.T) {
	for _, mode := range []string{"", "hot", "restart", "HOT", " Restart "} {
		t.Run(mode, func(t *testing.T) {
			if err := validateGatewayConfigReloadMode(mode); err != nil {
				t.Fatalf("validateGatewayConfigReloadMode(%q) returned unexpected error: %v", mode, err)
			}
		})
	}
	if err := validateGatewayConfigReloadMode("reload"); err == nil {
		t.Fatal("expected validateGatewayConfigReloadMode to reject reload")
	}
}

func TestLoadFromFileNormalizesGatewayConfigReloadMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, DefaultConfigName)
	raw := "config_version: 9\ndata_dir: " + dir + "\ngateway:\n  config_reload:\n    mode: ' Restart '\n"
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if got := cfg.Gateway.ConfigReload.Mode; got != "restart" {
		t.Fatalf("config reload mode = %q, want restart", got)
	}
}

func TestExpandPath(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input string
		want  string
	}{
		{"~/foo", filepath.Join(home, "foo")},
		{"/abs/path", "/abs/path"},
		{"relative", "relative"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := expandPath(tt.input)
			if got != tt.want {
				t.Errorf("expandPath(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestDedup(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{"empty", nil, []string{}},
		{"no dups", []string{"a", "b"}, []string{"a", "b"}},
		{"with dups", []string{"x", "y", "x", "z", "y"}, []string{"x", "y", "z"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dedup(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("dedup() len = %d, want %d", len(got), len(tt.want))
				return
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("dedup()[%d] = %q, want %q", i, v, tt.want[i])
				}
			}
		})
	}
}

func TestReadMCPServersFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	ocJSON := `{
		"mcp": {
			"servers": {
				"test-server": {
					"command": "npx",
					"args": ["-y", "test-server"],
					"url": "http://localhost:3000"
				},
				"another": {
					"url": "https://example.com/mcp"
				}
			}
		}
	}`
	ocPath := filepath.Join(tmpDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(ocJSON), 0o644); err != nil {
		t.Fatalf("write openclaw.json: %v", err)
	}

	servers, err := readMCPServersFromFile(ocPath)
	if err != nil {
		t.Fatalf("readMCPServersFromFile: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	byName := map[string]MCPServerEntry{}
	for _, s := range servers {
		byName[s.Name] = s
	}

	ts, ok := byName["test-server"]
	if !ok {
		t.Fatal("expected test-server entry")
	}
	if ts.Command != "npx" {
		t.Errorf("command = %q, want npx", ts.Command)
	}
	if ts.URL != "http://localhost:3000" {
		t.Errorf("url = %q, want http://localhost:3000", ts.URL)
	}

	another, ok := byName["another"]
	if !ok {
		t.Fatal("expected another entry")
	}
	if another.URL != "https://example.com/mcp" {
		t.Errorf("url = %q, want https://example.com/mcp", another.URL)
	}
}

func TestReadMCPServersFromFile_NoMCPBlock(t *testing.T) {
	tmpDir := t.TempDir()
	ocJSON := `{"agents": {"defaults": {"workspace": "/tmp"}}}`
	ocPath := filepath.Join(tmpDir, "openclaw.json")
	if err := os.WriteFile(ocPath, []byte(ocJSON), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	servers, err := readMCPServersFromFile(ocPath)
	if err != nil {
		t.Fatalf("readMCPServersFromFile: %v", err)
	}
	if len(servers) != 0 {
		t.Fatalf("expected 0 servers, got %d", len(servers))
	}
}

func TestReadMCPServersFromFile_MissingFile(t *testing.T) {
	servers, err := readMCPServersFromFile("/tmp/nonexistent/openclaw.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if len(servers) != 0 {
		t.Fatalf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseMCPServersJSON(t *testing.T) {
	data := []byte(`{
		"server-a": {"command": "npx", "args": ["-y", "srv"]},
		"server-b": {"url": "https://example.com/mcp", "transport": "sse"}
	}`)
	entries, err := parseMCPServersJSON(data)
	if err != nil {
		t.Fatalf("parseMCPServersJSON: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2, got %d", len(entries))
	}

	byName := map[string]MCPServerEntry{}
	for _, e := range entries {
		byName[e.Name] = e
	}
	if byName["server-b"].Transport != "sse" {
		t.Errorf("transport = %q, want sse", byName["server-b"].Transport)
	}
}

func TestParseMCPServersJSON_Empty(t *testing.T) {
	entries, err := parseMCPServersJSON([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0, got %d", len(entries))
	}
}

func TestSkillDirsForOpenClaw_NoOpenclawJSON(t *testing.T) {
	home := filepath.Join(t.TempDir(), "nonexistent-home")
	dirs := SkillDirsForOpenClaw(home)
	if len(dirs) < 2 {
		t.Fatalf("expected workspace and global skill dirs, got %v", dirs)
	}
	if want := filepath.Join(home, "workspace", "skills"); dirs[0] != want {
		t.Errorf("first dir = %q, want %q", dirs[0], want)
	}
	if want := filepath.Join(home, "skills"); dirs[len(dirs)-1] != want {
		t.Errorf("last dir = %q, want %q", dirs[len(dirs)-1], want)
	}
}

func TestSkillDirsForOpenClaw_WithOpenclawJSON(t *testing.T) {
	tmpDir := t.TempDir()
	workspaceDir := filepath.Join(tmpDir, "project-workspace")

	ocConfig := map[string]interface{}{
		"agents": map[string]interface{}{
			"defaults": map[string]interface{}{
				"workspace": workspaceDir,
			},
		},
		"skills": map[string]interface{}{
			"load": map[string]interface{}{
				"extraDirs": []string{"/tmp/extra-skills"},
			},
		},
	}

	data, _ := json.Marshal(ocConfig)
	ocPath := filepath.Join(tmpDir, "openclaw.json")
	if err := os.WriteFile(ocPath, data, 0o644); err != nil {
		t.Fatalf("write openclaw.json: %v", err)
	}

	dirs := SkillDirsForOpenClaw(tmpDir)

	found := false
	for _, d := range dirs {
		if d == "/tmp/extra-skills" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected /tmp/extra-skills in dirs: %v", dirs)
	}

	wsSkills := filepath.Join(workspaceDir, "skills")
	foundWs := false
	for _, d := range dirs {
		if d == wsSkills {
			foundWs = true
			break
		}
	}
	if !foundWs {
		t.Errorf("expected workspace/skills %q in dirs: %v", wsSkills, dirs)
	}
	if dirs[len(dirs)-1] != filepath.Join(tmpDir, "skills") {
		t.Errorf("expected global skill dir last, got %v", dirs)
	}
}

func TestConfig_InstalledSkillCandidates(t *testing.T) {
	cfg := &Config{
		Claw: ClawConfig{
			HomeDir:    "/tmp/test-home",
			ConfigFile: "/tmp/nonexistent/openclaw.json",
		},
	}

	tests := []struct {
		name string
		want string
	}{
		{"my-skill", "my-skill"},
		{"@org/my-skill", "my-skill"},
		{"scope/sub-skill", "sub-skill"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := cfg.InstalledSkillCandidates(tt.name)
			if len(candidates) == 0 {
				t.Fatal("expected at least one candidate")
			}
			for _, c := range candidates {
				if filepath.Base(c) != tt.want {
					t.Errorf("candidate base = %q, want %q", filepath.Base(c), tt.want)
				}
			}
		})
	}
}

func TestConfig_WorkspaceScopedOpenHandsPathsUsePinnedWorkspace(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	testenv.SetHome(t, home)
	workspace := filepath.Join(root, "repo")
	cfg := &Config{
		Claw: ClawConfig{
			Mode:         ClawMode("openhands"),
			WorkspaceDir: workspace,
		},
	}

	if got, want := cfg.ConnectorWorkspaceDir(), workspace; got != want {
		t.Fatalf("ConnectorWorkspaceDir() = %q, want %q", got, want)
	}
	if got, want := cfg.ConnectorHomeDir("openhands"), filepath.Join(workspace, ".openhands"); got != want {
		t.Fatalf("ConnectorHomeDir(openhands) = %q, want %q", got, want)
	}

	dirs := cfg.SkillDirsForConnector("openhands")
	if !stringSliceContains(dirs, filepath.Join(workspace, ".agents", "skills")) {
		t.Fatalf("OpenHands skill dirs = %v, want pinned workspace .agents/skills", dirs)
	}
	if !stringSliceContains(dirs, filepath.Join(workspace, ".openhands", "skills")) {
		t.Fatalf("OpenHands skill dirs = %v, want pinned workspace .openhands/skills", dirs)
	}
	if !stringSliceContains(dirs, filepath.Join(workspace, ".openhands", "microagents")) {
		t.Fatalf("OpenHands skill dirs = %v, want pinned workspace .openhands/microagents", dirs)
	}
	if !stringSliceContains(dirs, filepath.Join(home, ".openhands", "cache", "skills", "public-skills", "skills")) {
		t.Fatalf("OpenHands skill dirs = %v, want user public skills cache", dirs)
	}
}

func TestConfig_PluginDirs(t *testing.T) {
	home := filepath.Join(t.TempDir(), "test-oc-home")
	cfg := &Config{
		Claw: ClawConfig{HomeDir: home},
	}
	dirs := cfg.PluginDirs()
	if len(dirs) != 1 {
		t.Fatalf("expected 1 plugin dir, got %d", len(dirs))
	}
	want := filepath.Join(home, "extensions")
	if dirs[0] != want {
		t.Errorf("PluginDirs()[0] = %q, want %q", dirs[0], want)
	}
}

func TestDefaultConfigInspectLLM(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.InspectLLM.Timeout != 30 {
		t.Errorf("expected InspectLLM.Timeout=30, got %d", cfg.InspectLLM.Timeout)
	}
	if cfg.InspectLLM.MaxRetries != 3 {
		t.Errorf("expected InspectLLM.MaxRetries=3, got %d", cfg.InspectLLM.MaxRetries)
	}
	if cfg.InspectLLM.Provider != "" {
		t.Errorf("expected empty InspectLLM.Provider, got %q", cfg.InspectLLM.Provider)
	}
}

func TestDefaultConfigCiscoAIDefense(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.CiscoAIDefense.Endpoint != "https://us.api.inspect.aidefense.security.cisco.com" {
		t.Errorf("unexpected CiscoAIDefense.Endpoint: %q", cfg.CiscoAIDefense.Endpoint)
	}
	if cfg.CiscoAIDefense.APIKeyEnv != "CISCO_AI_DEFENSE_API_KEY" {
		t.Errorf("expected APIKeyEnv %q, got %q", "CISCO_AI_DEFENSE_API_KEY", cfg.CiscoAIDefense.APIKeyEnv)
	}
	if cfg.CiscoAIDefense.TimeoutMs != 3000 {
		t.Errorf("expected TimeoutMs=3000, got %d", cfg.CiscoAIDefense.TimeoutMs)
	}
}

func TestInspectLLMResolvedAPIKey_Direct(t *testing.T) {
	llm := &InspectLLMConfig{APIKey: "direct-key"}
	if got := llm.ResolvedAPIKey(); got != "direct-key" {
		t.Errorf("expected 'direct-key', got %q", got)
	}
}

func TestInspectLLMResolvedAPIKey_Env(t *testing.T) {
	t.Setenv("TEST_GO_LLM_KEY_XYZ", "env-key")
	llm := &InspectLLMConfig{APIKey: "fallback", APIKeyEnv: "TEST_GO_LLM_KEY_XYZ"}
	if got := llm.ResolvedAPIKey(); got != "env-key" {
		t.Errorf("expected env-key, got %q", got)
	}
}

func TestInspectLLMResolvedAPIKey_EnvUnset(t *testing.T) {
	os.Unsetenv("TEST_GO_LLM_NONEXIST_XYZ")
	llm := &InspectLLMConfig{APIKey: "fallback", APIKeyEnv: "TEST_GO_LLM_NONEXIST_XYZ"}
	if got := llm.ResolvedAPIKey(); got != "fallback" {
		t.Errorf("expected 'fallback', got %q", got)
	}
}

func TestInspectLLMResolvedAPIKey_Empty(t *testing.T) {
	llm := &InspectLLMConfig{}
	if got := llm.ResolvedAPIKey(); got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

func TestCiscoAIDefenseResolvedAPIKey_Direct(t *testing.T) {
	aid := &CiscoAIDefenseConfig{APIKey: "cisco-direct", APIKeyEnv: ""}
	if got := aid.ResolvedAPIKey(); got != "cisco-direct" {
		t.Errorf("expected 'cisco-direct', got %q", got)
	}
}

func TestCiscoAIDefenseResolvedAPIKey_Env(t *testing.T) {
	t.Setenv("TEST_GO_CISCO_KEY_XYZ", "cisco-env")
	aid := &CiscoAIDefenseConfig{APIKey: "fallback", APIKeyEnv: "TEST_GO_CISCO_KEY_XYZ"}
	if got := aid.ResolvedAPIKey(); got != "cisco-env" {
		t.Errorf("expected 'cisco-env', got %q", got)
	}
}

func TestGuardrailConfigNoCiscoField(t *testing.T) {
	cfg := DefaultConfig()
	_ = cfg.Guardrail.Mode
	_ = cfg.Guardrail.Port
	_ = cfg.CiscoAIDefense.Endpoint
}

func TestSkillScannerConfigNoLLMFields(t *testing.T) {
	cfg := DefaultConfig()
	sc := cfg.Scanners.SkillScanner
	if sc.Binary != "skill-scanner" {
		t.Errorf("expected 'skill-scanner', got %q", sc.Binary)
	}
	if sc.Policy != "quiet" || !sc.UseLLM {
		t.Errorf("expected the recommended default (policy quiet, judge on), got policy %q use_llm %v", sc.Policy, sc.UseLLM)
	}
	if !sc.Lenient {
		t.Error("expected default lenient=true")
	}
	_ = sc.UseLLM
	_ = sc.VirusTotalKey
}

func TestMCPScannerConfigNoLLMFields(t *testing.T) {
	cfg := DefaultConfig()
	mc := cfg.Scanners.MCPScanner
	if mc.Binary != "mcp-scanner" {
		t.Errorf("expected 'mcp-scanner', got %q", mc.Binary)
	}
	if mc.AnalyzersArg() != "" {
		t.Errorf("expected the auto analyzer set (no --analyzers), got %q", mc.Analyzers)
	}
	if mc.ScanPrompts {
		t.Error("expected default scan_prompts=false")
	}
	if mc.ScanResources {
		t.Error("expected default scan_resources=false")
	}
	if mc.ScanInstructions {
		t.Error("expected default scan_instructions=false")
	}
}

func TestOpenShellConfig_IsStandalone(t *testing.T) {
	tests := []struct {
		mode string
		want bool
	}{
		{"standalone", true},
		{"", false},
		{"cluster", false},
	}
	for _, tt := range tests {
		t.Run(tt.mode, func(t *testing.T) {
			oc := OpenShellConfig{Mode: tt.mode}
			if got := oc.IsStandalone(); got != tt.want {
				t.Errorf("IsStandalone() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOpenShellConfig_EffectiveSandboxHome(t *testing.T) {
	tests := []struct {
		home string
		want string
	}{
		{"", DefaultSandboxHome},
		{"/opt/sandbox", "/opt/sandbox"},
	}
	for _, tt := range tests {
		t.Run(tt.home, func(t *testing.T) {
			oc := OpenShellConfig{SandboxHome: tt.home}
			if got := oc.EffectiveSandboxHome(); got != tt.want {
				t.Errorf("EffectiveSandboxHome() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultConfig_OpenShellFields(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.OpenShell.Mode != "" {
		t.Errorf("expected legacy openshell.mode to be empty by default, got %q", cfg.OpenShell.Mode)
	}
	if cfg.OpenShell.SandboxHome != "" {
		t.Errorf("expected sandbox_home to be empty by default, got %q", cfg.OpenShell.SandboxHome)
	}
	if got := cfg.OpenShell.EffectiveSandboxHome(); got != DefaultSandboxHome {
		t.Errorf("EffectiveSandboxHome() = %q, want %q", got, DefaultSandboxHome)
	}
}

func TestGuardrailConfig_EffectiveHost(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"", "127.0.0.1"},
		{"localhost", "localhost"},
		{"127.0.0.1", "127.0.0.1"},
		{"10.200.0.1", "10.200.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			gc := GuardrailConfig{Host: tt.host}
			if got := gc.EffectiveHost(); got != tt.want {
				t.Errorf("EffectiveHost() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Config.ResolveLLM — unified LLM precedence (v5)
// ---------------------------------------------------------------------------
//
// v5 collapses inspect_llm + default_llm_* + guardrail.model onto a single
// top-level llm: block with per-component overrides. These tests pin the
// merge semantics so a regression here would silently reroute an operator's
// DEFENSECLAW_LLM_KEY to the wrong scanner.
//
// Precedence (high -> low) per field:
//  1. component override (scanners.mcp.llm, guardrail.llm, ...)
//  2. top-level c.LLM
//  3. DEFENSECLAW_LLM_MODEL env (model only)
//  4. legacy default_llm_* (temporary back-compat)
func TestResolveLLM(t *testing.T) {
	t.Run("empty path returns top-level as-is", func(t *testing.T) {
		c := &Config{LLM: LLMConfig{Provider: "openai", Model: "gpt-4o"}}
		got := c.ResolveLLM("")
		if got.Model != "gpt-4o" || got.Provider != "openai" {
			t.Fatalf("ResolveLLM(\"\") = %+v, want top-level echoed back", got)
		}
	})

	t.Run("component override beats top-level", func(t *testing.T) {
		c := &Config{
			LLM: LLMConfig{Provider: "openai", Model: "gpt-4o", APIKeyEnv: "DEFENSECLAW_LLM_KEY"},
		}
		c.Scanners.MCPScanner.LLM = LLMConfig{Model: "gpt-4o-mini", APIKeyEnv: "MCP_KEY"}
		got := c.ResolveLLM("scanners.mcp")
		if got.Model != "gpt-4o-mini" {
			t.Errorf("model: got %q, want gpt-4o-mini (override)", got.Model)
		}
		if got.Provider != "openai" {
			t.Errorf("provider: got %q, want openai (inherited)", got.Provider)
		}
		if got.APIKeyEnv != "MCP_KEY" {
			t.Errorf("api_key_env: got %q, want MCP_KEY (override)", got.APIKeyEnv)
		}
	})

	t.Run("empty override field inherits top-level", func(t *testing.T) {
		c := &Config{
			LLM: LLMConfig{Provider: "anthropic", Model: "claude-3-5-sonnet", BaseURL: "https://top"},
		}
		// Only the model is overridden; provider and base_url must inherit.
		c.Guardrail.LLM = LLMConfig{Model: "claude-3-5-haiku"}
		got := c.ResolveLLM("guardrail")
		if got.Provider != "anthropic" || got.BaseURL != "https://top" {
			t.Errorf("inherit failed: got provider=%q base_url=%q", got.Provider, got.BaseURL)
		}
		if got.Model != "claude-3-5-haiku" {
			t.Errorf("override failed: got model=%q", got.Model)
		}
	})

	t.Run("unknown path warns and returns top-level", func(t *testing.T) {
		c := &Config{LLM: LLMConfig{Model: "gpt-4o"}}
		got := c.ResolveLLM("scanners.does_not_exist")
		if got.Model != "gpt-4o" {
			t.Errorf("unknown path should degrade to top-level, got %+v", got)
		}
	})

	t.Run("instance_name override carries through", func(t *testing.T) {
		// instance_name is the ONLY signal that binds a role to a
		// custom-providers.json overlay entry. Dropping it from the
		// merge silently rerouted role-level custom-provider bindings
		// (e.g. guardrail.judge.llm.instance_name) to the inferred
		// public provider endpoint.
		c := &Config{
			LLM: LLMConfig{Model: "ollama/llama3.1"},
		}
		c.Guardrail.Judge.LLM = LLMConfig{Model: "internal-gpt/mock-judge", InstanceName: "internal-gpt"}
		got := c.ResolveLLM("guardrail.judge")
		if got.InstanceName != "internal-gpt" {
			t.Errorf("instance_name: got %q, want internal-gpt (override)", got.InstanceName)
		}
		if got.Model != "internal-gpt/mock-judge" {
			t.Errorf("model: got %q, want internal-gpt/mock-judge (override)", got.Model)
		}
	})

	t.Run("instance_name inherits from top-level when override empty", func(t *testing.T) {
		c := &Config{
			LLM: LLMConfig{Model: "internal-gpt/base", InstanceName: "internal-gpt"},
		}
		c.Guardrail.Judge.LLM = LLMConfig{Model: "internal-gpt/judge-model"}
		got := c.ResolveLLM("guardrail.judge")
		if got.InstanceName != "internal-gpt" {
			t.Errorf("instance_name: got %q, want internal-gpt (inherited)", got.InstanceName)
		}
	})

	t.Run("env fallback fills empty model", func(t *testing.T) {
		t.Setenv(DefenseClawLLMModelEnv, "openai/gpt-4o-from-env")
		c := &Config{}
		got := c.ResolveLLM("")
		if got.Model != "openai/gpt-4o-from-env" {
			t.Errorf("env fallback: got %q, want openai/gpt-4o-from-env", got.Model)
		}
	})

	t.Run("legacy default_llm_model back-compat", func(t *testing.T) {
		c := &Config{DefaultLLMModel: "openai/gpt-4o-legacy"}
		got := c.ResolveLLM("")
		if got.Model != "openai/gpt-4o-legacy" {
			t.Errorf("legacy back-compat: got %q, want openai/gpt-4o-legacy", got.Model)
		}
	})

	t.Run("legacy default_llm_api_key_env back-compat", func(t *testing.T) {
		c := &Config{DefaultLLMAPIKeyEnv: "LEGACY_KEY_ENV"}
		got := c.ResolveLLM("")
		if got.APIKeyEnv != "LEGACY_KEY_ENV" {
			t.Errorf("legacy api_key_env back-compat: got %q", got.APIKeyEnv)
		}
	})

	t.Run("env beats legacy default_llm_model", func(t *testing.T) {
		t.Setenv(DefenseClawLLMModelEnv, "env-wins")
		c := &Config{DefaultLLMModel: "legacy-loses"}
		got := c.ResolveLLM("")
		if got.Model != "env-wins" {
			t.Errorf("env should outrank legacy default_llm_model, got %q", got.Model)
		}
	})

	t.Run("scanners.plugin path resolves", func(t *testing.T) {
		c := &Config{LLM: LLMConfig{Model: "top"}}
		c.Scanners.PluginScannerLLM = LLMConfig{Model: "plugin-override"}
		got := c.ResolveLLM("scanners.plugin")
		if got.Model != "plugin-override" {
			t.Errorf("scanners.plugin: got %q, want plugin-override", got.Model)
		}
	})

	t.Run("guardrail.judge path resolves", func(t *testing.T) {
		c := &Config{LLM: LLMConfig{Model: "top"}}
		c.Guardrail.Judge.LLM = LLMConfig{Model: "judge-override"}
		got := c.ResolveLLM("guardrail.judge")
		if got.Model != "judge-override" {
			t.Errorf("guardrail.judge: got %q, want judge-override", got.Model)
		}
	})
}

func TestViperDefaultGuardrailHostIsEmpty(t *testing.T) {
	cfg := DefaultConfig()
	if cfg == nil {
		t.Fatal("DefaultConfig() returned nil")
		return
	}
	if cfg.Guardrail.Host != "" {
		t.Fatalf("Guardrail.Host = %q, want empty string (not localhost); non-empty default breaks EffectiveHost IPv4 fallback", cfg.Guardrail.Host)
	}
	if got := cfg.Guardrail.EffectiveHost(); got != "127.0.0.1" {
		t.Fatalf("EffectiveHost() = %q, want 127.0.0.1", got)
	}
}

// TestRecognizedLLMProvidersLockstep guards against drift between the
// Go-side recognizedLLMProviders set and the Python-side
// _RECOGNIZED_LLM_PROVIDERS in cli/defenseclaw/config.py. A missing
// entry on either side surfaces as a one-shot "unknown provider"
// warning even when the prefix is wired through Bifrost — exactly the
// regression we hit when "gemini-openai" was added to the gateway and
// the wizards but never to either recognized-providers map.
//
// The Bifrost gateway (internal/gateway/provider.go,
// internal/gateway/provider_bifrost.go) and both wizards
// (cli/defenseclaw/commands/cmd_setup.py, internal/tui/setup.go)
// already accept these prefixes; the recognized-providers maps must
// follow.
func TestRecognizedLLMProvidersLockstep(t *testing.T) {
	mustHave := []string{
		"openai", "anthropic", "azure", "gemini", "gemini-openai",
		"vertex_ai", "bedrock", "groq", "mistral", "cohere",
		"ollama", "vllm", "deepseek", "xai",
		"fireworks_ai", "perplexity", "huggingface", "replicate",
		"openrouter", "together_ai", "cerebras",
		"lm_studio", "lmstudio", "local",
	}
	for _, p := range mustHave {
		if _, ok := recognizedLLMProviders[p]; !ok {
			t.Errorf("recognizedLLMProviders missing %q — keep this set in lockstep with cli/defenseclaw/config.py:_RECOGNIZED_LLM_PROVIDERS", p)
		}
	}
}
