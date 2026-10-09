// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestResolveEnterpriseConfigProfiles(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		cfg     Config
		pinned  string
		want    string
		wantErr string
	}{
		{name: "secure client default keeps today's posture", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise"}, want: managed.ProfileSecureClient},
		{name: "darwin default", goos: "darwin", cfg: Config{DeploymentMode: "managed_enterprise"}, want: managed.ProfileSecureClient},
		{name: "linux default", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise"}, want: managed.ProfileStandalone},
		{name: "pinned standalone", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}, pinned: "standalone", want: managed.ProfileStandalone},
		{name: "pinned standalone needs a declared profile on windows", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise"}, pinned: "standalone", wantErr: "enterprise.profile must be set to standalone"},
		{name: "pinned standalone needs a declared profile on darwin", goos: "darwin", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Inspection: EnterpriseInspectionConfig{AIDefense: EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}}}}, pinned: "standalone", wantErr: "enterprise.profile must be set to standalone"},
		{name: "pinned standalone on linux may leave the profile unset", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise"}, pinned: "standalone", want: managed.ProfileStandalone},
		{name: "unmanaged ignores empty block", goos: "linux", cfg: Config{}, want: ""},
		{name: "unmanaged rejects block", goos: "linux", cfg: Config{Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{Mode: "auto"}}}, wantErr: "requires deployment_mode"},
		{name: "secure client rejects standalone knobs", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Coexistence: EnterpriseCoexistenceConfig{PerUserInstall: "block"}}}, wantErr: "apply only to the standalone profile"},
		{name: "standalone rejects inline key", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", CiscoAIDefense: CiscoAIDefenseConfig{APIKey: "k"}}, wantErr: "protected credential"},
		{name: "standalone requires credential name", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Inspection: EnterpriseInspectionConfig{AIDefense: EnterpriseAIDefenseConfig{Enabled: true, Credential: "../key"}}}}, wantErr: "protected credential name"},
		{name: "bad enum", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{Default: EnterpriseConnectorPolicy{ForeignHooks: "delete"}}}}, wantErr: "foreign_hooks"},
		{name: "bad home root", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{HomeRoots: []string{"/tmp"}}}}, wantErr: "home parent"},
		{name: "bad signer", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Trust: EnterpriseTrustConfig{AllowedSigners: []string{"abc"}}}}, wantErr: "thumbprint"},
		{name: "bad connector key", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"Bad Name": {}}}}}, wantErr: "connector name"},
		{name: "proxy with credentials", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Network: EnterpriseNetworkConfig{HTTPSProxy: "http://u:p@proxy.corp:3128"}}}, wantErr: "enterprise.network.https_proxy"},
		{name: "proxy without scheme", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Network: EnterpriseNetworkConfig{HTTPSProxy: "proxy.corp:3128"}}}, wantErr: "enterprise.network.https_proxy"},
		{name: "valid proxy", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Network: EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}}}, want: managed.ProfileStandalone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := resolveEnterpriseConfig(&cfg, tc.goos, tc.pinned)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveEnterpriseConfig() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEnterpriseConfig() unexpected error: %v", err)
			}
			if got := cfg.EnterpriseProfile(); got != tc.want {
				t.Fatalf("EnterpriseProfile() = %q, want %q", got, tc.want)
			}
			if got, want := cfg.DeclaredEnterpriseProfile(), managed.NormalizeEnterpriseProfile(tc.cfg.Enterprise.Profile); managed.IsManagedEnterprise(tc.cfg.DeploymentMode) && got != want {
				t.Fatalf("DeclaredEnterpriseProfile() = %q, want %q", got, want)
			}
		})
	}
}

func TestEnterprisePredicates(t *testing.T) {
	secureClient := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client"}}
	standalone := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	unmanaged := &Config{Enterprise: EnterpriseConfig{Profile: "standalone"}}
	if !secureClient.ManagedAIDOnly() || !secureClient.SecureClientIntegration() || secureClient.StandaloneEnterprise() {
		t.Fatal("secure client predicates wrong")
	}
	if standalone.ManagedAIDOnly() || standalone.SecureClientIntegration() || !standalone.StandaloneEnterprise() {
		t.Fatal("standalone predicates wrong")
	}
	if unmanaged.ManagedAIDOnly() || unmanaged.StandaloneEnterprise() || unmanaged.EnterpriseProfile() != "" {
		t.Fatal("unmanaged config must not report a profile")
	}
	var nilCfg *Config
	if nilCfg.ManagedAIDOnly() || nilCfg.StandaloneEnterprise() {
		t.Fatal("nil config predicates must be false")
	}
	unresolved := &Config{DeploymentMode: "managed_enterprise"}
	if !unresolved.ManagedAIDOnly() || unresolved.EnterpriseProfile() != managed.ProfileSecureClient {
		t.Fatal("a managed config built without the loader must keep the Secure Client posture")
	}
}

func TestMachinePolicyForDefaultsAreSecure(t *testing.T) {
	m := EnterpriseMachinePolicyConfig{
		Default: EnterpriseConnectorPolicy{AllowedHooks: []string{"sha256:" + strings.Repeat("A", 64)}},
		Connectors: map[string]EnterpriseConnectorPolicy{
			"cursor": {ForeignHooks: "report", AllowedHooks: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		},
	}
	codex := m.PolicyFor("Codex")
	if codex.Ownership != MachinePolicyOwnershipMerge || codex.ManagedHooksOnly != ManagedHooksOnlyEnforce ||
		codex.ForeignHooks != ForeignHooksRemove || codex.HigherPrecedenceSources != HigherPrecedenceFail {
		t.Fatalf("built-in defaults must be secure: %+v", codex)
	}
	cursor := m.PolicyFor("cursor")
	if cursor.ForeignHooks != ForeignHooksReport || cursor.ManagedHooksOnly != ManagedHooksOnlyEnforce {
		t.Fatalf("connector override not applied: %+v", cursor)
	}
	if len(cursor.AllowedHooks) != 2 || cursor.AllowedHooks[0] != strings.Repeat("a", 64) {
		t.Fatalf("allowed hooks not normalized and deduplicated: %v", cursor.AllowedHooks)
	}
}

func TestEnterpriseSelfUpdateDefault(t *testing.T) {
	if !(EnterpriseCoexistenceConfig{}).SelfUpdateDisabled() {
		t.Fatal("self update must be disabled by default on managed hosts")
	}
	off := false
	if (EnterpriseCoexistenceConfig{DisableSelfUpdate: &off}).SelfUpdateDisabled() {
		t.Fatal("explicit false must re-enable self update")
	}
}

func TestConfigV8SchemaAcceptsEnterpriseBlock(t *testing.T) {
	raw := []byte(`config_version: 8
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
  inspection:
    ai_defense:
      enabled: true
      credential: ai-defense-api-key
  enrollment:
    mode: auto
    exclude_users: [ubuntu]
    unenrolled_users: inspect
    home_roots: [/srv/home]
  machine_policy:
    default:
      ownership: merge
      managed_hooks_only: enforce
      foreign_hooks: remove
    connectors:
      cursor:
        foreign_hooks: report
  trust:
    mode: hash_pinned
  coexistence:
    per_user_install: migrate
    disable_self_update: true
  network:
    https_proxy: http://proxy.example.test:3128
`)
	validate := func(name string, data []byte) error {
		document, err := ParseV8YAML(name, data)
		if err != nil {
			return err
		}
		return validateV8Schema(name, document)
	}
	if err := validate("enterprise-v8.yaml", raw); err != nil {
		t.Fatalf("v8 schema rejected the enterprise block: %v", err)
	}
	for name, doc := range map[string]string{
		"unknown profile":    "config_version: 8\nenterprise:\n  profile: saas\n",
		"unknown key":        "config_version: 8\nenterprise:\n  api_key: secret\n",
		"bad credential":     "config_version: 8\nenterprise:\n  inspection:\n    ai_defense:\n      credential: ../x\n",
		"bad connector key":  "config_version: 8\nenterprise:\n  machine_policy:\n    connectors:\n      Bad Name: {}\n",
		"bad foreign policy": "config_version: 8\nenterprise:\n  machine_policy:\n    default:\n      foreign_hooks: delete\n",
		"bad signer":         "config_version: 8\nenterprise:\n  trust:\n    allowed_signers: [abc]\n",
	} {
		if err := validate(name+".yaml", []byte(doc)); err == nil {
			t.Errorf("v8 schema accepted %s", name)
		}
	}

	t.Run("claude version floor", func(t *testing.T) {
		validate := func(name, doc string) error {
			document, err := ParseV8YAML(name, []byte(doc))
			if err != nil {
				return err
			}
			return validateV8Schema(name, document)
		}
		const head = "config_version: 8\nenterprise:\n  machine_policy:\n"
		for name, doc := range map[string]string{
			"version_floor":         head + "    connectors:\n      claudecode:\n        version_floor: report\n",
			"with the other keys":   head + "    connectors:\n      claudecode:\n        ownership: merge\n        managed_hooks_only: preserve\n        allowed_hooks: [\"sha256:" + strings.Repeat("a", 64) + "\"]\n        version_floor: \"off\"\n",
			"other connectors keep": head + "    connectors:\n      codex:\n        ownership: verify_only\n",
		} {
			if err := validate(name+".yaml", doc); err != nil {
				t.Fatalf("v8 schema rejected %s: %v", name, err)
			}
		}
		for name, doc := range map[string]string{
			"bad mode":               head + "    connectors:\n      claudecode:\n        version_floor: strict\n",
			"unknown key":            head + "    connectors:\n      claudecode:\n        version_ceiling: enforce\n",
			"another connector":      head + "    connectors:\n      codex:\n        version_floor: enforce\n",
			"the default block":      head + "    default:\n      version_floor: enforce\n",
			"a top-level claudecode": head + "    claudecode:\n      version_floor: enforce\n",
		} {
			if err := validate(name+".yaml", doc); err == nil {
				t.Errorf("v8 schema accepted %s", name)
			}
		}
	})

	t.Run("copilot harness knobs", func(t *testing.T) {
		const head = "config_version: 8\nenterprise:\n  machine_policy:\n"
		for name, doc := range map[string]string{
			"both":     head + "    connectors:\n      copilot:\n        harness_preference: unmanaged\n        local_harness: retire\n        ownership: merge\n",
			"defaults": head + "    connectors:\n      copilot:\n        harness_preference: sdk\n        local_harness: govern\n",
		} {
			document, err := ParseV8YAML(name+".yaml", []byte(doc))
			if err == nil {
				err = validateV8Schema(name+".yaml", document)
			}
			if err != nil {
				t.Fatalf("v8 schema rejected %s: %v", name, err)
			}
		}
		for name, doc := range map[string]string{
			"bad value":         head + "    connectors:\n      copilot:\n        local_harness: remove\n",
			"another connector": head + "    connectors:\n      cursor:\n        harness_preference: sdk\n",
			"the default block": head + "    default:\n      local_harness: govern\n",
		} {
			document, err := ParseV8YAML(name+".yaml", []byte(doc))
			if err == nil {
				err = validateV8Schema(name+".yaml", document)
			}
			if err == nil {
				t.Errorf("v8 schema accepted %s", name)
			}
		}
		if err := validateConnectorPolicy("enterprise.machine_policy.connectors.cursor", EnterpriseConnectorPolicy{LocalHarness: "govern"}); err == nil {
			t.Error("validation accepted local_harness outside connectors.copilot")
		}
		m := EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"copilot": {HarnessPreference: "Unmanaged"}}}
		if m.CopilotHarnessPreference() != CopilotHarnessPreferenceUnmanaged || m.CopilotLocalHarness() != CopilotLocalHarnessGovern {
			t.Errorf("effective knobs = %q, %q", m.CopilotHarnessPreference(), m.CopilotLocalHarness())
		}
	})
}

// enterprise.trust.mode "" is the documented default (the hash_pinned
// minimum; Linux and macOS do not read the key), so the v8 schema and the
// loader accept it for a config shared across Linux, macOS and Windows. An
// unknown mode stays refused.
func TestEnterpriseTrustModeEmptyIsTheDefault(t *testing.T) {
	validate := func(name, doc string) error {
		document, err := ParseV8YAML(name, []byte(doc))
		if err != nil {
			return err
		}
		return validateV8Schema(name, document)
	}
	const empty = "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n  trust:\n    mode: \"\"\n"
	for _, goos := range []string{"linux", "darwin", "windows"} {
		t.Run(goos, func(t *testing.T) {
			if err := validate("trust-empty.yaml", empty); err != nil {
				t.Fatalf("v8 schema rejected enterprise.trust.mode \"\": %v", err)
			}
			if err := validate("trust-unknown.yaml", strings.Replace(empty, `mode: ""`, "mode: signed", 1)); err == nil {
				t.Fatal("v8 schema accepted an unknown enterprise.trust.mode")
			}
			cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
			if err := resolveEnterpriseConfig(&cfg, goos, ""); err != nil {
				t.Fatalf("an empty enterprise.trust.mode was rejected on %s: %v", goos, err)
			}
			bad := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Trust: EnterpriseTrustConfig{Mode: "signed"}}}
			if err := resolveEnterpriseConfig(&bad, goos, ""); err == nil || !strings.Contains(err.Error(), "enterprise.trust.mode") {
				t.Fatalf("unknown enterprise.trust.mode on %s: error = %v", goos, err)
			}
		})
	}
	// The runtime loader of the OS running the test accepts it end to end.
	path := filepath.Join(t.TempDir(), "config.yaml")
	if _, err := ParseCompileObservabilityV8(path, []byte(empty), ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()}); err != nil {
		t.Fatalf("compile rejected an empty enterprise.trust.mode: %v", err)
	}
	if _, err := LoadRuntimeV8InspectionCandidateFromBytes(path, []byte(empty)); err != nil {
		t.Fatalf("load rejected an empty enterprise.trust.mode: %v", err)
	}
}

func TestStandaloneDropsSecureClientSurfaces(t *testing.T) {
	standalone := &Config{
		DeploymentMode: "managed_enterprise",
		Enterprise:     EnterpriseConfig{Profile: "standalone"},
		CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "https://us.api.inspect.aidefense.security.cisco.com"},
	}
	if standalone.HasManagedAIDLogSink() {
		t.Fatal("standalone must not require the CMID-authenticated AI Defense sink")
	}
	if standalone.ManagedIPCEnabled() {
		t.Fatal("standalone has no Secure Client GUI and must not expose IPC")
	}
	secureClient := &Config{
		DeploymentMode: "managed_enterprise",
		CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "https://us.api.inspect.aidefense.security.cisco.com"},
	}
	if !secureClient.HasManagedAIDLogSink() || !secureClient.ManagedIPCEnabled() {
		t.Fatal("Secure Client surfaces must stay enabled for an unprofiled managed config")
	}
}

func TestManagedAIDDestinationSkippedForStandalone(t *testing.T) {
	plan := &ObservabilityV8Plan{}
	got, err := WithObservabilityV8ManagedAIDDestination(plan, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise",
		Profile:        "standalone",
		Endpoint:       "https://us.api.inspect.aidefense.security.cisco.com",
	})
	if err != nil || got != plan {
		t.Fatalf("standalone must leave the observability plan untouched: plan=%p got=%p err=%v", plan, got, err)
	}
}

func TestStandalonePolicyInputsMustBeAdministratorControlled(t *testing.T) {
	cfg := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	cfg.PolicyDir = filepath.Join(t.TempDir(), "absent")
	if err := validateManagedStandalonePolicyInputs(cfg); err != nil {
		t.Fatalf("absent policy dirs fall back to embedded rule packs: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("a root-owned temp dir is trusted; the negative case needs a non-root owner")
	}
	cfg.PolicyDir = t.TempDir()
	if err := validateManagedStandalonePolicyInputs(cfg); err == nil || !strings.Contains(err.Error(), "not administrator-controlled") {
		t.Fatalf("user-owned policy dir must be rejected, got %v", err)
	}
	// A guardrail profile's rule pack gets the same check as the base one.
	cfg.PolicyDir = filepath.Join(t.TempDir(), "absent")
	cfg.Guardrail.Profiles = map[string]GuardrailProfile{"contractors": {
		Connectors: map[string]PerConnectorGuardrailConfig{"codex": {RulePackDir: t.TempDir()}},
	}}
	if err := validateManagedStandalonePolicyInputs(cfg); err == nil ||
		!strings.Contains(err.Error(), "guardrail.profiles.contractors.connectors.codex.rule_pack_dir is not administrator-controlled") {
		t.Fatalf("user-owned profile rule pack must be rejected, got %v", err)
	}
	secureClient := &Config{DeploymentMode: "managed_enterprise", PolicyDir: t.TempDir()}
	if err := validateManagedStandalonePolicyInputs(secureClient); err != nil {
		t.Fatalf("Secure Client never consults local policy inputs: %v", err)
	}
}

// Outside the standalone layout the implicit rule pack follows policy_dir. On
// the Linux and macOS standalone layouts (a config read from the layout's
// config path) the implicit rule pack always names a pack that exists: the
// administrator's pack in policy_dir when that folder exists, otherwise the
// vendor default pack the lifecycle installs. An explicit rule_pack_dir is
// kept for the lifecycle to check.
func TestStandaloneLayoutImplicitRulePackExists(t *testing.T) {
	// Outside the layout the implicit pack follows policy_dir. The resolver
	// joins with the host separator, so the expected paths do too.
	dataDirPack := filepath.Join("/var/lib/defenseclaw", "policies", "guardrail", "default")
	cases := []struct {
		name    string
		goos    string
		policy  string
		pack    string
		profile string
		want    string
		// policyCleared: policy_dir names no Rego bundle, so the gateway
		// uses its built-in policy.
		policyCleared bool
	}{
		{name: "standalone implicit follows policy_dir", goos: "linux", policy: "/opt/defenseclaw/share/policies", pack: dataDirPack, want: filepath.Join("/opt/defenseclaw/share/policies", "guardrail", "default")},
		{name: "standalone explicit pack is kept", goos: "linux", policy: "/opt/defenseclaw/share/policies", pack: "/etc/defenseclaw/policies/guardrail/custom", want: "/etc/defenseclaw/policies/guardrail/custom"},
		{name: "standalone with data_dir policies is unchanged", goos: "linux", policy: "/var/lib/defenseclaw/policies", pack: dataDirPack, want: dataDirPack},
		{name: "secure client is unchanged", goos: "windows", policy: "/opt/defenseclaw/share/policies", pack: dataDirPack, profile: managed.ProfileSecureClient, want: dataDirPack},
		// Nothing stages a pack under a Windows data_dir, so the
		// implicit default selects the embedded packs.
		{name: "windows standalone implicit uses the embedded packs", goos: "windows", policy: "/var/lib/defenseclaw/policies", pack: dataDirPack, profile: managed.ProfileStandalone, want: "", policyCleared: true},
		{name: "windows standalone implicit follows an administrator policy_dir", goos: "windows", policy: "/opt/defenseclaw/share/policies", pack: dataDirPack, profile: managed.ProfileStandalone, want: filepath.Join("/opt/defenseclaw/share/policies", "guardrail", "default")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{DeploymentMode: "managed_enterprise", DataDir: "/var/lib/defenseclaw", PolicyDir: tc.policy}
			cfg.Guardrail.RulePackDir = tc.pack
			cfg.Enterprise.Profile = tc.profile
			if err := resolveEnterpriseConfig(&cfg, tc.goos, ""); err != nil {
				t.Fatal(err)
			}
			if cfg.Guardrail.RulePackDir != tc.want {
				t.Fatalf("rule_pack_dir = %q, want %q", cfg.Guardrail.RulePackDir, tc.want)
			}
			if (cfg.PolicyDir == "") != tc.policyCleared {
				t.Fatalf("policy_dir = %q, want cleared=%t", cfg.PolicyDir, tc.policyCleared)
			}
		})
	}

	if runtime.GOOS == "windows" {
		t.Skip("the Linux and macOS layout paths are not paths on Windows")
	}
	emptyPolicy := t.TempDir()
	seededPolicy := t.TempDir()
	seededPack := filepath.Join(seededPolicy, "guardrail", "default")
	if err := os.MkdirAll(seededPack, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		vendor := layout.VendorPolicyDir + "/guardrail/default"
		implicit := filepath.Join(layout.DataDir, "policies", "guardrail", "default")
		for _, tc := range []struct {
			name, policy, pack, want string
			declared                 bool
		}{
			{name: "absent admin pack falls back to the vendor pack", policy: emptyPolicy, pack: implicit, want: vendor},
			{name: "a missing policy_dir folder", policy: filepath.Join(emptyPolicy, "policies"), pack: implicit, want: vendor},
			{name: "an existing admin pack wins", policy: seededPolicy, pack: implicit, want: seededPack},
			{name: "policy_dir inside data_dir never supplies the pack", policy: filepath.Join(layout.DataDir, "policies"), pack: implicit, want: vendor},
			{name: "vendor policy_dir", policy: layout.VendorPolicyDir, pack: implicit, want: vendor},
			{name: "explicit pack is kept", policy: emptyPolicy, pack: filepath.Join(emptyPolicy, "guardrail", "custom"), want: filepath.Join(emptyPolicy, "guardrail", "custom")},
			{name: "an explicit pack inside data_dir is kept for the lifecycle to refuse", policy: filepath.Join(layout.DataDir, "policies"), pack: implicit, want: implicit, declared: true},
		} {
			t.Run(goos+"/"+tc.name, func(t *testing.T) {
				cfg := Config{
					DeploymentMode: "managed_enterprise",
					ConfigFilePath: layout.ConfigPath,
					DataDir:        layout.DataDir,
					PolicyDir:      tc.policy,
					Enterprise:     EnterpriseConfig{Profile: managed.ProfileStandalone},
				}
				cfg.Guardrail.RulePackDir = tc.pack
				cfg.rulePackDirDeclared = tc.declared
				if err := resolveEnterpriseConfig(&cfg, goos, ""); err != nil {
					t.Fatal(err)
				}
				if cfg.Guardrail.RulePackDir != tc.want {
					t.Fatalf("rule_pack_dir = %q, want %q", cfg.Guardrail.RulePackDir, tc.want)
				}
			})
		}
	}
	// Secure Client never gets a standalone rule pack default.
	secureClient := Config{DeploymentMode: "managed_enterprise", ConfigFilePath: "/opt/cisco/defenseclaw/etc/config.yaml", DataDir: "/opt/cisco/defenseclaw/runtime", PolicyDir: emptyPolicy}
	implicit := filepath.Join("/opt/cisco/defenseclaw/runtime", "policies", "guardrail", "default")
	secureClient.Guardrail.RulePackDir = implicit
	if err := resolveEnterpriseConfig(&secureClient, "darwin", ""); err != nil {
		t.Fatal(err)
	}
	if secureClient.Guardrail.RulePackDir != implicit {
		t.Fatalf("secure client rule_pack_dir = %q, want %q", secureClient.Guardrail.RulePackDir, implicit)
	}
}

// agent_prefixes applies to Linux and macOS, but one standalone config may
// be shared with Windows hosts, so every OS validates it the same way (Unix
// path semantics) whatever OS runs the check.
func TestEnterpriseAgentPrefixes(t *testing.T) {
	cases := map[string]string{
		"/opt/tools":         "",
		"/usr/local/company": "",
		"/opt/tools/":        "clean absolute path",
		"/opt//tools":        "clean absolute path",
		"relative/path":      "clean absolute path",
		"/opt/a:/opt/b":      "clean absolute path",
		"/opt/../home/x":     "clean absolute path",
		"/":                  "not an install prefix",
		"/home/alice/.npm":   "users can write",
		"/tmp/agents":        "users can write",
		"/Users/bob/tools":   "users can write",
	}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for prefix, wantErr := range cases {
			cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Enrollment: EnterpriseEnrollmentConfig{AgentPrefixes: []string{prefix}}}}
			err := resolveEnterpriseConfig(&cfg, goos, "")
			if wantErr == "" {
				if err != nil {
					t.Fatalf("%s: agent prefix %q rejected: %v", goos, prefix, err)
				}
				continue
			}
			if err == nil || !strings.Contains(err.Error(), wantErr) {
				t.Fatalf("%s: agent prefix %q error = %v, want %q", goos, prefix, err, wantErr)
			}
		}
	}
	// Secure Client keeps rejecting standalone-only enrollment knobs.
	cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Enrollment: EnterpriseEnrollmentConfig{AgentPrefixes: []string{"/opt/tools"}}}}
	if err := resolveEnterpriseConfig(&cfg, "windows", ""); err == nil {
		t.Fatal("secure_client accepted enrollment.agent_prefixes")
	}
}

func TestEnterpriseEnrollmentUIDMax(t *testing.T) {
	for _, tc := range []struct {
		min, max int
		wantErr  string
	}{
		{0, 0, ""}, {1000, 2000000000, ""}, {0, 70000, ""},
		{0, -1, "uid_max must not be negative"},
		{5000, 4000, "must not be below uid_min"},
	} {
		cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{UIDMin: tc.min, UIDMax: tc.max}}}
		err := resolveEnterpriseConfig(&cfg, "linux", "")
		if tc.wantErr == "" && err != nil {
			t.Fatalf("uid range %d-%d rejected: %v", tc.min, tc.max, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Fatalf("uid range %d-%d error = %v, want %q", tc.min, tc.max, err, tc.wantErr)
		}
	}
	document, err := ParseV8YAML("uid-max.yaml", []byte("config_version: 8\nenterprise:\n  enrollment:\n    uid_max: 2000000000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateV8Schema("uid-max.yaml", document); err != nil {
		t.Fatalf("v8 schema rejected enrollment.uid_max: %v", err)
	}
	cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Enrollment: EnterpriseEnrollmentConfig{UIDMax: 70000}}}
	if err := resolveEnterpriseConfig(&cfg, "windows", ""); err == nil {
		t.Fatal("secure_client accepted enrollment.uid_max")
	}
}

func claudeFloorPolicy(mode string) EnterpriseMachinePolicyConfig {
	return EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"claudecode": {VersionFloor: mode}}}
}

func TestClaudeVersionFloorDefaultsToEnforce(t *testing.T) {
	if got := (EnterpriseMachinePolicyConfig{}).ClaudeVersionFloor(); got != ClaudeVersionFloorEnforce {
		t.Fatalf("default version_floor = %q, want enforce", got)
	}
	if got := claudeFloorPolicy(" Report ").ClaudeVersionFloor(); got != ClaudeVersionFloorReport {
		t.Fatalf("version_floor = %q, want report", got)
	}
	// Other claudecode keys leave the floor at its default, and the floor
	// leaves them at theirs.
	m := EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"claudecode": {Ownership: "verify_only"}}}
	if got := m.ClaudeVersionFloor(); got != ClaudeVersionFloorEnforce {
		t.Fatalf("version_floor = %q, want enforce", got)
	}
	if got := claudeFloorPolicy("off").PolicyFor("claudecode"); got.Ownership != MachinePolicyOwnershipMerge || got.ManagedHooksOnly != ManagedHooksOnlyEnforce {
		t.Fatalf("version_floor changed the other claudecode keys: %+v", got)
	}
}

// enterprise.machine_policy.windows_wsl: defaults, the schema, the loader and
// the standalone-only rule.
func TestWindowsWSLPolicyValidation(t *testing.T) {
	if got := (EnterpriseMachinePolicyConfig{}).WSL(); got != (EnterpriseWindowsWSLPolicy{AgentSessions: "block", Platform: "leave", EditorSettings: "repair", ClaudeDesktopKey: "merge"}) {
		t.Fatalf("defaults: %+v", got)
	}
	const head = "config_version: 8\nenterprise:\n  machine_policy:\n    windows_wsl:\n"
	for doc, ok := range map[string]bool{
		head + "      agent_sessions: allow\n      platform: disable\n      editor_settings: report\n      claude_desktop_key: create\n": true,
		head + "      platform: off\n":    false,
		head + "      codex_app: block\n": false,
	} {
		document, err := ParseV8YAML("wsl.yaml", []byte(doc))
		if err == nil {
			err = validateV8Schema("wsl.yaml", document)
		}
		if (err == nil) != ok {
			t.Errorf("schema on %q: %v", doc, err)
		}
	}
	managedConfig := func(w EnterpriseWindowsWSLPolicy, profile string) Config {
		return Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: profile, MachinePolicy: EnterpriseMachinePolicyConfig{WindowsWSL: w}}}
	}
	good := managedConfig(EnterpriseWindowsWSLPolicy{Platform: "disable"}, "standalone")
	if err := resolveEnterpriseConfig(&good, "windows", ""); err != nil {
		t.Fatalf("valid windows_wsl rejected: %v", err)
	}
	bad := managedConfig(EnterpriseWindowsWSLPolicy{EditorSettings: "delete"}, "standalone")
	if err := resolveEnterpriseConfig(&bad, "windows", ""); err == nil || !strings.Contains(err.Error(), "enterprise.machine_policy.windows_wsl.editor_settings") {
		t.Fatalf("a bad knob must be rejected by name, got %v", err)
	}
	secureClient := managedConfig(EnterpriseWindowsWSLPolicy{AgentSessions: "allow"}, "secure_client")
	if err := resolveEnterpriseConfig(&secureClient, "windows", ""); err == nil || !strings.Contains(err.Error(), "apply only to the standalone profile") {
		t.Fatalf("secure_client accepted windows_wsl: %v", err)
	}
}

func TestClaudeVersionFloorValidation(t *testing.T) {
	managedConfig := func(m EnterpriseMachinePolicyConfig) Config {
		return Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: m}}
	}
	for _, mode := range []string{"enforce", "report", "off", "OFF"} {
		cfg := managedConfig(claudeFloorPolicy(mode))
		if err := resolveEnterpriseConfig(&cfg, "linux", ""); err != nil {
			t.Fatalf("version_floor %q rejected: %v", mode, err)
		}
	}
	bad := managedConfig(claudeFloorPolicy("strict"))
	if err := resolveEnterpriseConfig(&bad, "linux", ""); err == nil || !strings.Contains(err.Error(), "enterprise.machine_policy.connectors.claudecode.version_floor") {
		t.Fatalf("an unknown version_floor must be rejected, got %v", err)
	}
	// The key belongs to connectors.claudecode only: default does not carry
	// it, and no other connector has a version floor.
	for name, m := range map[string]EnterpriseMachinePolicyConfig{
		"enterprise.machine_policy.default.version_floor":          {Default: EnterpriseConnectorPolicy{VersionFloor: "off"}},
		"enterprise.machine_policy.connectors.codex.version_floor": {Connectors: map[string]EnterpriseConnectorPolicy{"codex": {VersionFloor: "off"}}},
	} {
		cfg := managedConfig(m)
		if err := resolveEnterpriseConfig(&cfg, "linux", ""); err == nil || !strings.Contains(err.Error(), name+" is not a setting") || !strings.Contains(err.Error(), "connectors.claudecode.version_floor") {
			t.Fatalf("%s must be rejected and name the right key, got %v", name, err)
		}
	}
	// The floor is a standalone knob: Secure Client configs keep their exact
	// behavior and refuse it.
	secureClient := managedConfig(claudeFloorPolicy("off"))
	secureClient.Enterprise.Profile = "secure_client"
	if err := resolveEnterpriseConfig(&secureClient, "windows", ""); err == nil || !strings.Contains(err.Error(), "apply only to the standalone profile") {
		t.Fatalf("secure_client accepted version_floor: %v", err)
	}
	unmanaged := Config{Enterprise: EnterpriseConfig{MachinePolicy: claudeFloorPolicy("off")}}
	if err := resolveEnterpriseConfig(&unmanaged, "linux", ""); err == nil || !strings.Contains(err.Error(), "requires deployment_mode") {
		t.Fatalf("an unmanaged config accepted version_floor: %v", err)
	}
}

// unverified_versions defaults to report, a per-connector override wins,
// both are validated, and Secure Client refuses the knob.
func TestEnterpriseUnverifiedVersions(t *testing.T) {
	en := EnterpriseEnrollmentConfig{UnverifiedVersions: "refuse", UnverifiedVersionsByConnector: map[string]string{"devin": "report"}}
	if got := (EnterpriseEnrollmentConfig{}).UnverifiedVersionsFor("codex"); got != EnterpriseUnverifiedReport {
		t.Fatalf("default = %q, want report", got)
	}
	if en.UnverifiedVersionsFor("codex") != EnterpriseUnverifiedRefuse || en.UnverifiedVersionsFor("Devin") != EnterpriseUnverifiedReport {
		t.Fatalf("override not applied: %+v", en)
	}
	for _, tc := range []struct {
		en      EnterpriseEnrollmentConfig
		profile string
		ok      bool
	}{
		{en, "", true},
		{EnterpriseEnrollmentConfig{UnverifiedVersions: "block"}, "", false},
		{EnterpriseEnrollmentConfig{UnverifiedVersionsByConnector: map[string]string{"codex": "allow"}}, "", false},
		{EnterpriseEnrollmentConfig{UnverifiedVersions: "report"}, "secure_client", false},
	} {
		goos := "linux"
		if tc.profile == "secure_client" {
			goos = "windows"
		}
		cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: tc.profile, Enrollment: tc.en}}
		if err := resolveEnterpriseConfig(&cfg, goos, ""); (err == nil) != tc.ok {
			t.Fatalf("%+v (%q): err = %v, want ok=%v", tc.en, tc.profile, err, tc.ok)
		}
	}
	for doc, ok := range map[string]bool{
		"    unverified_versions: refuse\n    unverified_versions_by_connector:\n      codex: report\n": true,
		"    unverified_versions: block\n": false,
	} {
		document, err := ParseV8YAML("unverified.yaml", []byte("config_version: 8\nenterprise:\n  enrollment:\n"+doc))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateV8Schema("unverified.yaml", document); (err == nil) != ok {
			t.Fatalf("schema on %q: err = %v, want ok=%v", doc, err, ok)
		}
	}
}

// The Windows managed-hook lifecycle snapshot reads only listener settings
// from the protected config, also while a rollback restores the previous
// deployment under a new config whose rule pack the gateway service cannot
// read. Refusing that config there failed the rollback and left every
// service stopped (GAP-1291). Root-only: managed config trust needs a
// root-owned path.
func TestLoadManagedFileForLifecycleRecoverySkipsPolicyInputChecks(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("needs root on Linux: a managed config must sit on a root-owned path")
	}
	root, err := os.MkdirTemp("/var/lib", "dc-config-recovery-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	pack := filepath.Join(root, "pack")
	if err := os.Mkdir(pack, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(pack, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config.yaml")
	body := fmt.Sprintf("deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\ndata_dir: %s\nguardrail:\n  rule_pack_dir: %s\n", root, pack)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFromFile(path); err == nil || !strings.Contains(err.Error(), "rule_pack_dir") {
		t.Fatalf("strict load of a user-owned rule pack: err = %v, want the policy-input refusal", err)
	}
	cfg, err := LoadManagedFileForLifecycleRecovery(path)
	if err != nil {
		t.Fatalf("lifecycle recovery load: %v", err)
	}
	if cfg.Gateway.APIPort == 0 {
		t.Fatal("lifecycle recovery load has no gateway API port")
	}
}
