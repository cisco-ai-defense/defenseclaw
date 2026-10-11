// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0132: a standalone deployment reads the llm: key (judge and scanner
// LLM analyzers) from enterprise.inspection.llm.credential, never from the
// environment, and a Secure Client config cannot name one.
func TestStandaloneLLMKeyComesFromProtectedCredential(t *testing.T) {
	t.Setenv("P0_JUDGE_KEY_ENV", "from-env")
	t.Setenv(DefenseClawLLMKeyEnv, "inherited-key")
	read := ""
	prev := resolveStandaloneLLMCredential
	resolveStandaloneLLMCredential = func(name, _ string) ([]byte, error) {
		read = name
		if name == "missing" {
			return nil, errors.New("not provisioned")
		}
		return []byte("from-credential"), nil
	}
	t.Cleanup(func() { resolveStandaloneLLMCredential = prev })

	cfg := Config{
		DeploymentMode: "managed_enterprise",
		ConfigFilePath: `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		Enterprise: EnterpriseConfig{
			Profile:    "standalone",
			Inspection: EnterpriseInspectionConfig{LLM: EnterpriseLLMConfig{Credential: "llm-judge"}},
		},
		LLM: LLMConfig{Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", APIKeyEnv: "P0_JUDGE_KEY_ENV"},
	}
	for _, role := range []string{"guardrail.judge", "scanners.skill", "scanners.mcp", "scanners.plugin"} {
		if got := cfg.ResolveLLM(role).ResolvedAPIKey(); got != "from-credential" {
			t.Fatalf("ResolveLLM(%q) key = %q, want the protected credential", role, got)
		}
	}
	if read != "llm-judge" {
		t.Fatalf("read credential %q", read)
	}

	cfg.Enterprise.Inspection.LLM.Credential = "missing"
	if got := cfg.ResolveLLM("guardrail.judge").ResolvedAPIKey(); got != "" {
		t.Fatal("an unreadable credential must not fall back to an inherited key")
	}

	sc := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{
		Profile:    "secure_client",
		Inspection: EnterpriseInspectionConfig{LLM: EnterpriseLLMConfig{Credential: "llm-judge"}},
	}}
	if err := validateEnterpriseConfig(&sc); err == nil || !strings.Contains(err.Error(), "standalone") {
		t.Fatalf("secure client accepted an llm credential: %v", err)
	}
	if got := sc.ResolveLLM("guardrail.judge").APIKey; got != "" {
		t.Fatalf("secure client resolved a credential key %q", got)
	}
}

// GAP-0674: the installed config still names the judge key, so `enterprise
// secret remove` of that credential is refused with the key that names it;
// AI Defense only counts while it is enabled.
func TestInstalledCredentialReferenceNamesTheJudgeKey(t *testing.T) {
	raw := []byte("\xef\xbb\xbfconfig_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n  inspection:\n    llm:\n      credential: llm-judge\n    ai_defense:\n      credential: aid-key\n")
	if at := InstalledCredentialReference("config.yaml", raw, t.TempDir(), "llm-judge"); at != "enterprise.inspection.llm.credential" {
		t.Fatalf("judge key reference = %q", at)
	}
	if at := InstalledCredentialReference("config.yaml", raw, t.TempDir(), "aid-key"); at != "" {
		t.Fatalf("disabled AI Defense key reference = %q, want none", at)
	}
	if at := InstalledCredentialReference("config.yaml", raw, t.TempDir(), "unused"); at != "" {
		t.Fatalf("unused key reference = %q, want none", at)
	}
}

// GAP-1437: a standalone config that names no LLM credential has no LLM key,
// and its AI Defense analyzers no key from cisco_ai_defense.api_key_env: a
// DEFENSECLAW_LLM_KEY or AI Defense key the gateway service inherited never
// stands in, so a plugin scan whose judge needs a key fails closed. Per-user
// installs keep DEFENSECLAW_LLM_KEY and api_key_env.
func TestStandaloneKeysIgnoreServiceEnvironment(t *testing.T) {
	t.Setenv(DefenseClawLLMKeyEnv, "inherited-key")
	t.Setenv("P0_AID_KEY_ENV", "inherited-aid")
	const doc = "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n" +
		"llm:\n  model: bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0\ncisco_ai_defense:\n  api_key_env: P0_AID_KEY_ENV\n"
	loaded, err := LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), []byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"guardrail.judge", "scanners.plugin", "scanners.skill", "scanners.mcp"} {
		if got := loaded.ResolveLLM(role).ResolvedAPIKey(); got != "" {
			t.Fatalf("standalone ResolveLLM(%q) without a credential = %q, want no key", role, got)
		}
	}
	if got := loaded.CiscoAIDefense.ResolvedAPIKey(); got != "" {
		t.Fatalf("standalone AI Defense key = %q, want none from the environment", got)
	}

	// GAP-1483: with AI Defense enabled the scanners' analyzers get the
	// protected credential, also from a copy of the configuration (the
	// gateway publishes one), and an unreadable one never the environment key.
	provisioned := true
	prev := resolveStandaloneLLMCredential
	t.Cleanup(func() { resolveStandaloneLLMCredential = prev })
	resolveStandaloneLLMCredential = func(name, _ string) ([]byte, error) {
		if !provisioned || name != "aid-key" {
			return nil, errors.New("not provisioned")
		}
		return []byte("from-credential"), nil
	}
	withAID := strings.Replace(doc, "profile: standalone\n",
		"profile: standalone\n  inspection:\n    ai_defense:\n      enabled: true\n      credential: aid-key\n", 1)
	loaded, err = LoadRuntimeV8InspectionCandidateFromBytes(filepath.Join(t.TempDir(), "config.yaml"), []byte(withAID))
	if err != nil {
		t.Fatal(err)
	}
	copied, err := loaded.DeepCopy()
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*Config{"loaded": loaded, "copied": copied} {
		provisioned = true
		if got := cfg.CiscoAIDefense.ResolvedAPIKey(); got != "from-credential" {
			t.Fatalf("%s standalone AI Defense key = %q, want the protected credential", name, got)
		}
		provisioned = false
		if got := cfg.CiscoAIDefense.ResolvedAPIKey(); got != "" {
			t.Fatalf("%s unreadable AI Defense credential gave key %q, want none", name, got)
		}
	}

	perUser := Config{LLM: LLMConfig{Model: "openai/gpt-4o-mini"}, CiscoAIDefense: CiscoAIDefenseConfig{APIKeyEnv: "P0_AID_KEY_ENV"}}
	if got := perUser.ResolveLLM("scanners.plugin").ResolvedAPIKey(); got != "inherited-key" {
		t.Fatalf("per-user key = %q, want DEFENSECLAW_LLM_KEY", got)
	}
	if got := perUser.CiscoAIDefense.ResolvedAPIKey(); got != "inherited-aid" {
		t.Fatalf("per-user AI Defense key = %q, want api_key_env", got)
	}
}
