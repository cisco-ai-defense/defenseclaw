// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"strings"
	"testing"
)

// GAP-0132: a standalone deployment reads the llm: key (judge and scanner
// LLM analyzers) from enterprise.inspection.llm.credential, never from the
// environment, and a Secure Client config cannot name one.
func TestStandaloneLLMKeyComesFromProtectedCredential(t *testing.T) {
	t.Setenv("P0_JUDGE_KEY_ENV", "from-env")
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
	if got := cfg.ResolveLLM("guardrail.judge").ResolvedAPIKey(); got == "from-env" {
		t.Fatal("an unreadable credential must not fall back to the environment key")
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
