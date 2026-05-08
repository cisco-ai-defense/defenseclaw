// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestParseCredentialRowsAndMissing(t *testing.T) {
	raw := []byte(`warning: privacy.disable_redaction=true
[
	  {"env_name":"DEFENSECLAW_LLM_KEY","feature":"LLM","requirement":"required","source":"unset","set":false},
	  {"env_name":"OPTIONAL_KEY","feature":"optional","requirement":"optional","source":"dotenv","set":true}
	]`)
	rows, err := ParseCredentialRows(raw)
	if err != nil {
		t.Fatal(err)
	}
	missing := MissingCredentialRows(rows)
	if len(missing) != 1 || missing[0].EnvName != "DEFENSECLAW_LLM_KEY" {
		t.Fatalf("missing=%v", missing)
	}
}

func TestBuildReadinessChecksMissingCredential(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.LLM.Provider = "openai"
	cfg.LLM.Model = "gpt-4o"
	health := &HealthSnapshot{
		Gateway: SubsystemHealth{State: "running"},
		API:     SubsystemHealth{State: "running"},
	}
	checks := BuildReadinessChecks(cfg, health, nil, []CredentialRow{
		{EnvName: "DEFENSECLAW_LLM_KEY", Requirement: "required", Set: false},
	}, RestartQueue{})
	var found ReadinessCheck
	for _, ck := range checks {
		if ck.Title == "Required Credentials" {
			found = ck
			break
		}
	}
	if found.Status != ReadinessFail {
		t.Fatalf("credentials readiness=%s want fail", found.Status)
	}
	if found.Fix == nil || strings.Join(found.Fix.Args, " ") != "keys fill-missing" {
		t.Fatalf("missing credential fix=%+v", found.Fix)
	}
}

func TestValidateConfigField(t *testing.T) {
	cases := []struct {
		name string
		f    configField
		want ValidationSeverity
	}{
		{"port-range", configField{Key: "gateway.port", Kind: "int", Value: "70000"}, ValidationError},
		{"env-secret-warning", configField{Key: "llm.api_key_env", Kind: "string", Value: "sk-test-1234567890abcdef"}, ValidationWarning},
		{"url-credentials", configField{Key: "otel.endpoint", Kind: "string", Value: "https://u:p@example.com"}, ValidationError},
		{"duration", configField{Key: "notifications.dedup_window", Kind: "string", Value: "30s"}, ValidationOK},
		{"choice", configField{Key: "guardrail.mode", Kind: "choice", Value: "action", Options: []string{"observe", "action"}}, ValidationOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateConfigField(tc.f)
			if got.Severity != tc.want {
				t.Fatalf("severity=%s want %s message=%q", got.Severity, tc.want, got.Message)
			}
		})
	}
}

func TestConfigDiffAndAuditPayloadMaskSecrets(t *testing.T) {
	cfg := config.DefaultConfig()
	p := NewSetupPanel(DefaultTheme(), cfg, NewCommandExecutor())
	p.sections = []configSection{{
		Name: "Secrets",
		Fields: []configField{
			{Label: "API Key", Key: "llm.api_key", Kind: "password", Original: "old-secret-1234", Value: "new-secret-5678"},
			{Label: "API Key Env", Key: "llm.api_key_env", Kind: "string", Original: "DEFENSECLAW_LLM_KEY", Value: "sk-test-1234567890abcdef"},
		},
	}}
	diff := p.ConfigDiff()
	if len(diff) != 2 {
		t.Fatalf("diff=%v", diff)
	}
	for _, entry := range diff {
		if strings.Contains(entry.Before, "old-secret") ||
			strings.Contains(entry.After, "new-secret") ||
			strings.Contains(entry.After, "sk-test") {
			t.Fatalf("diff leaked secret: %+v", entry)
		}
	}
	path, cleanup, err := p.AuditActivityTempFile()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "old-secret") ||
		strings.Contains(string(data), "new-secret") ||
		strings.Contains(string(data), "sk-test") {
		t.Fatalf("audit payload leaked secret: %s", string(data))
	}
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatal(err)
	}
}
