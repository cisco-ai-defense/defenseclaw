// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// A custom rule written for 1.0 with a whole-argument expression blocks only
// a command argument equal to its literal; a file a tool writes that
// mentions the literal is not blocked. The same rule marked as migrated from
// 0.8.x blocks it, as 0.8.x did (GAP-1512).
func TestHandWrittenWholeArgumentRuleKeepsItsMeaning(t *testing.T) {
	write := func(marked bool) string {
		t.Helper()
		const connector = "whole-argument"
		pack := &guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
			Version: 1, Category: "acme-marker", Rules: []guardrail.RuleDefYAML{{
				ID: "ACME-MARKER", Pattern: "acme-marker-5d1e", MigratedLiteral: marked,
				Expression: "f.commands.exists(c, 'acme-marker-5d1e' in c.argv)",
				Title:      "Acme marker", Severity: "CRITICAL", Confidence: 0.99,
			}},
		}}}
		if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
			t.Fatal(err)
		}
		defer RemoveConnectorRulePackOverrides(connector)
		args, _ := json.Marshal(map[string]string{
			"file_path": "/home/alice/project/README.md", "content": "notes about acme-marker-5d1e\n",
		})
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input:      actionfacts.Input{Tool: "Write", Args: args, CWD: "/home/alice/project", ActiveHome: "/home/alice"},
			LegacyText: string(args), Connector: connector, EnforcementCapable: true,
		})
		return buildVerdict(findings, "tool_call").Action
	}
	if action := write(false); action == guardrailActionBlock {
		t.Fatalf("hand-written rule: write of a file that mentions the literal = %s, want not blocked", action)
	}
	if action := write(true); action != guardrailActionBlock {
		t.Fatalf("migrated rule: write of a file that mentions the literal = %s, want block", action)
	}
}

// Startup reads the migration record next to the config file the gateway
// loaded, which can be outside data_dir (GAP-1383).
func TestUnrebasedRulePacksFollowTheActiveConfigFile(t *testing.T) {
	external := filepath.Join(t.TempDir(), "etc", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(external), 0o700); err != nil {
		t.Fatal(err)
	}
	record := `{"schema_version":1,"from_version":8,"to_version":9,"source_sha256":"aa","result_sha256":"bb",` +
		`"moved":[],"conflicts":[],"actions_rows_moved":0,"rule_pack_rebase_failures":["custom pack: kept as it is"]}`
	if err := os.WriteFile(config.MigrationRecordPath(external), []byte(record), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{ConfigFilePath: external, DataDir: t.TempDir()}
	if got := unrebasedRulePacks(cfg); !slices.Equal(got, []string{"custom pack: kept as it is"}) {
		t.Fatalf("unrebasedRulePacks = %v", got)
	}
	if got := unrebasedRulePacks(&config.Config{DataDir: t.TempDir()}); len(got) != 0 {
		t.Fatalf("no record: %v", got)
	}
}
