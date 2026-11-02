// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

func defaultRulesWithExtension(t *testing.T, extensions ...string) string {
	t.Helper()
	dir := t.TempDir()
	files, err := os.ReadDir(filepath.Join("..", "..", "policies", "guardrail", "default", "rules"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}
		contents, err := os.ReadFile(filepath.Join("..", "..", "policies", "guardrail", "default", "rules", file.Name()))
		if err != nil {
			t.Fatal(err)
		}
		writeRulePackFile(t, dir, filepath.Join("rules", file.Name()), string(contents))
	}
	for i, extension := range extensions {
		writeRulePackFile(t, dir, fmt.Sprintf("rules/extension-%d.yaml", i), extension)
	}
	return dir
}

func TestDefaultCatalogAcceptsPartnerExtension(t *testing.T) {
	partner, err := os.ReadFile(filepath.Join("testdata", "amd-partner.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pack := mustLoadRulePack(t, defaultRulesWithExtension(t, string(partner)))
	if got := pack.Summary().RuleFileCount; got < 2 {
		t.Fatalf("rule file count = %d, want default rules and partner extension", got)
	}
}

func TestDefaultCatalogAcceptsBenignExtension(t *testing.T) {
	pack := mustLoadRulePack(t, defaultRulesWithExtension(t, validRulesYAML("fixture-extension", "FIXTURE-LOW-COST")))
	if got := pack.Summary().RuleFileCount; got < 2 {
		t.Fatalf("rule file count = %d, want default rules and benign extension", got)
	}
}

func TestDefaultCatalogPreservesPartnerExtensionHeadroom(t *testing.T) {
	partner, err := os.ReadFile(filepath.Join("testdata", "amd-partner.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	extra, err := os.ReadFile(filepath.Join("testdata", "amd-partner-extra.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	pack := mustLoadRulePack(t, defaultRulesWithExtension(t, string(partner), string(extra)))

	// These are the enabled semantic count and cost of the 1.0.6 defaults
	// measured with this loader. Staying within both bounds preserves its
	// semantic budget for partner extensions.
	const priorSemanticRules = 137
	const priorStaticCost uint64 = 24_889_075
	defaultPack := mustLoadRulePack(t, filepath.Join("..", "..", "policies", "guardrail", "default"))
	compiler, err := semantic.NewCompiler()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	var cost uint64
	for _, file := range defaultPack.RuleFiles {
		for _, rule := range file.Rules {
			if rule.Expression == "" || rule.Enabled != nil && !*rule.Enabled {
				continue
			}
			program, code := compiler.Compile(rule.Expression)
			if code != semantic.CompileOK {
				t.Fatalf("default rule %s failed semantic compilation: %s", rule.ID, code)
			}
			count++
			cost += program.StaticCost()
		}
	}
	if count > priorSemanticRules || cost > priorStaticCost {
		t.Fatalf("default semantic count/cost = %d/%d, want at most %d/%d", count, cost, priorSemanticRules, priorStaticCost)
	}

	if got, want := pack.Summary().RuleFileCount, defaultPack.Summary().RuleFileCount+2; got != want {
		t.Fatalf("rule file count = %d, want %d", got, want)
	}
}
