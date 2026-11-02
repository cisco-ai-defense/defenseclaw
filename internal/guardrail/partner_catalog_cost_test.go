// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func defaultRulesWithExtension(t *testing.T, extension string) string {
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
	writeRulePackFile(t, dir, "rules/extension.yaml", extension)
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
