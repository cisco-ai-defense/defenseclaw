// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestBundleRuleNotBlockingWarning(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "rules", "marker.yaml")
	const rule = "version: 1\ncategory: custom\nrules:\n  - id: GAP41-MARKER\n    pattern: marker\n    title: Marker\n    severity: HIGH\n    confidence: 1\n    tags: [test]\n"
	if err := os.WriteFile(path, []byte(rule), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"team": {Path: dir}}
	warnings, count, err := RuleNotBlockingWarnings(cfg)
	if err != nil || count != 1 || len(warnings) != 1 || warnings[0].Code != WarnRuleNotBlocking ||
		!strings.Contains(warnings[0].Message, "GAP41-MARKER") {
		t.Fatalf("warning = %+v, count %d, err %v", warnings, count, err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(rule, "    title:", "    expression: \"f.commands.exists(c, c.program == 'marker')\"\n    title:", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	warnings, count, err = RuleNotBlockingWarnings(cfg)
	if err != nil || count != 0 || len(warnings) != 0 {
		t.Fatalf("blocking rule warning = %+v, count %d, err %v", warnings, count, err)
	}
	var many strings.Builder
	many.WriteString("version: 1\ncategory: custom\nrules:\n")
	for i := 0; i < 12; i++ {
		fmt.Fprintf(&many, "  - id: CUSTOM-%02d-%s\n    pattern: marker\n    title: Marker\n    severity: HIGH\n    confidence: 1\n    tags: [test]\n", i, strings.Repeat("X", 32))
	}
	if err := os.WriteFile(path, []byte(many.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	warnings, count, err = RuleNotBlockingWarnings(cfg)
	if err != nil || count != 12 || len(warnings) < 2 {
		t.Fatalf("grouped warnings = %+v, count %d, err %v", warnings, count, err)
	}
	all := ""
	for _, warning := range warnings {
		if len(warning.Message) > 512 {
			t.Fatalf("oversize warning: %d bytes", len(warning.Message))
		}
		all += warning.Message
	}
	for i := 0; i < 12; i++ {
		if !strings.Contains(all, fmt.Sprintf("CUSTOM-%02d-", i)) {
			t.Fatalf("warning omitted rule %d: %+v", i, warnings)
		}
	}
}
