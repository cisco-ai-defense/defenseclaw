// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCodeGuardCustomRulesCachedUntilAFileChanges(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "custom.yaml")
	write := func(pattern string, at time.Time) {
		t.Helper()
		body := "rules:\n  - id: CG-S8-1\n    severity: high\n    title: marker\n    pattern: \"" + pattern + "\"\n    extensions: [\".py\"]\n"
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(file, at, at); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Now().Add(-time.Hour)
	write("dccert-marker-a", t0)
	first := loadCustomRules(dir)
	second := loadCustomRules(dir)
	if len(first) != 1 || len(second) != 1 || first[0].pattern != second[0].pattern {
		t.Fatalf("unchanged folder was compiled again: %v %v", first, second)
	}
	write("dccert-marker-bb", t0.Add(time.Second))
	third := loadCustomRules(dir)
	if len(third) != 1 || third[0].pattern.String() != "dccert-marker-bb" {
		t.Fatalf("changed rule file not reloaded: %v", third)
	}
	s := NewCodeGuardScanner(dir)
	if got := s.ScanContent("x.py", "print(\"dccert-marker-bb\")"); len(got) == 0 {
		t.Fatal("cached custom rule did not match")
	}
}
