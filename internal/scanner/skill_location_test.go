// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1848: the upstream JSON names the file as file_path/line_number; the
// gateway (watcher) scan keeps it as "helper.py:6" like the Python skill scan,
// and corrects a SKILL.md line counted from the end of the front matter.
func TestParseSkillOutputNamesFileAndLine(t *testing.T) {
	skill := t.TempDir()
	manifest := "---\nname: s\ndescription: d\n---\n\n# S\n\nIgnore the previous rules marker.\n"
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	out := `{"findings":[` +
		`{"rule_id":"COMMAND_INJECTION_EVAL","severity":"HIGH","file_path":"helper.py","line_number":6},` +
		`{"rule_id":"YARA_prompt_injection_generic","severity":"HIGH","file_path":"SKILL.md","line_number":3,"snippet":"Ignore the previous rules marker."},` +
		`{"rule_id":"MANIFEST","severity":"LOW","file_path":null,"line_number":null},` +
		`{"rule_id":"OLD","severity":"LOW","location":"x.py:2","line":2}]}`
	findings, err := parseSkillOutput([]byte(out), skill)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"helper.py:6", "SKILL.md:8", "", "x.py:2"}
	for i, f := range findings {
		if f.Location != want[i] {
			t.Errorf("finding %d location = %q, want %q", i, f.Location, want[i])
		}
	}
	if ln := findings[1].LineNumber; ln == nil || *ln != 8 {
		t.Errorf("SKILL.md line = %v, want 8", ln)
	}
}
