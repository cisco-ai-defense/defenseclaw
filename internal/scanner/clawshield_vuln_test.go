// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCSVulnFindingTitlesAreReadable(t *testing.T) {
	findings := csVulnScanContent([]byte("value = eval(os.environ.get('X'))\n"), "helper.py")
	var eval *Finding
	for i := range findings {
		if findings[i].ID == "CS-VLN-CODE-EVAL" {
			eval = &findings[i]
		}
	}
	if eval == nil {
		t.Fatalf("eval() not reported: %+v", findings)
	}
	if eval.Title != "Dynamic code evaluation with eval()" {
		t.Fatalf("eval title = %q", eval.Title)
	}
	for _, rule := range csVulnRules {
		if title := csVulnTitle(rule); strings.Contains(title, rule.id) || strings.HasPrefix(title, "Vulnerability pattern") {
			t.Errorf("rule %s has no readable title: %q", rule.id, title)
		}
	}
}

// GAP-1595: one eval() line is one code-scan finding (CS-VLN-CODE-EVAL), not
// also CodeGuard's "Unsafe command execution"; a real command call still
// keeps CG-EXEC-001.
func TestScanCodeReportsEvalOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "calc.py"), []byte("import sys\nprint(eval(sys.argv[1]))\nos.system(sys.argv[2])\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := ScanCode(t.Context(), dir, "")
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string][]string{}
	for _, f := range result.Findings {
		counts[f.ID] = append(counts[f.ID], f.Location)
	}
	if got := counts["CS-VLN-CODE-EVAL"]; len(got) != 1 {
		t.Fatalf("CS-VLN-CODE-EVAL = %v, want one", got)
	}
	exec := counts["CG-EXEC-001"]
	if len(exec) != 1 || !strings.HasSuffix(exec[0], ":3") {
		t.Fatalf("CG-EXEC-001 = %v, want only the os.system line", exec)
	}
}
