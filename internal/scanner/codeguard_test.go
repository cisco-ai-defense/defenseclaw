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
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestScanContent_DetectsUnsafeExec(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("app.py", `import os
cmd = input("cmd: ")
os.system(cmd)
`)
	assertFindingID(t, findings, "CG-EXEC-001")
}

func TestScanContent_DetectsSQLInjection(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("db.py", `def get_user(name):
    cursor.execute(f"SELECT * FROM users WHERE name = {name}")
`)
	assertFindingID(t, findings, "CG-SQL-001")
}

func TestScanContent_DetectsHardcodedSecret(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("config.py", `api_key = "sk-proj-abcdefghij1234567890"
`)
	assertFindingID(t, findings, "CG-CRED-001")
}

func TestScanContent_DetectsPrivateKey(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("keys.py", `KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn
-----END RSA PRIVATE KEY-----"""
`)
	assertFindingID(t, findings, "CG-CRED-003")
	if findings[0].Severity != SeverityCritical {
		t.Errorf("expected CRITICAL severity for private key, got %s", findings[0].Severity)
	}
}

func TestScanContent_DetectsWeakCrypto(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("hash.py", `import hashlib
h = hashlib.md5(data)
`)
	assertFindingID(t, findings, "CG-CRYPTO-001")
}

func TestScanContent_DetectsShellTrue(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("run.py", `import subprocess
subprocess.call("ls -la", shell=True)
`)
	assertFindingID(t, findings, "CG-EXEC-002")
}

func TestScanContent_DetectsPathTraversal(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("file.py", `path = "../../etc/passwd"
`)
	assertFindingID(t, findings, "CG-PATH-001")
}

func TestScanContent_DetectsUnsafeDeserialize(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("load.py", `import pickle
obj = pickle.loads(data)
`)
	assertFindingID(t, findings, "CG-DESER-001")
}

func TestScanContent_CleanCodeNoFindings(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("clean.py", `def greet(name: str) -> str:
    return f"Hello, {name}!"

if __name__ == "__main__":
    print(greet("world"))
`)
	if len(findings) != 0 {
		t.Errorf("expected 0 findings for clean code, got %d: %+v", len(findings), findings)
	}
}

func TestScanContent_ExtensionFiltering(t *testing.T) {
	cg := NewCodeGuardScanner("")

	pyFindings := cg.ScanContent("app.py", `os.system(cmd)`)
	if len(pyFindings) == 0 {
		t.Error("expected CG-EXEC-001 to fire on .py file")
	}

	goFindings := cg.ScanContent("app.go", `os.system(cmd)`)
	for _, f := range goFindings {
		if f.ID == "CG-EXEC-001" {
			t.Error("CG-EXEC-001 should not fire on .go files (not in extensions list)")
		}
	}

	pyOnlyFindings := cg.ScanContent("run.go", `subprocess.call("ls", shell=True)`)
	for _, f := range pyOnlyFindings {
		if f.ID == "CG-EXEC-002" {
			t.Error("CG-EXEC-002 (shell=True) should not fire on .go files")
		}
	}
}

func TestScanContent_MultipleFindings(t *testing.T) {
	cg := NewCodeGuardScanner("")
	code := `import os, pickle, hashlib
os.system(user_input)
obj = pickle.loads(data)
h = hashlib.md5(secret)
`
	findings := cg.ScanContent("multi.py", code)
	if len(findings) < 3 {
		t.Errorf("expected at least 3 findings, got %d: %+v", len(findings), findings)
	}

	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.ID] = true
	}
	for _, want := range []string{"CG-EXEC-001", "CG-DESER-001", "CG-CRYPTO-001"} {
		if !ids[want] {
			t.Errorf("expected finding %s in results", want)
		}
	}
}

func TestScanContent_LocationFormat(t *testing.T) {
	cg := NewCodeGuardScanner("")
	findings := cg.ScanContent("test.py", "line1\nos.system(cmd)\nline3\n")
	if len(findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	if findings[0].Location != "test.py:2" {
		t.Errorf("expected location test.py:2, got %s", findings[0].Location)
	}
}

func TestIsCodeFile(t *testing.T) {
	tests := []struct {
		ext  string
		want bool
	}{
		{".py", true},
		{".js", true},
		{".ts", true},
		{".go", true},
		{".java", true},
		{".rb", true},
		{".rs", true},
		{".c", true},
		{".txt", false},
		{".md", false},
		{".png", false},
		{"", false},
		{".exe", false},
	}
	for _, tc := range tests {
		t.Run(tc.ext, func(t *testing.T) {
			got := IsCodeFile(tc.ext)
			if got != tc.want {
				t.Errorf("IsCodeFile(%q) = %v, want %v", tc.ext, got, tc.want)
			}
		})
	}
}

func TestScan_SingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vuln.py")
	if err := os.WriteFile(path, []byte("os.system(cmd)\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cg := NewCodeGuardScanner("")
	result, err := cg.Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if result.Scanner != "codeguard" {
		t.Errorf("expected scanner=codeguard, got %s", result.Scanner)
	}
	assertFindingID(t, result.Findings, "CG-EXEC-001")
}

func TestScan_Directory(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "bad.py"), []byte("os.system(cmd)\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "clean.py"), []byte("print('hello')\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("os.system(cmd)\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cg := NewCodeGuardScanner("")
	result, err := cg.Scan(context.Background(), dir)
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding (from bad.py only, .txt skipped), got %d", len(result.Findings))
	}
}

func TestScan_NonexistentPath(t *testing.T) {
	cg := NewCodeGuardScanner("")
	_, err := cg.Scan(context.Background(), "/nonexistent/path/file.py")
	if err == nil {
		t.Error("expected error for nonexistent path")
	}
}

func assertFindingID(t *testing.T, findings []Finding, wantID string) {
	t.Helper()
	for _, f := range findings {
		if f.ID == wantID {
			return
		}
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	t.Errorf("expected finding %s, got %v", wantID, ids)
}

func TestCodeGuardCustomRules(t *testing.T) {
	dir := t.TempDir()

	ruleContent := `version: 1
rules:
  - id: CUSTOM-001
    severity: high
    title: Custom test rule
    pattern: 'TODO_FIXME_HACK'
    remediation: Fix the hack
`
	if err := os.WriteFile(filepath.Join(dir, "custom.yaml"), []byte(ruleContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cg := NewCodeGuardScanner(dir)
	if len(cg.customRules) != 1 {
		t.Fatalf("expected 1 custom rule, got %d", len(cg.customRules))
	}
	if cg.customRules[0].id != "CUSTOM-001" {
		t.Errorf("custom rule id = %q, want CUSTOM-001", cg.customRules[0].id)
	}

	findings := cg.ScanContent("test.py", "# TODO_FIXME_HACK: fix this\nprint('hello')\n")
	found := false
	for _, f := range findings {
		if f.ID == "CUSTOM-001" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected CUSTOM-001 finding from custom rule")
	}
}

func TestCodeGuardCustomRules_InvalidRegex(t *testing.T) {
	dir := t.TempDir()

	ruleContent := `version: 1
rules:
  - id: BAD-001
    severity: high
    title: Bad regex rule
    pattern: '[invalid'
    remediation: Fix
`
	if err := os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(ruleContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cg := NewCodeGuardScanner(dir)
	if len(cg.customRules) != 0 {
		t.Errorf("expected 0 custom rules for invalid regex, got %d", len(cg.customRules))
	}
}

func TestCodeGuardCustomRules_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	cg := NewCodeGuardScanner(dir)
	if len(cg.customRules) != 0 {
		t.Errorf("expected 0 custom rules for empty dir, got %d", len(cg.customRules))
	}
	all := cg.allRules()
	if len(all) != len(builtinRules) {
		t.Errorf("allRules should equal builtinRules when no custom rules, got %d vs %d", len(all), len(builtinRules))
	}
}
