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

package gateway

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectTool_WriteFile_CodeGuardAlert(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{
		"tool": "write_file",
		"args": {
			"path": "/tmp/app.py",
			"content": "import os\nos.system(cmd)"
		}
	}`
	_, verdict := postInspect(t, api, body)

	if verdict.Action != "alert" {
		t.Errorf("action = %q, want alert under balanced policy", verdict.Action)
	}
	if verdict.Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH", verdict.Severity)
	}
	assertHasFinding(t, verdict.Findings, "codeguard:CG-EXEC-001")
}

func TestInspectTool_WriteFile_CodeGuardAllow(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{
		"tool": "write_file",
		"args": {
			"path": "/tmp/clean.py",
			"content": "def greet(name):\n    return f'Hello, {name}!'"
		}
	}`
	_, verdict := postInspect(t, api, body)

	if verdict.Action != "allow" {
		t.Errorf("action = %q, want allow", verdict.Action)
	}
	if len(verdict.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d: %v", len(verdict.Findings), verdict.Findings)
	}
}

func TestInspectTool_EditFile_PrivateKey(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{
		"tool": "edit_file",
		"args": {
			"path": "/tmp/config.py",
			"new_string": "KEY = \"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\""
		}
	}`
	_, verdict := postInspect(t, api, body)

	if verdict.Action != "block" {
		t.Errorf("action = %q, want block", verdict.Action)
	}
	if verdict.Severity != "CRITICAL" {
		t.Errorf("severity = %q, want CRITICAL", verdict.Severity)
	}
	assertHasFinding(t, verdict.Findings, "codeguard:CG-CRED-003")
}

func TestInspectTool_WriteFile_SQLInjection(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{
		"tool": "write_file",
		"args": {
			"path": "/tmp/db.py",
			"content": "cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")"
		}
	}`
	_, verdict := postInspect(t, api, body)

	if verdict.Action != "alert" {
		t.Errorf("action = %q, want alert under balanced policy", verdict.Action)
	}
	assertHasFinding(t, verdict.Findings, "codeguard:CG-SQL-001")
}

func TestInspectTool_NonCodeFile_Skipped(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{
		"tool": "write_file",
		"args": {
			"path": "/tmp/readme.txt",
			"content": "os.system(cmd)"
		}
	}`
	_, verdict := postInspect(t, api, body)

	for _, f := range verdict.Findings {
		if strings.HasPrefix(f, "codeguard:") {
			t.Errorf("CodeGuard should not scan .txt files, but got finding: %s", f)
		}
	}
}

func TestInspectTool_ExecTool_NotCodeGuard(t *testing.T) {
	api := testAPIServerWithConfig(t, "action")
	body := `{
		"tool": "shell",
		"args": {"command": "rm -rf /"}
	}`
	_, verdict := postInspect(t, api, body)

	if verdict.Action != "block" {
		t.Errorf("action = %q, want block (dangerous cmd)", verdict.Action)
	}
	for _, f := range verdict.Findings {
		if strings.HasPrefix(f, "codeguard:") {
			t.Errorf("shell tool should not trigger CodeGuard, but got: %s", f)
		}
	}
}

func assertHasFinding(t *testing.T, findings []string, prefix string) {
	t.Helper()
	for _, f := range findings {
		if strings.HasPrefix(f, prefix) {
			return
		}
	}
	j, _ := json.Marshal(findings)
	t.Errorf("expected finding with prefix %q in %s", prefix, string(j))
}
