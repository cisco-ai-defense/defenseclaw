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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A credential copy a Windows shell call runs inside a PowerShell
// subexpression, a -and operand, a foreach body, a powershell -c script or a
// cmd /c line gets the verdict of the same copy sent alone, in every pack, on
// the exec route (/inspect/tool) and the Claude Code PowerShell tool
// (rel-1-0-10:GAP-0998, GAP-1226). The copy of an ordinary file stays allowed.
func TestWindowsHookNestedCredentialCopyIsJudgedAsTheCopyAlone(t *testing.T) {
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = previous })
	const home = `C:\Users\alice`
	sameHostHomeForTest = home
	t.Cleanup(func() { sameHostHomeForTest = "" })
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	exec := func(t *testing.T, server *APIServer, command string) string {
		t.Helper()
		body, _ := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw",
			"args": map[string]any{"command": command, "workdir": home + `\proj`}})
		rec := httptest.NewRecorder()
		server.handleInspectTool(rec, httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body)))
		var v ToolInspectVerdict
		if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
			t.Fatalf("exec %q: %v (%s)", command, err, rec.Body.String())
		}
		return v.Action + " " + v.Severity
	}
	powerShellTool := func(t *testing.T, server *APIServer, command string) string {
		t.Helper()
		r := server.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{HookEventName: "PreToolUse",
			ToolName: "PowerShell", CWD: home + `\proj`, ToolInput: map[string]interface{}{"command": command}})
		return r.Action + " " + r.Severity
	}
	nested := map[string]string{
		"sub":     `$x = $(Copy-Item $HOME\%s C:\t\n); $x`,
		"andop":   `$true -and (Copy-Item $HOME\%s C:\t\n)`,
		"foreach": `foreach ($i in 1) { Copy-Item $HOME\%s C:\t\n }`,
		"psc":     `powershell -c "Copy-Item $HOME\%s C:\t\n"`,
		"cmdc":    `cmd /c "copy %%USERPROFILE%%\%s C:\t\n & echo ok"`,
		"cmdcone": `cmd /c "copy %%USERPROFILE%%\%s C:\t\n"`,
	}
	const alone = `Copy-Item $HOME\%s C:\t\n`
	credentials := map[string][]string{
		`.git-credentials`: {"sub", "andop", "foreach", "psc", "cmdc", "cmdcone"},
		`.ssh\id_rsa`:      {"sub", "andop", "foreach", "psc", "cmdc", "cmdcone"},
		// GAP-1226: every file of the native repro, powershell -c.
		`.netrc`:           {"psc"},
		`.aws\credentials`: {"psc"},
		`.pgpass`:          {"psc"},
		`.kube\config`:     {"psc"},
	}
	for _, pack := range gap0437Packs {
		t.Run(pack.name, func(t *testing.T) {
			openclaw := gap0437Server(t, pack, "openclaw", "action")
			claudecode := gap0437Server(t, pack, "claudecode", "action")
			routes := []struct {
				name  string
				judge func(*testing.T, string) string
			}{
				{"exec", func(t *testing.T, c string) string { return exec(t, openclaw, c) }},
				{"powershell-tool", func(t *testing.T, c string) string { return powerShellTool(t, claudecode, c) }},
			}
			for _, route := range routes {
				for file, forms := range credentials {
					want := route.judge(t, fmt.Sprintf(alone, file))
					if want == "allow NONE" {
						t.Fatalf("%s %s: the copy alone is %q: the repro no longer holds", route.name, file, want)
					}
					for _, form := range forms {
						if got := route.judge(t, fmt.Sprintf(nested[form], file)); got != want {
							t.Errorf("%s %s %s: %q, the copy alone is %q", route.name, file, form, got, want)
						}
					}
				}
				// Benign twins: the same nesting of an ordinary file's copy.
				for form, spelling := range nested {
					if got := route.judge(t, fmt.Sprintf(spelling, `notes\a.txt`)); !strings.HasPrefix(got, "allow") {
						t.Errorf("%s notes\\a.txt %s: %q, want allow", route.name, form, got)
					}
				}
			}
		})
	}
}
