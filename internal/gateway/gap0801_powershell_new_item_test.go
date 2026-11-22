// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-10:GAP-0801: a benign PowerShell script that writes files in its
// project and creates one with New-Item (a file, not a link) is not blocked
// in the default or permissive tier on a Windows host. On a
// native Windows gateway the authorized-keys proof held each relative write
// as unknown and every New-Item counted as link-making code, so the hold was
// never lowered and the call blocked; the 4-write script without New-Item
// allowed. The rows are the s7-g766 H1 timing rows.
func TestGAP0801BenignPowerShellNewItemFileScript(t *testing.T) {
	gap0589WindowsHost(t)
	writes := []string{
		`Set-Content -Path .\a.txt -Value 'one'`,
		`Set-Content -Path .\b.txt -Value 'two'`,
		`Add-Content -Path .\c.log -Value 'three'`,
		`Set-Content -Path .\d.md -Value 'four'`,
	}
	rows := map[string]string{
		"4 writes":              strings.Join(writes, "\n"),
		"4 writes + New-Item":   strings.Join(append(append([]string{}, writes...), `New-Item -Path .\e.txt -ItemType File -Force`), "\n"),
		"1 write + New-Item":    writes[0] + "\n" + `New-Item -Path .\e.txt -ItemType File -Force`,
		"write + New-Item dir":  writes[0] + "\n" + `New-Item -Path .\logs -ItemType Directory -Force`,
		"write + New-Item bare": writes[0] + "; " + `New-Item -Path .\e.txt -Force`,
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		pack := pack
		t.Run(pack, func(t *testing.T) {
			api := instructionProtectionTestAPIWithPack(t, "claudecode", "action", "", pack)
			cwd := t.TempDir()
			for name, command := range rows {
				body, _ := json.Marshal(map[string]any{"session_id": "g801-" + pack + name, "hook_event_name": "PreToolUse",
					"tool_name": "PowerShell", "cwd": cwd, "tool_input": map[string]any{"command": command}})
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
				req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
				rec := httptest.NewRecorder()
				api.handleAgentHook("claudecode").ServeHTTP(rec, req)
				var resp struct {
					Action string `json:"action"`
				}
				if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
					t.Fatalf("%s: answer is not JSON", name)
				}
				// The strict tier keeps its own reading of what it cannot prove.
				if pack != "strict" && resp.Action == "block" {
					t.Errorf("%s %s: blocked a benign project write script", pack, name)
				}
				t.Logf("%s %s: %s", pack, name, resp.Action)
			}
		})
	}
}
