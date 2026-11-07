// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// rel-1-0-6:GAP-0729: a file-tool write to DefenseClaw state is the write
// of the state file whichever spelling of the volume names it: the drive
// path, the \\?\ and \\.\ prefixes, the \\?\UNC\ form, and the
// \\localhost\C$ and \\127.0.0.1\C$ administrative shares. A file of the
// project in the same spellings stays allowed. 8.3 short names, junctions
// and a call with an extra argument key need the Windows file system or
// belong to the argument-key class, and are proved elsewhere.
func TestG235bWindowsVolumeAliasesOfStateAreSelfProtection(t *testing.T) {
	const home = `C:\Users\vn`
	state := home + `\.defenseclaw\config.yaml`
	project := home + `\proj\notes.txt`
	alias := func(file string) []string {
		rest := strings.TrimPrefix(file, `C:\`)
		return []string{file, `\\?\` + file, `\\.\` + file, `\\?\UNC\localhost\C$\` + rest,
			`\\localhost\C$\` + rest, `\\127.0.0.1\C$\` + rest, `//localhost/C$/` + strings.ReplaceAll(rest, `\`, "/")}
	}
	for _, tool := range []string{"Write", "Edit"} {
		for _, managed := range []bool{false, true} {
			for _, pack := range []string{"", "strict", "permissive"} {
				for _, protected := range []bool{true, false} {
					target := project
					if protected {
						target = state
					}
					for _, file := range alias(target) {
						input := map[string]any{"file_path": file, "content": "x"}
						if tool == "Edit" {
							input = map[string]any{"file_path": file, "old_string": "a", "new_string": "b"}
						}
						cfg := &config.Config{}
						cfg.Guardrail.Mode = "action"
						cfg.Guardrail.Connector = "claudecode"
						cfg.Guardrail.RulePack = pack
						api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
						body := mustJSON(t, map[string]any{"session_id": "s", "hook_event_name": "PreToolUse",
							"tool_name": tool, "cwd": home + `\proj`, "tool_input": input})
						req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(body)))
						if managed {
							req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
							req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
						}
						rec := httptest.NewRecorder()
						api.handleAgentHook("claudecode").ServeHTTP(rec, req)
						got := rec.Body.String()
						block := strings.HasPrefix(got, `{"action":"block"`)
						if protected && (!block || !strings.Contains(got, "tamper.detector_state_write")) {
							t.Errorf("%s managed=%t pack=%s %s = %.160s, want protected block", tool, managed, pack, file, got)
						}
						if !protected && block {
							t.Errorf("%s managed=%t pack=%s %s = %.160s, want allow", tool, managed, pack, file, got)
						}
					}
				}
			}
		}
	}
}
