// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// The inspect endpoint is OpenClaw's native before-tool-call surface. A file
// created by this session was absent when the first call was inspected; its
// next edit is still ordinary work, including after a gateway restart.
func TestInstructionProtectionInspectCreationStaysWritableUntilNextSession(t *testing.T) {
	for _, connectorName := range []string{"openclaw", "zeptoclaw"} {
		t.Run(connectorName, func(t *testing.T) {
			installToolCallCorpusProfileConnector(t, connectorName, "default")
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			project := filepath.Join(home, ".openclaw", "workspace")
			if err := os.MkdirAll(project, 0o700); err != nil {
				t.Fatal(err)
			}
			dataDir := t.TempDir()
			target := filepath.Join(project, "SOUL.md")
			loaded := filepath.Join(project, "AGENTS.md")
			if err := os.WriteFile(loaded, []byte("loaded\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			command := "printf new >> '" + target + "'"
			loadedCommand := "printf new >> '" + loaded + "'"
			if runtime.GOOS == "windows" {
				command = "Add-Content -LiteralPath '" + target + "' -Value new"
				loadedCommand = "Add-Content -LiteralPath '" + loaded + "' -Value new"
			}
			newGateway := func() *APIServer {
				api := testAPIServerWithConfig(t, "action")
				api.scannerCfg.Guardrail.Connector = connectorName
				api.scannerCfg.Guardrail.BlockAt = "HIGH"
				api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
				api.scannerCfg.DataDir = dataDir
				return api
			}
			inspect := func(api *APIServer, session, writeCommand string) ToolInspectVerdict {
				t.Helper()
				body := mustJSON(t, map[string]interface{}{
					"tool": "exec", "direction": "tool_call", "session_id": session,
					"args": map[string]interface{}{"command": writeCommand, "workdir": project},
				})
				_, verdict := postInspectForConnector(t, api, connectorName, string(body))
				return verdict
			}
			api := newGateway()
			if got := inspect(api, "first", command); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("first write of absent SOUL.md: %+v", got)
			}
			if got := inspect(api, "first", loadedCommand); got.Action != guardrailActionBlock ||
				!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
				t.Fatalf("startup AGENTS.md lost protection: %+v", got)
			}
			if err := os.WriteFile(target, []byte("new\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := inspect(api, "first", command); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("next edit in the same session: %+v", got)
			}
			api = newGateway()
			if got := inspect(api, "first", command); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("next edit after gateway restart: %+v", got)
			}
			if got := inspect(api, "second", command); got.Action != guardrailActionBlock ||
				!findingStringHasRuleID(got.Findings, "COG-SOUL") {
				t.Fatalf("new session did not protect loaded SOUL.md: %+v", got)
			}
		})
	}
}
