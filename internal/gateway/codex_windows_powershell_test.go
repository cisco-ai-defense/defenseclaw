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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestCodexWindowsCmdletWritesReachCELBlockRules pins GAP-0175: on Windows
// Codex runs its Bash tool's commands in PowerShell, so a cmdlet write of
// the marker is blocked by a CEL rule on the command's argv, as echo is. It
// was parsed as POSIX, partial, and only a detection-only candidate.
func TestCodexWindowsCmdletWritesReachCELBlockRules(t *testing.T) {
	resetConnectorRuleCategories(t)
	if err := ApplyRulePackOverrides(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version: 1, Category: "dccert-marker", Rules: []guardrail.RuleDefYAML{{
			ID: "DCCERT-MARKER-BLOCK", ToolCallOnly: true,
			Expression: "f.commands.exists(c, 'dccert-block-marker' in c.argv)",
			Pattern:    "dccert-block-marker", Title: "Certification marker command", Severity: "CRITICAL", Confidence: 0.99,
		}},
	}}}); err != nil {
		t.Fatal(err)
	}
	previous := codexShellRunsPowerShell
	codexShellRunsPowerShell = true
	t.Cleanup(func() { codexShellRunsPowerShell = previous })

	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	api := &APIServer{scannerCfg: cfg}
	cwd := t.TempDir()
	for _, command := range []string{
		"Set-Content -Path f.txt -Value dccert-block-marker -NoNewline",
		"Set-Content -Path f.txt -Value dccert-block-marker",
		"Add-Content -Path f.txt -Value dccert-block-marker -NoNewline",
		"Out-File -FilePath f.txt -InputObject dccert-block-marker -Encoding utf8",
		"echo dccert-block-marker > f.txt",
		"Set-Content -Path f.txt -Value hello",
	} {
		resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
			HookEventName: "PreToolUse", ToolName: "Bash", CWD: cwd,
			ToolInput: map[string]interface{}{"command": command},
		})
		want := "block"
		if command == "Set-Content -Path f.txt -Value hello" {
			want = "allow"
		}
		if resp.RawAction != want {
			t.Errorf("%q: raw_action = %q (action %q, reason %q), want %s", command, resp.RawAction, resp.Action, resp.Reason, want)
		}
	}
}
