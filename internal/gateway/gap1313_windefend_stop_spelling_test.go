// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

const gap1313Rule = "tamper.endpoint_security_product_disable"

// A WinDefend service stop beside other WinDefend sc steps but no sc config
// of its start type (stop+query, query+stop, stop+stop) is no partial disable
// sequence: the stop keeps the finding it proves alone, in the CMD reading
// and the Git Bash reading of a Windows hook host, as the PowerShell reading
// of the same steps does (rel-1-0-10:GAP-1313). The closed sequence proof
// still owns a call with a start-type config (GAP-1194): a stop beside a
// restore (start= auto) is not newly flagged. A query alone is no finding.
func TestGAP1313WinDefendStopIsAFindingInEverySpelling(t *testing.T) {
	cmd := actionfacts.DialectCMD
	for _, pack := range []string{"default", "strict"} {
		installToolCallCorpusProfileConnector(t, "codex", pack)
		for _, row := range []struct {
			command string
			want    bool
		}{
			{"sc stop WinDefend\nsc query WinDefend", true},
			{"sc query WinDefend\nsc stop WinDefend", true},
			{"sc stop WinDefend\nsc stop WinDefend", true},
			{"sc query WinDefend\nsc query WinDefend", false},
		} {
			input := actionfacts.Input{Tool: "shell", Command: row.command, CWD: `C:\repo`, ActiveHome: `C:\Users\fixture`, DialectHint: cmd}
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: row.command, Connector: "codex", EnforcementCapable: true,
			})
			got := slices.ContainsFunc(findings, func(f RuleFinding) bool {
				return f.RuleID == gap1313Rule && f.contributesToEnforcement()
			})
			if got != row.want {
				t.Errorf("%s CMD %q: enforcing endpoint finding %v, want %v; findings %v", pack, row.command, got, row.want, gap1313IDs(findings))
			}
		}
	}
	root := windowsLiveShapePacks(t)
	for _, tier := range []struct {
		name, pack string
		managed    bool
	}{
		{"default", "default", false}, {"permissive", "permissive", false}, {"strict", "strict", false},
		{"managed", "default", true}, {"managed-strict", "strict", true},
	} {
		for _, row := range []struct {
			command string
			want    bool
		}{
			{`sc.exe stop WinDefend; sc.exe query WinDefend`, true},
			{`sc.exe query WinDefend; sc.exe stop WinDefend`, true},
			{`sc.exe stop WinDefend; sc.exe stop WinDefend`, true},
			// The restore and a status read stay unflagged.
			{`sc.exe stop WinDefend; sc.exe config WinDefend start= auto; sc.exe query WinDefend`, false},
			{`sc.exe query WinDefend; sc.exe query WinDefend`, false},
		} {
			action, rules := gap1313ClaudeCodeBashHook(t, filepath.Join(root, tier.pack), row.command, tier.managed)
			if got := slices.Contains(rules, gap1313Rule); got != row.want {
				t.Errorf("%s claudecode Bash %q: %s, endpoint finding %v, want %v; rules %v", tier.name, row.command, action, got, row.want, rules)
			}
			if row.want && action == "allow" {
				t.Errorf("%s claudecode Bash %q: allow, want at least alert", tier.name, row.command)
			}
		}
	}
}

func gap1313IDs(findings []RuleFinding) string {
	var ids []string
	for _, f := range findings {
		ids = append(ids, f.RuleID)
	}
	return strings.Join(ids, ",")
}

// gap1313ClaudeCodeBashHook asks the Claude Code hook (the Bash tool, read
// as Git Bash on a Windows host) for one command.
func gap1313ClaudeCodeBashHook(t *testing.T, packDir, command string, managed bool) (string, []string) {
	t.Helper()
	installToolCallCorpusPackDirConnector(t, "claudecode", packDir)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.RulePackDir = packDir
	previous := windowsHookHost
	windowsHookHost = func() bool { return true }
	defer func() { windowsHookHost = previous }()
	body, err := json.Marshal(map[string]any{
		"session_id": "gap1313", "hook_event_name": "PreToolUse", "cwd": `C:\Users\fixture\work`,
		"tool_name": "Bash", "tool_use_id": "call-1", "tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: `C:\Users\fixture`}))
	}
	rec := httptest.NewRecorder()
	(&APIServer{scannerCfg: cfg, health: NewSidecarHealth()}).handleAgentHook("claudecode").ServeHTTP(rec, req)
	var got struct {
		Action  string   `json:"action"`
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || got.Action == "" {
		t.Fatalf("hook answer %q is not a decision", rec.Body.String())
	}
	return got.Action, got.RuleIDs
}
