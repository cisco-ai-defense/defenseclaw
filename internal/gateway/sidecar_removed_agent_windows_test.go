// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// A real Amp admission failure on Windows enters the same multi-connector
// start as the per-user installer. The retained plugin receives a named block
// if Amp returns before the next start; the next start admits it again.
func TestWindowsAmpRemovedAgentKeepsClaudeCodeGuarded(t *testing.T) {
	f := newAgentSettingsRefusalFixture(t)
	f.cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"amp":        {},
		"claudecode": {RulePackDir: meetRulePackDir(t, testenv.PrivateTempDir(t), "CF492-WIN"), BlockAt: "HIGH"},
	}
	profile := filepath.Dir(filepath.Dir(f.claudeSettings))
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current Windows user: %v", err)
	}
	for _, path := range []string{filepath.Dir(f.claudeSettings), f.claudeSettings} {
		if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
			windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
			t.Fatalf("own Claude Code fixture %s: %v", path, err)
		}
	}
	systemRoot := os.Getenv("SystemRoot")
	t.Setenv("PATH", strings.Join([]string{
		filepath.Join(systemRoot, "System32"), systemRoot,
		filepath.Join(os.Getenv("ProgramFiles"), "PowerShell", "7"),
		filepath.Join(os.Getenv("ProgramFiles"), "Git", "bin"),
	}, string(os.PathListSeparator)))
	t.Setenv("USERPROFILE", profile)
	roaming := filepath.Join(profile, "AppData", "Roaming")
	local := filepath.Join(profile, "AppData", "Local")
	for _, dir := range []string{roaming, local} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("APPDATA", roaming)
	t.Setenv("LOCALAPPDATA", local)
	packageDir := filepath.Join(roaming, "npm", "node_modules", "@ampcode", "cli")
	fixture := prepareAmpGatewayAuthorityFixtureAtPath(t, f.dataDir, filepath.Join(packageDir, "bin", "amp.exe"))
	s, err := f.boot(t)
	if err != nil || !reflect.DeepEqual(f.running(s), []string{"amp", "claudecode"}) {
		t.Fatalf("first Windows start: err=%v running=%v", err, f.running(s))
	}
	if err := os.Remove(filepath.Join(f.dataDir, "agent_selection.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(fixture.executablePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Dir(fixture.executablePath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(packageDir); err != nil {
		t.Fatal(err)
	}
	s, err = f.boot(t)
	if err != nil || !reflect.DeepEqual(f.running(s), []string{"claudecode"}) {
		t.Fatalf("removed Amp start: err=%v running=%v", err, f.running(s))
	}
	reason := fmt.Sprint(s.health.Snapshot().Guardrail.Details[GuardrailAgentSettingsRefused])
	if !strings.Contains(reason, "amp:") || !strings.Contains(reason, "the agent is not installed for this account") {
		t.Fatalf("removed Amp reason = %s", reason)
	}
	api := &APIServer{health: s.health, scannerCfg: f.cfg}
	if ids := findingIDs(ScanAllRulesForConnector("claudecode", "CF492-WIN_fixture_marker", "Bash")); !containsRuleID(ids, "CF492-WIN-FIXTURE") {
		t.Fatalf("surviving connector rule ids = %v, want its own marker rule", ids)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(
		`{"hook_event_name":"PreToolUse","session_id":"peer-claude","tool_name":"Bash","tool_input":{"command":"echo benign"}}`))
	response := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(response, request)
	var peerVerdict struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &peerVerdict); err != nil || peerVerdict.Action != "allow" {
		t.Fatalf("peer Claude Code benign call: err=%v status=%d answer=%s", err, response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(
		`{"hook_event_name":"PreToolUse","session_id":"peer-claude-protected","tool_name":"Bash","tool_input":{"command":"rm -rf /"}}`))
	response = httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(response, request)
	if err := json.Unmarshal(response.Body.Bytes(), &peerVerdict); err != nil || peerVerdict.Action != "block" {
		t.Fatalf("peer Claude Code protected call: err=%v status=%d answer=%s", err, response.Code, response.Body.String())
	}
	if err := os.MkdirAll(filepath.Dir(fixture.executablePath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.executablePath, []byte("MZ native Amp gateway fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/amp/hook", strings.NewReader(
		`{"hook_event_name":"tool.call","session_id":"returned-amp","tool_name":"bash","tool_input":{"command":"echo benign"}}`))
	response = httptest.NewRecorder()
	api.handleAgentHook("amp").ServeHTTP(response, request)
	var verdict struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &verdict); err != nil {
		t.Fatalf("returned Amp answer %d: %v: %s", response.Code, err, response.Body.String())
	}
	if verdict.Action != "block" || !strings.Contains(verdict.Reason, "defenseclaw-gateway restart") {
		t.Fatalf("returned Amp answer = %+v, want named block until restart", verdict)
	}
	s, err = f.boot(t)
	if err != nil || !reflect.DeepEqual(f.running(s), []string{"amp", "claudecode"}) {
		t.Fatalf("re-admitted Amp start: err=%v running=%v", err, f.running(s))
	}
}
