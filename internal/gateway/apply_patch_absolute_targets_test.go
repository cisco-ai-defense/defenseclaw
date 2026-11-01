// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The rows name POSIX targets (/etc/sudoers, ~/.zshrc) and a POSIX managed
// peer; the parser rows in internal/actionfacts cover drive paths.

//go:build !windows

package gateway

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// absolutePatchFixture is one account: home h with its shell, history,
// keys and DefenseClaw files, and the project p (a git checkout).
type absolutePatchFixture struct{ home, project string }

func newAbsolutePatchFixture(t *testing.T) absolutePatchFixture {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	f := absolutePatchFixture{home: home, project: filepath.Join(home, "proj")}
	for _, dir := range []string{".ssh", ".defenseclaw", "proj/.git/hooks", "proj/src", "proj/docs"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{".zshrc", ".bashrc", ".bash_history", ".ssh/authorized_keys", ".defenseclaw/config.yaml",
		"proj/src/main.go", "proj/README.md", "proj/docs/zshrc.example", "proj/.git/hooks/pre-commit"} {
		if err := os.WriteFile(filepath.Join(home, file), []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return f
}

func (f absolutePatchFixture) path(template string) string {
	return strings.NewReplacer("{H}", f.home, "{P}", f.project).Replace(template)
}

// postApplyPatch posts one apply_patch call of patch to the Codex or
// Copilot CLI hook in action mode on the profile pack, per-user or as a
// managed gateway that knows the caller, and returns the decision (block,
// alert or allow) and the response.
func postApplyPatch(t *testing.T, f absolutePatchFixture, connectorName, profile string, managed bool, patch string) (string, string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, profile)
	var body map[string]any
	if connectorName == "codex" {
		body = map[string]any{"session_id": "gap0361", "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default",
			"tool_name": "apply_patch", "tool_use_id": "toolu_gap0361", "tool_input": map[string]any{"command": patch}}
	} else {
		body = map[string]any{"sessionId": "gap0361", "timestamp": 1790483549431, "cwd": f.project, "toolName": "apply_patch", "toolArgs": patch}
	}
	raw := string(mustJSON(t, body))
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), profile)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if connectorName == "copilot" {
		req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
		req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", "", "preToolUse", []byte(raw)))
	} else {
		req.Header.Set(hookpaths.Header, hookpaths.Resolve([]byte(raw)))
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	if managed {
		req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: f.home}))
	}
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	out := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.400s", recorder.Code, out)
	}
	switch {
	case strings.Contains(out, `"action":"block"`) || strings.Contains(out, `"permissionDecision":"deny"`):
		return "block", out
	case strings.Contains(out, `"action":"alert"`):
		return "alert", out
	default:
		return "allow", out
	}
}

func updatePatch(target string) string {
	return "*** Begin Patch\n*** Update File: " + target + "\n@@\n a\n+b\n*** End Patch\n"
}

// TestApplyPatchAbsoluteTargetsAreJudged: a Codex or Copilot CLI apply_patch
// that names a protected file by its absolute path is judged by the path
// rule of that file, as the same patch with a relative path is
// (rel-1-0-6:GAP-0361). Each rule keeps its severity, so strict refuses
// every row and the default pack refuses the CRITICAL ones and alerts on
// the HIGH ones.
func TestApplyPatchAbsoluteTargetsAreJudged(t *testing.T) {
	rows := []struct {
		target, rule string
		critical     bool // blocks in the default pack too
	}{
		{"/etc/sudoers", "PATH-ETC-SUDOERS", false},
		{"/etc/shadow", "PATH-ETC-SHADOW", true},
		{"{H}/.zshrc", "persistence.shell_profile_write", false},
		{"{H}/.bashrc", "persistence.shell_profile_write", false},
		{"{H}/.bash_history", "PATH-HISTORY", false},
		{"{P}/.git/hooks/pre-commit", "persistence.git_hook_write", false},
		{"{H}/.defenseclaw/config.yaml", "tamper.detector_state_write", true},
		{"{H}/.ssh/authorized_keys", "persistence.ssh_authorized_keys_command", true},
	}
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, connectorName := range []string{"codex", "copilot"} {
				for _, row := range rows {
					name := profile + "/" + map[bool]string{false: "per-user", true: "managed"}[managed] + "/" + connectorName + "/" + row.target
					t.Run(name, func(t *testing.T) {
						f := newAbsolutePatchFixture(t)
						got, out := postApplyPatch(t, f, connectorName, profile, managed, updatePatch(f.path(row.target)))
						if !strings.Contains(out, row.rule) {
							t.Fatalf("the absolute patch of %s does not name %s: %.600s", row.target, row.rule, out)
						}
						want := "alert"
						if profile == "strict" || row.critical {
							want = "block"
						}
						if got != want {
							t.Fatalf("decision %s, want %s: %.600s", got, want, out)
						}
					})
				}
			}
		}
	}
}

// TestApplyPatchProjectTargetsStayAllowed: ordinary project patches, by
// relative or absolute path, stay allowed with no path finding.
func TestApplyPatchProjectTargetsStayAllowed(t *testing.T) {
	patches := map[string]string{
		"relative update":          updatePatch("src/main.go"),
		"absolute update":          updatePatch("{P}/src/main.go"),
		"absolute README":          updatePatch("{P}/README.md"),
		"absolute name-alike":      updatePatch("{P}/docs/zshrc.example"),
		"absolute add":             "*** Begin Patch\n*** Add File: {P}/src/new.go\n+package src\n*** End Patch\n",
		"absolute add and delete":  "*** Begin Patch\n*** Add File: {P}/docs/new.md\n+x\n*** Delete File: {P}/docs/zshrc.example\n*** End Patch\n",
		"absolute project sudoers": "*** Begin Patch\n*** Add File: {P}/etc/sudoers\n+Defaults env_reset\n*** End Patch\n",
	}
	for _, profile := range []string{"default", "strict"} {
		for _, managed := range []bool{false, true} {
			for _, connectorName := range []string{"codex", "copilot"} {
				for name, patch := range patches {
					t.Run(profile+"/"+map[bool]string{false: "per-user", true: "managed"}[managed]+"/"+connectorName+"/"+name, func(t *testing.T) {
						f := newAbsolutePatchFixture(t)
						got, out := postApplyPatch(t, f, connectorName, profile, managed, f.path(patch))
						if got != "allow" {
							t.Fatalf("decision %s, want allow: %.600s", got, out)
						}
						for _, rule := range []string{"PATH-ETC-SUDOERS", "persistence.shell_profile_write", "persistence.git_hook_write", "PATH-HISTORY", hookToolCallUnparsedRuleID} {
							if strings.Contains(out, rule) {
								t.Fatalf("a project patch names %s: %.600s", rule, out)
							}
						}
					})
				}
			}
		}
	}
}
