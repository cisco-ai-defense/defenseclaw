// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

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

// The Windows twin of apply_patch_absolute_targets_test.go: a Codex or
// Copilot CLI apply_patch that names a protected file of the account by its
// drive path (C:\Users\<u>\...) or its root-relative path (\Users\<u>\...)
// is judged by the path rule of that file, and project patches by drive
// path stay allowed (rel-1-0-6:GAP-0361, GAP-0398).

type windowsPatchFixture struct{ home, project string }

func newWindowsPatchFixture(t *testing.T) windowsPatchFixture {
	t.Helper()
	home := filepath.Join(t.TempDir(), "alice")
	f := windowsPatchFixture{home: home, project: filepath.Join(home, "proj")}
	for _, dir := range []string{".ssh", ".defenseclaw", `proj\.git\hooks`, `proj\src`, `proj\docs`} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{`.ssh\authorized_keys`, `.defenseclaw\config.yaml`, `proj\src\main.go`, `proj\README.md`, `proj\.git\hooks\pre-commit`} {
		if err := os.WriteFile(filepath.Join(home, file), []byte("a\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	return f
}

// path fills {H} (home) and {P} (project); a leading {R} makes the result
// root-relative, the drive path without its drive.
func (f windowsPatchFixture) path(template string) string {
	rootRelative := strings.HasPrefix(template, "{R}")
	value := strings.NewReplacer("{R}", "", "{H}", f.home, "{P}", f.project).Replace(template)
	if rootRelative {
		value = strings.TrimPrefix(value, filepath.VolumeName(value))
	}
	return value
}

func postWindowsApplyPatch(t *testing.T, f windowsPatchFixture, connectorName, profile, patch string) (string, string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, profile)
	var body map[string]any
	if connectorName == "codex" {
		body = map[string]any{"session_id": "gap0398", "hook_event_name": "PreToolUse", "cwd": f.project, "permission_mode": "default",
			"tool_name": "apply_patch", "tool_use_id": "toolu_gap0398", "tool_input": map[string]any{"command": patch}}
	} else {
		body = map[string]any{"sessionId": "gap0398", "timestamp": 1790483549431, "cwd": f.project, "toolName": "apply_patch", "toolArgs": patch}
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

func windowsUpdatePatch(target string) string {
	return "*** Begin Patch\n*** Update File: " + target + "\n@@\n a\n+b\n*** End Patch\n"
}

func TestWindowsApplyPatchAbsoluteTargetsAreJudged(t *testing.T) {
	rows := []struct {
		target, rule string
		critical     bool
	}{
		{`{H}\.ssh\authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`{R}{H}\.ssh\authorized_keys`, "persistence.ssh_authorized_keys_command", true},
		{`{H}\.defenseclaw\config.yaml`, "tamper.detector_state_write", true},
		{`{P}\.git\hooks\pre-commit`, "persistence.git_hook_write", false},
		{`{R}{P}\.git\hooks\pre-commit`, "persistence.git_hook_write", false},
		{`{R}{H}\.defenseclaw\config.yaml`, "tamper.detector_state_write", true},
	}
	for _, profile := range []string{"default", "strict"} {
		for _, connectorName := range []string{"codex", "copilot"} {
			for _, row := range rows {
				t.Run(profile+"/"+connectorName+"/"+row.target, func(t *testing.T) {
					f := newWindowsPatchFixture(t)
					got, out := postWindowsApplyPatch(t, f, connectorName, profile, windowsUpdatePatch(f.path(row.target)))
					if !strings.Contains(out, row.rule) {
						t.Fatalf("the patch of %s does not name %s: %.600s", f.path(row.target), row.rule, out)
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

func TestWindowsApplyPatchProjectTargetsStayAllowed(t *testing.T) {
	patches := map[string]string{
		"relative update":      windowsUpdatePatch(`src\main.go`),
		"drive-path update":    windowsUpdatePatch(`{P}\src\main.go`),
		"drive-path README":    windowsUpdatePatch(`{P}\README.md`),
		"drive-path add":       "*** Begin Patch\n*** Add File: {P}\\src\\new.go\n+package src\n*** End Patch\n",
		"drive-path doc name":  "*** Begin Patch\n*** Add File: {P}\\docs\\authorized_keys.md\n+x\n*** End Patch\n",
		"root-relative update": windowsUpdatePatch(`{R}{P}\src\main.go`),
	}
	for _, profile := range []string{"default", "strict"} {
		for _, connectorName := range []string{"codex", "copilot"} {
			for name, patch := range patches {
				t.Run(profile+"/"+connectorName+"/"+name, func(t *testing.T) {
					f := newWindowsPatchFixture(t)
					got, out := postWindowsApplyPatch(t, f, connectorName, profile, f.path(patch))
					if got != "allow" {
						t.Fatalf("decision %s, want allow: %.600s", got, out)
					}
				})
			}
		}
	}
}
