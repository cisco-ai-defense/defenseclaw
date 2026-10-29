// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// protectHomeCodexHandler drives the Codex hook handler of a managed POSIX
// gateway that cannot read the caller's home (ProtectHome) as the managed
// hook does: the hook client resolves each body as the user (its evidence
// header), then the home is closed for the gateway's request, so the
// handler's decode clears the request's working directory
// (hookCWDForContext) as it does on a ProtectHome host.
type protectHomeCodexHandler struct {
	t       *testing.T
	api     *APIServer
	handler http.HandlerFunc
	home    string
	base    string
	session string
}

func newProtectHomeCodexHandler(t *testing.T, mode string) *protectHomeCodexHandler {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a managed POSIX gateway")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a closed home")
	}
	home := filepath.Join(t.TempDir(), "home")
	base := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(base, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	api := instructionProtectionTestAPI(t, "codex", mode, "HIGH")
	api.scannerCfg.DataDir = t.TempDir()
	return &protectHomeCodexHandler{t: t, api: api, handler: api.handleUnifiedConnectorHook("codex"), home: home, base: base, session: "live"}
}

func (h *protectHomeCodexHandler) post(event, cwd string, extra map[string]interface{}) (string, []string) {
	h.t.Helper()
	body := map[string]interface{}{"hook_event_name": event, "session_id": h.session, "cwd": cwd}
	for key, value := range extra {
		body[key] = value
	}
	raw := mustJSON(h.t, body)
	evidence := hookpaths.ResolveConnector("codex", "", event, raw)
	if evidence == "" {
		h.t.Fatalf("the managed hook sent no evidence for %s", event)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/codex/hook", bytes.NewReader(raw))
	req.Header.Set("X-DefenseClaw-Hook-Event", event)
	req.Header.Set("X-DefenseClaw-Hook-Contract", h.api.hookProfileForConnector("codex").ContractID)
	req.Header.Set(hookpaths.Header, evidence)
	ctx := withManagedHookPeer(withAuthenticatedHookConnector(context.Background(), "codex"),
		managedHookPeer{UID: os.Getuid(), Home: h.home})
	if err := os.Chmod(h.home, 0); err != nil {
		h.t.Fatal(err)
	}
	defer func() { _ = os.Chmod(h.home, 0o700) }()
	if _, err := os.Lstat(filepath.Join(h.base, "x")); err == nil || os.IsNotExist(err) {
		h.t.Skip("the home stays readable")
	}
	if resolved := hookCWDForContext(ctx, cwd); resolved != "" {
		h.t.Fatalf("the gateway resolved the closed project %q", resolved)
	}
	rec := httptest.NewRecorder()
	h.handler(rec, req.WithContext(ctx))
	if rec.Code != http.StatusOK {
		h.t.Fatalf("%s status %d: %s", event, rec.Code, rec.Body.String())
	}
	var out map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		h.t.Fatalf("%s answer: %v", event, err)
	}
	action, _ := out["action"].(string)
	var findings []string
	if list, ok := out["findings"].([]interface{}); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				findings = append(findings, text)
			}
		}
	}
	return action, findings
}

func (h *protectHomeCodexHandler) start() {
	h.t.Helper()
	h.post("SessionStart", h.base, map[string]interface{}{"source": "startup"})
}

func (h *protectHomeCodexHandler) bash(cwd, command string) (string, []string) {
	h.t.Helper()
	return h.post("PreToolUse", cwd, map[string]interface{}{"tool_name": "Bash", "tool_input": map[string]interface{}{"command": command}})
}

func (h *protectHomeCodexHandler) patch(cwd, patch string) (string, []string) {
	h.t.Helper()
	return h.post("PreToolUse", cwd, map[string]interface{}{"tool_name": "apply_patch", "tool_input": map[string]interface{}{"command": patch}})
}

// Protected-target corpus (GAP-1462, P1). On a managed POSIX gateway behind
// ProtectHome, the AGENTS.md a Codex session started with stays protected in
// action through the hook handler: an absolute, relative, patch, parent
// directory, symlink alias or hard-link write blocks COG-AGENTS-MD. The
// gateway places the project by the directory the managed hook client ran
// the call in as the user (hookpaths.CWDKey), at the start and at each call.
func TestInstructionProtectHomeCodexStartupFileStaysProtected(t *testing.T) {
	type write struct {
		name string
		run  func(h *protectHomeCodexHandler) (string, []string)
	}
	agents := func(h *protectHomeCodexHandler) string { return filepath.Join(h.base, "AGENTS.md") }
	writes := []write{
		{"absolute append", func(h *protectHomeCodexHandler) (string, []string) {
			return h.bash(h.base, "printf x >> "+agents(h))
		}},
		{"relative append", func(h *protectHomeCodexHandler) (string, []string) {
			return h.bash(h.base, "printf x >> AGENTS.md")
		}},
		{"relative patch", func(h *protectHomeCodexHandler) (string, []string) {
			return h.patch(h.base, sightingUpdatePatch)
		}},
		{"absolute patch", func(h *protectHomeCodexHandler) (string, []string) {
			return h.patch(h.base, "*** Begin Patch\n*** Update File: "+agents(h)+"\n@@\n-x\n+new\n*** End Patch")
		}},
		{"parent from a subdirectory", func(h *protectHomeCodexHandler) (string, []string) {
			return h.bash(filepath.Join(h.base, "sub"), "printf x >> "+agents(h))
		}},
		{"symlink alias", func(h *protectHomeCodexHandler) (string, []string) {
			alias := filepath.Join(h.home, "alias.md")
			if err := os.Symlink(agents(h), alias); err != nil {
				h.t.Skipf("symlinks unavailable: %v", err)
			}
			return h.bash(h.base, "printf x >> "+alias)
		}},
		{"hard link", func(h *protectHomeCodexHandler) (string, []string) {
			if err := os.Link(agents(h), filepath.Join(h.base, "notes.txt")); err != nil {
				h.t.Skipf("hard links unavailable: %v", err)
			}
			return h.bash(h.base, "printf x >> notes.txt")
		}},
	}
	for _, w := range writes {
		t.Run(w.name, func(t *testing.T) {
			h := newProtectHomeCodexHandler(t, "action")
			writeActiveAgentTestFile(t, h.base, "AGENTS.md")
			h.start()
			if action, findings := w.run(h); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-AGENTS-MD") {
				t.Fatalf("a write to the AGENTS.md the session started with ran behind ProtectHome: action=%q findings=%v", action, findings)
			}
		})
	}
	t.Run("observe audits only", func(t *testing.T) {
		h := newProtectHomeCodexHandler(t, "observe")
		writeActiveAgentTestFile(t, h.base, "AGENTS.md")
		h.start()
		if action, findings := h.bash(h.base, "printf x >> "+agents(h)); action == guardrailActionBlock {
			t.Fatalf("observe blocked: %v", findings)
		}
	})
}

// Benign corpus (GAP-1462). Behind ProtectHome, the AGENTS.md a Codex
// session creates in its project is its own: creating it and editing it
// (patch and shell append, relative and absolute) never meets an
// instruction rule in action, nor does an ordinary file write. (cogBlocked,
// as the hidden-home corpus: the fixture's hook reads this process's home,
// not the caller home the gateway is given.)
func TestInstructionBenignProtectHomeCodexSessionCreatedFile(t *testing.T) {
	h := newProtectHomeCodexHandler(t, "action")
	h.start()
	steps := []struct {
		name string
		run  func() (string, []string)
	}{
		{"create", func() (string, []string) { return h.patch(h.base, sightingAddPatch) }},
		{"edit by patch", func() (string, []string) { return h.patch(h.base, sightingUpdatePatch) }},
		{"absolute append", func() (string, []string) {
			return h.bash(h.base, "printf x >> "+filepath.Join(h.base, "AGENTS.md"))
		}},
		{"relative append", func() (string, []string) { return h.bash(h.base, "printf x >> AGENTS.md") }},
		{"ordinary file", func() (string, []string) { return h.bash(h.base, "printf x >> notes2.txt") }},
	}
	for index, step := range steps {
		action, findings := step.run()
		if cogBlocked(action, false, findings) {
			t.Fatalf("%s of the session's own AGENTS.md was blocked: %v", step.name, findings)
		}
		if index == 0 {
			writeActiveAgentTestFile(t, h.base, "AGENTS.md")
		}
	}
}

// managedClientCWD keeps the managed hook client's directory only for a
// call the gateway could not place itself, from a kernel-verified managed
// caller, inside that caller's home, and never for a sandbox, a per-user
// gateway, or a directory outside the home or spelled with "..".
func TestManagedClientCWDIsBoundToTheVerifiedCallerHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a managed POSIX gateway")
	}
	home := filepath.Join(t.TempDir(), "home")
	project := filepath.Join(home, "project")
	managed := withManagedHookPeer(t.Context(), managedHookPeer{UID: 1001, Home: home})
	evidence := func(cwd string) map[string]string { return map[string]string{hookpaths.CWDKey: cwd} }
	cases := []struct {
		name     string
		ctx      context.Context
		cwd      string
		evidence map[string]string
		want     string
	}{
		{"project in the home", managed, "", evidence(project), project},
		{"the home itself", managed, "", evidence(home), home},
		{"unclean spelling", managed, "", evidence(project + "/./"), project},
		{"gateway resolved its own", managed, "/srv/own", evidence(project), "/srv/own"},
		{"outside the home", managed, "", evidence("/srv/project"), ""},
		{"another home", managed, "", evidence(home + "-other/project"), ""},
		{"parent element", managed, "", evidence(home + "/../x"), ""},
		{"relative", managed, "", evidence("project"), ""},
		{"no evidence", managed, "", nil, ""},
		{"malformed evidence marker only", managed, "", map[string]string{hookpaths.TruncatedKey: "1"}, ""},
		{"per-user gateway", t.Context(), "", evidence(project), ""},
		{"caller home unknown", withManagedHookPeer(t.Context(), managedHookPeer{UID: 1001}), "", evidence(project), ""},
	}
	for _, c := range cases {
		if got := managedClientCWD(c.ctx, c.cwd, c.evidence); got != c.want {
			t.Errorf("%s: managedClientCWD = %q, want %q", c.name, got, c.want)
		}
	}
	// The managed hook's startup evidence names the directory it read.
	body := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "s", "cwd": project})
	facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", body))
	if !ok || facts[hookpaths.CWDKey] != project {
		t.Fatalf("startup evidence cwd = %q (ok %v), want %q", facts[hookpaths.CWDKey], ok, project)
	}
}
