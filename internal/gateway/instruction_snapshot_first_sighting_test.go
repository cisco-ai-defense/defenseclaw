// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// managedHiddenHomeSession is a managed POSIX Codex session whose gateway,
// when hide is set, cannot read the user's home (ProtectHome): the hook
// client reads as the user, then the home is closed for the gateway's call.
type managedHiddenHomeSession struct {
	t       *testing.T
	home    string
	base    string
	hide    bool
	gateway func() *APIServer
}

func newManagedHiddenHomeSession(t *testing.T, hide bool) *managedHiddenHomeSession {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("a managed POSIX gateway")
	}
	if hide && os.Geteuid() == 0 {
		t.Skip("root reads a closed home")
	}
	home, dataDir := filepath.Join(t.TempDir(), "home"), t.TempDir()
	base := filepath.Join(home, "project")
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
	return &managedHiddenHomeSession{t: t, home: home, base: base, hide: hide, gateway: func() *APIServer {
		api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}}
}

func (s *managedHiddenHomeSession) judge(ctx context.Context, req codexHookRequest) codexHookResponse {
	s.t.Helper()
	ctx = withManagedHookPeer(withAuthenticatedHookConnector(ctx, "codex"), managedHookPeer{Home: s.home})
	if s.hide {
		if err := os.Chmod(s.home, 0); err != nil {
			s.t.Fatal(err)
		}
		defer func() { _ = os.Chmod(s.home, 0o700) }()
		if _, err := os.Lstat(filepath.Join(s.base, "x")); err == nil || os.IsNotExist(err) {
			s.t.Skip("the home stays readable")
		}
	}
	return s.gateway().evaluateCodexHook(ctx, req)
}

// start is a SessionStart; evidence false is a 1.0.3 managed hook's, which
// sends no startup evidence.
func (s *managedHiddenHomeSession) start(evidence bool) {
	s.t.Helper()
	ctx := s.t.Context()
	if evidence {
		body := mustJSON(s.t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": s.base})
		facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", body))
		if !ok {
			s.t.Fatal("managed hook did not send startup identity evidence")
		}
		ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
	}
	s.judge(ctx, codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: s.base})
}

func (s *managedHiddenHomeSession) call(cwd, tool string, input map[string]interface{}) codexHookResponse {
	s.t.Helper()
	return s.judge(instructionResolvedWriteContext(s.t, cwd, tool, input), codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "live", CWD: cwd, ToolName: tool, ToolInput: input,
	})
}

func (s *managedHiddenHomeSession) patch(cwd, patch string) codexHookResponse {
	s.t.Helper()
	return s.call(cwd, "apply_patch", map[string]interface{}{"command": patch})
}

// Benign corpus (GAP-1415 class, review loop round 2), with protected-target
// controls. A managed POSIX gateway that cannot read the user's home binds a
// directory the session created to its identity from the hook client's
// sighting of it, before it accepts another spelling: a symlink to it, or
// the name a mv of it gives it.
func TestInstructionBenignManagedCreatedDirectoryHiddenHome(t *testing.T) {
	create := func(t *testing.T, s *managedHiddenHomeSession) string {
		t.Helper()
		if got := s.patch(s.base, createdDirAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("creating new/AGENTS.md was blocked: %+v", got)
		}
		created := filepath.Join(s.base, "new")
		if err := os.Mkdir(created, 0o700); err != nil {
			t.Fatal(err)
		}
		writeActiveAgentTestFile(t, created, "AGENTS.md")
		return created
	}
	t.Run("symlink", func(t *testing.T) {
		s := newManagedHiddenHomeSession(t, true)
		s.start(true)
		created := create(t, s)
		link := filepath.Join(s.base, "link")
		if err := os.Symlink(created, link); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if got := s.patch(link, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("a symlink made the session's own AGENTS.md pre-existing: %+v", got)
		}
		if got := s.patch(created, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("the created directory lost its empty record: %+v", got)
		}
	})
	t.Run("mv", func(t *testing.T) {
		s := newManagedHiddenHomeSession(t, true)
		s.start(true)
		created := create(t, s)
		// A later call reaches the created directory before the mv: the
		// client's sighting of it binds its identity.
		if got := s.call(created, "Bash", map[string]interface{}{"command": "ls"}); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("ls was blocked: %+v", got)
		}
		if got := s.call(s.base, "Bash", map[string]interface{}{"command": "mv new renamed"}); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("mv of the session's own directory was blocked: %+v", got)
		}
		renamed := filepath.Join(s.base, "renamed")
		if err := os.Rename(filepath.Join(s.base, "new"), renamed); err != nil {
			t.Fatal(err)
		}
		if got := s.patch(renamed, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("a mv made the session's own AGENTS.md pre-existing: %+v", got)
		}
	})
	t.Run("a link at a missing spelling keeps its target protected", func(t *testing.T) {
		s := newManagedHiddenHomeSession(t, true)
		s.start(true)
		other := filepath.Join(s.home, "other")
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		writeActiveAgentTestFile(t, other, "AGENTS.md")
		if got := s.patch(s.base, createdDirAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("creating new/AGENTS.md was blocked: %+v", got)
		}
		if err := os.Symlink(other, filepath.Join(s.base, "new")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		// Through the link at the missing spelling and at the directory.
		for _, cwd := range []string{filepath.Join(s.base, "new"), other} {
			if got := s.patch(cwd, sightingUpdatePatch); got.Action != guardrailActionBlock ||
				!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
				t.Fatalf("a link at a missing spelling made an existing AGENTS.md writable at %s: %+v", cwd, got)
			}
		}
	})
	t.Run("a directory moved onto a missing spelling keeps its file protected", func(t *testing.T) {
		s := newManagedHiddenHomeSession(t, true)
		s.start(true)
		other := filepath.Join(s.home, "other")
		if err := os.Mkdir(other, 0o700); err != nil {
			t.Fatal(err)
		}
		writeActiveAgentTestFile(t, other, "AGENTS.md")
		if got := s.patch(s.base, createdDirAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("creating new/AGENTS.md was blocked: %+v", got)
		}
		// The session reaches other/ with its AGENTS.md first, then moves
		// it onto the missing new/.
		if got := s.patch(s.base, "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("an ordinary write was blocked: %+v", got)
		}
		if got := s.call(other, "Bash", map[string]interface{}{"command": "ls"}); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("ls was blocked: %+v", got)
		}
		if err := os.Rename(other, filepath.Join(s.base, "new")); err != nil {
			t.Fatal(err)
		}
		if got := s.patch(filepath.Join(s.base, "new"), sightingUpdatePatch); got.Action != guardrailActionBlock ||
			!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
			t.Fatalf("a directory moved onto a missing spelling made its AGENTS.md writable: %+v", got)
		}
	})
}

// Benign corpus (review loop round 2), with protected-target controls. A
// session whose start sent no startup evidence (a 1.0.3 managed hook during
// an upgrade) or that had no start event gets its first sighting at its
// first tool call: an AGENTS.md it creates after that stays editable, also
// after a gateway restart, and one that existed then stays protected. Later
// existence is never taken for startup proof.
func TestInstructionBenignFirstSightingWithoutStartupEvidence(t *testing.T) {
	cases := []struct {
		name  string
		hide  bool
		start func(s *managedHiddenHomeSession)
	}{
		{"managed 1.0.3 start", false, func(s *managedHiddenHomeSession) { s.start(false) }},
		{"managed 1.0.3 start, closed home", true, func(s *managedHiddenHomeSession) { s.start(false) }},
		{"managed, no start event", false, func(*managedHiddenHomeSession) {}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newManagedHiddenHomeSession(t, tc.hide)
			tc.start(s)
			if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating AGENTS.md was blocked: %+v", got)
			}
			writeActiveAgentTestFile(t, s.base, "AGENTS.md")
			for range 2 {
				if got := s.patch(s.base, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
					t.Fatalf("editing the session's own AGENTS.md was blocked: %+v", got)
				}
			}
		})
		t.Run(tc.name+" keeps an existing file protected", func(t *testing.T) {
			s := newManagedHiddenHomeSession(t, tc.hide)
			writeActiveAgentTestFile(t, s.base, "AGENTS.md")
			tc.start(s)
			for range 2 {
				if got := s.patch(s.base, sightingUpdatePatch); got.Action != guardrailActionBlock ||
					!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
					t.Fatalf("an AGENTS.md that existed before the first call became writable: %+v", got)
				}
			}
		})
	}
}

// Benign corpus (review loop round 2), with a protected-target control. An
// OpenClaw session on a service-account gateway has no start hook and its
// inspect calls carry no client evidence: its first inspect call takes the
// snapshot from this host's files, which its call-time proof reads too. A
// TOOLS.md it creates after that stays editable, also after a restart; an
// AGENTS.md that was there stays protected.
func TestInstructionBenignOpenClawServiceAccountFirstSighting(t *testing.T) {
	installToolCallCorpusProfileConnector(t, "openclaw", "default")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	workspace := filepath.Join(home, ".openclaw", "workspace")
	if err := os.MkdirAll(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	existing := writeActiveAgentTestFile(t, workspace, "AGENTS.md")
	created := filepath.Join(workspace, "TOOLS.md")
	appendTo := func(file string) string {
		if runtime.GOOS == "windows" {
			return "Add-Content -LiteralPath '" + file + "' -Value new"
		}
		return "printf new >> '" + file + "'"
	}
	dataDir := t.TempDir()
	newGateway := func() *APIServer {
		api := testAPIServerWithConfig(t, "action")
		api.scannerCfg.Guardrail.Connector = "openclaw"
		api.scannerCfg.Guardrail.BlockAt = "HIGH"
		api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	inspect := func(command string) ToolInspectVerdict {
		t.Helper()
		body := mustJSON(t, map[string]interface{}{
			"tool": "exec", "direction": "tool_call", "session_id": "live",
			"args": map[string]interface{}{"command": command, "workdir": workspace},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewBufferString(string(body)))
		req = req.WithContext(withServiceAccountGateway(withAuthenticatedInspectConnector(req.Context(), "openclaw")))
		_, verdict := postInspectHTTP(t, newGateway(), req)
		return verdict
	}
	if got := inspect(appendTo(filepath.Join(workspace, "notes.txt"))); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("first call: %+v", got)
	}
	if got := inspect(appendTo(created)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
		t.Fatalf("creating TOOLS.md was blocked: %+v", got)
	}
	if err := os.WriteFile(created, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if got := inspect(appendTo(created)); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("editing the TOOLS.md this session created was blocked: %+v", got)
		}
	}
	if got := inspect(appendTo(existing)); got.Action != guardrailActionBlock ||
		!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
		t.Fatalf("the AGENTS.md that was there became writable: %+v", got)
	}
}
