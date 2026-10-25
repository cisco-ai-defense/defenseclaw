// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Benign corpus (review loop round 2, GAP-0973 class), with protected-target
// controls. A call of a session can reach the gateway before its start event
// (Codex sends PreToolUse before SessionStart, the 1 s arrival wait runs
// out). The late first start is the start of the same session: the calls'
// first sighting stands, so the AGENTS.md the session created after its
// first call stays editable. A later start of the same session ID is a new
// generation and takes a new snapshot; a file that was there before the
// first call stays protected throughout.
func TestInstructionBenignLateSessionStartKeepsFirstSighting(t *testing.T) {
	cases := []struct {
		name      string
		hide      bool
		evidence  bool
		oneServer bool
	}{
		{"managed, late start with evidence, restarts between calls", false, true, false},
		{"managed, late start with evidence, one gateway process", false, true, true},
		{"managed, late 1.0.3 start without evidence, one gateway process", false, false, true},
		{"managed, late start with evidence, closed home", true, true, false},
		{"managed, late 1.0.3 start without evidence, closed home", true, false, false},
	}
	session := func(t *testing.T, hide, oneServer bool) *managedHiddenHomeSession {
		s := newManagedHiddenHomeSession(t, hide)
		if oneServer {
			api := s.gateway()
			s.gateway = func() *APIServer { return api }
		}
		return s
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := session(t, tc.hide, tc.oneServer)
			if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating AGENTS.md before the start was blocked: %+v", got)
			}
			writeActiveAgentTestFile(t, s.base, "AGENTS.md")
			s.start(tc.evidence)
			for range 2 {
				if got := s.patch(s.base, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
					t.Fatalf("a late start made the session's own AGENTS.md protected: %+v", got)
				}
			}
		})
		t.Run(tc.name+" keeps an existing file protected", func(t *testing.T) {
			s := session(t, tc.hide, tc.oneServer)
			writeActiveAgentTestFile(t, s.base, "AGENTS.md")
			for _, step := range []func(){func() {}, func() { s.start(tc.evidence) }} {
				step()
				if got := s.patch(s.base, sightingUpdatePatch); got.Action != guardrailActionBlock ||
					!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
					t.Fatalf("an AGENTS.md that existed before the first call became writable: %+v", got)
				}
			}
		})
	}
	// Protected control: a second start of the session ID (resume, clear)
	// is a new generation, also after a late first start, also after a
	// gateway restart.
	for _, oneServer := range []bool{false, true} {
		for _, callFirst := range []bool{false, true} {
			name := "a second start is a new generation"
			if callFirst {
				name += " after a late first start"
			}
			if oneServer {
				name += ", one gateway process"
			}
			t.Run(name, func(t *testing.T) {
				s := session(t, false, oneServer)
				if !callFirst {
					s.start(true)
				}
				if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
					t.Fatalf("creating AGENTS.md was blocked: %+v", got)
				}
				writeActiveAgentTestFile(t, s.base, "AGENTS.md")
				if callFirst {
					s.start(true)
					if got := s.patch(s.base, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
						t.Fatalf("the late first start protected the session's own AGENTS.md: %+v", got)
					}
				}
				s.start(true)
				if got := s.patch(s.base, sightingUpdatePatch); got.Action != guardrailActionBlock ||
					!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
					t.Fatalf("a new generation did not take a new snapshot: %+v", got)
				}
			})
		}
	}
}

// The same rule on the Claude Code route: a PreToolUse before SessionStart,
// one gateway process and a restarted one.
func TestInstructionBenignClaudeCodeLateSessionStart(t *testing.T) {
	for _, restart := range []bool{false, true} {
		for _, existed := range []bool{false, true} {
			name := map[bool]string{false: "created after the first call", true: "existing before the first call"}[existed]
			if restart {
				name += ", restarts between events"
			}
			t.Run(name, func(t *testing.T) {
				project := filepath.Join(instructionIdentityTestRoot(t), "project")
				if err := os.MkdirAll(project, 0o700); err != nil {
					t.Fatal(err)
				}
				dataDir := t.TempDir()
				api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
				api.scannerCfg.DataDir = dataDir
				gateway := func() *APIServer {
					if !restart {
						return api
					}
					next := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
					next.scannerCfg.DataDir = dataDir
					return next
				}
				target := filepath.Join(project, "CLAUDE.md")
				write := func() claudeCodeHookResponse {
					return gateway().evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "late", CWD: project, ToolName: "Write",
						ToolInput: map[string]interface{}{"file_path": target, "content": "new"},
					})
				}
				if existed {
					writeActiveAgentTestFile(t, project, "CLAUDE.md")
				}
				first := write()
				if !existed {
					if cogBlocked(first.Action, first.WouldBlock, first.Findings) {
						t.Fatalf("creating CLAUDE.md before the start was blocked: %+v", first)
					}
					writeActiveAgentTestFile(t, project, "CLAUDE.md")
				}
				gateway().evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
					HookEventName: "SessionStart", SessionID: "late", CWD: project,
				})
				for range 2 {
					got := write()
					if blocked := cogBlocked(got.Action, got.WouldBlock, got.Findings); blocked != existed {
						t.Fatalf("existed before the first call=%v, blocked=%v: %+v", existed, blocked, got)
					}
				}
			})
		}
	}
}

// Benign corpus (review loop round 2, GAP-1126 class), with protected-target
// controls. A loaded instruction file that is a symlink (or sits under a
// linked directory) is recorded with the identity of the file it reaches,
// from this host's file system or the hook client's sighting as the user.
// That is proof, not a loss of context: it does not make every
// instruction-named write of the session suspect, so a CLAUDE.md the
// session creates elsewhere stays writable, while the loaded file stays
// protected under its link name and its real name.
func TestInstructionBenignSymlinkedLoadKeepsSessionCertain(t *testing.T) {
	for _, name := range []string{"openclaw.json", "CLAUDE.md", "MEMORY.md"} {
		for _, linkedParent := range []bool{false, true} {
			label := name + " symlink"
			if linkedParent {
				label = name + " under a linked directory"
			}
			t.Run(label, func(t *testing.T) {
				root := instructionIdentityTestRoot(t)
				project := filepath.Join(root, "project")
				if err := os.MkdirAll(project, 0o700); err != nil {
					t.Fatal(err)
				}
				real := writeActiveAgentTestFile(t, filepath.Join(root, "real"), name)
				loaded := filepath.Join(root, "linked", name)
				if linkedParent {
					loaded = filepath.Join(root, "linked-dir", name)
					if err := os.Symlink(filepath.Dir(real), filepath.Dir(loaded)); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				} else {
					if err := os.MkdirAll(filepath.Dir(loaded), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(real, loaded); err != nil {
						t.Skipf("symlinks unavailable: %v", err)
					}
				}
				api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
				api.scannerCfg.DataDir = t.TempDir()
				ctx := authenticatedClaudeCodeTestContext()
				event := func(req claudeCodeHookRequest) claudeCodeHookResponse {
					req.SessionID, req.CWD = "linked", project
					return api.evaluateClaudeCodeHook(ctx, req)
				}
				event(claudeCodeHookRequest{HookEventName: "SessionStart"})
				event(claudeCodeHookRequest{HookEventName: "InstructionsLoaded", FilePath: loaded})
				key, _ := validActiveAgentContextKey("claudecode", "linked")
				if got := api.activeAgentContext.snapshotKey(key); got.uncertain || got.identities[loaded] == "" {
					t.Fatalf("a proved symlinked load = %#v", got)
				}
				write := func(target string) claudeCodeHookResponse {
					return event(claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Write",
						ToolInput: map[string]interface{}{"file_path": target, "content": "new"}})
				}
				for range 2 {
					if got := write(filepath.Join(project, "CLAUDE.md")); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
						t.Fatalf("a symlinked %s load blocked an unrelated CLAUDE.md: %+v", name, got)
					}
				}
				writeActiveAgentTestFile(t, project, "CLAUDE.md")
				if got := write(filepath.Join(project, "CLAUDE.md")); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
					t.Fatalf("a symlinked %s load blocked the session's own CLAUDE.md: %+v", name, got)
				}
				for _, target := range []string{loaded, real} {
					if got := write(target); got.Action != guardrailActionBlock {
						t.Fatalf("the loaded %s was writable as %s: %+v", name, target, got)
					}
				}
			})
		}
	}
}

// The client identity of a loaded symlink the gateway cannot read proves it
// as well; only a load nothing can identify marks the session uncertain.
func TestActiveAgentContextSymlinkedLoadUncertainOnlyWithoutIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX dangling link")
	}
	root := t.TempDir()
	link := filepath.Join(root, "linked", "CLAUDE.md")
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "unreadable", "CLAUDE.md"), link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	key, _ := validActiveAgentContextKey("claudecode", "s")
	cache := activeAgentContextCache{}
	cache.seedKey(key, link, "")
	if got := cache.snapshotKey(key); !got.uncertain {
		t.Fatalf("an unprovable load did not mark the session uncertain: %#v", got)
	}
	cache = activeAgentContextCache{}
	cache.seedKey(key, link, "1:2")
	if got := cache.snapshotKey(key); got.uncertain || got.identities[link] != "1:2" {
		t.Fatalf("a load the hook client identified = %#v", got)
	}
}
