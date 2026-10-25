// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const createdDirAddPatch = "*** Begin Patch\n*** Add File: new/AGENTS.md\n+x\n*** End Patch"

// Benign corpus (GAP-1415), with a protected-target control. A directory
// that was missing when the session first reached it starts empty: an
// AGENTS.md the session creates there, with the directory, is the session's
// own file under every later spelling of the directory (a symlink, a
// rename, a case variant), also after a gateway restart. A link the session
// makes at a missing spelling does not empty the directory it points to.
func TestInstructionBenignCreatedDirectoryKeepsItsRecord(t *testing.T) {
	type session struct {
		base    string
		ctx     context.Context
		gateway func() *APIServer
	}
	call := func(t *testing.T, s session, cwd, patch string) codexHookResponse {
		t.Helper()
		input := map[string]interface{}{"command": patch}
		callCtx := instructionResolvedWriteContext(t, cwd, "apply_patch", input)
		if peer, managed := managedHookPeerFromContext(s.ctx); managed {
			callCtx = withManagedHookPeer(callCtx, peer)
		}
		return s.gateway().evaluateCodexHook(withAuthenticatedHookConnector(callCtx, "codex"), codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "live", CWD: cwd, ToolName: "apply_patch", ToolInput: input,
		})
	}
	start := func(t *testing.T, managed bool) session {
		t.Helper()
		base, dataDir := t.TempDir(), t.TempDir()
		s := session{base: base, ctx: withAuthenticatedHookConnector(t.Context(), "codex")}
		s.gateway = func() *APIServer {
			api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
			api.scannerCfg.DataDir = dataDir
			return api
		}
		if managed {
			body := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "live", "cwd": base})
			facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", body))
			if !ok {
				t.Fatal("managed hook did not send startup identity evidence")
			}
			s.ctx = withManagedHookPeer(context.WithValue(s.ctx, resolvedWritesContextKey{}, facts),
				managedHookPeer{Home: t.TempDir()})
		}
		s.gateway().evaluateCodexHook(s.ctx, codexHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: base})
		return s
	}
	// create is the session's install -D new/AGENTS.md: judged while new/
	// is missing, then run.
	create := func(t *testing.T, s session) string {
		t.Helper()
		if got := call(t, s, s.base, createdDirAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("creating new/AGENTS.md was blocked: %+v", got)
		}
		created := filepath.Join(s.base, "new")
		if err := os.Mkdir(created, 0o700); err != nil {
			t.Fatal(err)
		}
		writeActiveAgentTestFile(t, created, "AGENTS.md")
		return created
	}
	for _, managed := range []bool{false, true} {
		name := "per-user"
		if managed {
			name = "managed"
		}
		t.Run(name+" symlink", func(t *testing.T) {
			s := start(t, managed)
			created := create(t, s)
			link := filepath.Join(s.base, "link")
			if err := os.Symlink(created, link); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if got := call(t, s, link, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("a symlink made the session's own AGENTS.md pre-existing: %+v", got)
			}
			// The created directory keeps its own record too.
			if got := call(t, s, created, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("the created directory lost its empty record: %+v", got)
			}
		})
		t.Run(name+" rename", func(t *testing.T) {
			s := start(t, managed)
			created := create(t, s)
			// A later call sees the created directory before it is renamed.
			if got := call(t, s, s.base, "*** Begin Patch\n*** Add File: notes.txt\n+x\n*** End Patch"); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("an ordinary write was blocked: %+v", got)
			}
			renamed := filepath.Join(s.base, "renamed")
			if err := os.Rename(created, renamed); err != nil {
				t.Fatal(err)
			}
			if got := call(t, s, renamed, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("a rename made the session's own AGENTS.md pre-existing: %+v", got)
			}
		})
		t.Run(name+" a link at a missing spelling keeps its target protected", func(t *testing.T) {
			s := start(t, managed)
			other := t.TempDir()
			writeActiveAgentTestFile(t, other, "AGENTS.md")
			// new/ is reached while missing, then made a link to a
			// directory whose AGENTS.md was there before.
			if got := call(t, s, s.base, createdDirAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating new/AGENTS.md was blocked: %+v", got)
			}
			if err := os.Symlink(other, filepath.Join(s.base, "new")); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}
			if got := call(t, s, other, sightingUpdatePatch); got.Action != guardrailActionBlock ||
				!findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
				t.Fatalf("a link at a missing spelling made an existing AGENTS.md writable: %+v", got)
			}
		})
	}
	t.Run("case variant", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows directory keys are case folded already")
		}
		s := start(t, false)
		create(t, s)
		upper := filepath.Join(s.base, "NEW")
		if _, err := os.Stat(upper); err != nil {
			t.Skip("case-sensitive volume")
		}
		if got := call(t, s, upper, sightingUpdatePatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
			t.Fatalf("a case variant made the session's own AGENTS.md pre-existing: %+v", got)
		}
	})
}

// A recorded directory that was missing gets the identity it has once it
// exists, unless another recorded directory has that identity already.
func TestInstructionSnapshotBindsCreatedDirectory(t *testing.T) {
	var cache activeAgentContextCache
	key := activeAgentContextKey{connector: "codex", sessionID: "live"}
	cache.beginKey(key)
	cache.setStartupKey(key, map[string]string{"/x/AGENTS.md": "1:9"}, []string{"/x", "/new", "/moved"}, map[string]string{"/x": "1:2"})
	if _, unbound, _ := cache.startupDirsKey(key, 1); len(unbound) != 1 || unbound[0] != "/moved" {
		t.Fatalf("unbound directories: %v", unbound)
	}
	if !cache.extendStartupKey(key, map[string]string{"/link/AGENTS.md": "1:5"}, []string{"/link"},
		map[string]string{"/link": "1:3"}, map[string]string{"/new": "1:3", "/moved": "1:2"}) {
		t.Fatal("the created directory was not bound")
	}
	got := cache.snapshotKey(key)
	if !got.startupCovers("/link") || got.startupFiles["/link/AGENTS.md"] != "" {
		t.Fatalf("another spelling of the created directory did not keep its empty record: %+v", got)
	}
	session, _ := cache.sessionKey(key)
	if session.startupDirIDs["/moved"] != "" || session.startupDirIDs["/new"] != "1:3" {
		t.Fatalf("bound identities: %v", session.startupDirIDs)
	}
}
