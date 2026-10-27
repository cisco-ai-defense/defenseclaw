// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// Benign corpus (T12b review loop round 2, cache churn), with a
// protected-target control. A session's first sighting outlives its
// eviction from the in-memory cache: churn through more sessions than the
// cache holds, in one gateway process or across a restart, never turns the
// AGENTS.md the session created into one that was there before it. A file
// that existed before the session stays protected after the churn.
func TestInstructionBenignFirstSightingSurvivesCacheChurn(t *testing.T) {
	for _, hide := range []bool{false, true} {
		for _, restart := range []bool{false, true} {
			for _, existed := range []bool{false, true} {
				name := fmt.Sprintf("closed home %v, restart %v, existed %v", hide, restart, existed)
				t.Run(name, func(t *testing.T) {
					s := newManagedHiddenHomeSession(t, hide)
					fresh := s.gateway
					api := fresh()
					s.gateway = func() *APIServer { return api }
					if existed {
						writeActiveAgentTestFile(t, s.base, "AGENTS.md")
					}
					s.start(true)
					if !existed {
						if got := s.patch(s.base, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
							t.Fatalf("creating AGENTS.md was blocked: %+v", got)
						}
						writeActiveAgentTestFile(t, s.base, "AGENTS.md")
					}
					churnInstructionSessions(t, s, maxActiveAgentContextSessions+8)
					key, _ := instructionStartupKey(withManagedHookPeer(t.Context(), managedHookPeer{}), "codex", "live")
					if _, cached := api.activeAgentContext.sessionKey(key); cached {
						t.Fatal("the churn did not evict the session from the cache")
					}
					if restart {
						s.gateway = fresh
					}
					got := s.patch(s.base, sightingUpdatePatch)
					if existed {
						if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
							t.Fatalf("an AGENTS.md that existed before the session became writable after churn: %+v", got)
						}
					} else if cogBlocked(got.Action, got.WouldBlock, got.Findings) {
						t.Fatalf("churn made the session's own AGENTS.md pre-existing: %+v", got)
					}
				})
			}
		}
	}
}

// churnInstructionSessions starts count other sessions with startup
// evidence in s's working directory.
func churnInstructionSessions(t *testing.T, s *managedHiddenHomeSession, count int) {
	t.Helper()
	body := mustJSON(t, map[string]interface{}{"hook_event_name": "SessionStart", "session_id": "churn", "cwd": s.base})
	facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", "SessionStart", body))
	if !ok {
		t.Fatal("managed hook did not send startup identity evidence")
	}
	ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, facts)
	for index := range count {
		s.judge(ctx, codexHookRequest{HookEventName: "SessionStart", SessionID: fmt.Sprintf("churn-%04d", index), CWD: s.base})
	}
}

// Benign corpus (T12b review loop round 2, shared managed gateway), with a
// protected-target control. Two enrolled users whose agents use the same
// session ID keep separate snapshots: user B's start or end of "live" never
// resets user A's, so the AGENTS.md A's session created stays editable for
// A, in one gateway process and across a restart, for a hook-socket caller
// (uid) and a verified user identity (a managed Windows caller). A's file
// that existed before A's session stays protected.
func TestInstructionBenignSessionStateIsScopedToTheVerifiedCaller(t *testing.T) {
	type caller struct {
		name string
		with func(ctx context.Context, home string) context.Context
	}
	callers := []struct {
		name string
		a, b caller
	}{
		{"hook socket uids", caller{"uid 1001", func(ctx context.Context, home string) context.Context {
			return withManagedHookPeer(ctx, managedHookPeer{UID: 1001, Home: home})
		}}, caller{"uid 1002", func(ctx context.Context, home string) context.Context {
			return withManagedHookPeer(ctx, managedHookPeer{UID: 1002, Home: home})
		}}},
		{"verified user identities", caller{"user A", func(ctx context.Context, _ string) context.Context {
			return context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, "S-1-5-21-1-2-3-1001")
		}}, caller{"user B", func(ctx context.Context, _ string) context.Context {
			return context.WithValue(ctx, verifiedUserScopedIdentityContextKey{}, "S-1-5-21-1-2-3-1002")
		}}},
	}
	for _, pair := range callers {
		for _, event := range []string{"SessionStart", "SessionEnd"} {
			for _, restart := range []bool{false, true} {
				for _, existed := range []bool{false, true} {
					name := fmt.Sprintf("%s, B sends %s, restart %v, existed %v", pair.name, event, restart, existed)
					t.Run(name, func(t *testing.T) {
						dataDir := t.TempDir()
						root := t.TempDir()
						homeA, homeB := filepath.Join(root, "a"), filepath.Join(root, "b")
						baseA, baseB := filepath.Join(homeA, "project"), filepath.Join(homeB, "project")
						for _, dir := range []string{baseA, baseB} {
							if err := os.MkdirAll(dir, 0o700); err != nil {
								t.Fatal(err)
							}
						}
						newAPI := func() *APIServer {
							api := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
							api.scannerCfg.DataDir = dataDir
							return api
						}
						shared := newAPI()
						gateway := func() *APIServer {
							if restart {
								return newAPI()
							}
							return shared
						}
						judge := func(who caller, home string, ctx context.Context, req codexHookRequest) codexHookResponse {
							t.Helper()
							ctx = who.with(withAuthenticatedHookConnector(ctx, "codex"), home)
							return gateway().evaluateCodexHook(ctx, req)
						}
						start := func(who caller, home, cwd, event string) {
							t.Helper()
							body := mustJSON(t, map[string]interface{}{"hook_event_name": event, "session_id": "live", "cwd": cwd})
							ctx := t.Context()
							if facts, ok := hookpaths.Decode(hookpaths.ResolveConnector("codex", "", event, body)); ok {
								ctx = context.WithValue(ctx, resolvedWritesContextKey{}, facts)
							}
							judge(who, home, ctx, codexHookRequest{HookEventName: event, SessionID: "live", CWD: cwd})
						}
						patch := func(who caller, home, cwd, text string) codexHookResponse {
							t.Helper()
							input := map[string]interface{}{"command": text}
							return judge(who, home, instructionResolvedWriteContext(t, cwd, "apply_patch", input), codexHookRequest{
								HookEventName: "PreToolUse", SessionID: "live", CWD: cwd, ToolName: "apply_patch", ToolInput: input,
							})
						}
						if existed {
							writeActiveAgentTestFile(t, baseA, "AGENTS.md")
						}
						start(pair.a, homeA, baseA, "SessionStart")
						if !existed {
							if got := patch(pair.a, homeA, baseA, sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
								t.Fatalf("creating AGENTS.md was blocked: %+v", got)
							}
							writeActiveAgentTestFile(t, baseA, "AGENTS.md")
						}
						// B's session of the same ID, in B's project and in A's.
						start(pair.b, homeB, baseB, event)
						start(pair.b, homeB, baseA, event)
						got := patch(pair.a, homeA, baseA, sightingUpdatePatch)
						if existed {
							if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-AGENTS-MD") {
								t.Fatalf("another user's %s made A's existing AGENTS.md writable: %+v", event, got)
							}
						} else if cogBlocked(got.Action, got.WouldBlock, got.Findings) {
							t.Fatalf("another user's %s made A's own AGENTS.md pre-existing: %+v", event, got)
						}
					})
				}
			}
		}
	}
}

// The key of every instruction-state route carries the verified caller;
// a per-user gateway's key (no verified caller) and its record name are
// the ones earlier builds used, so an upgrade keeps a running session's
// record.
func TestInstructionStartupKeyCarriesTheVerifiedCaller(t *testing.T) {
	base := t.Context()
	a, _ := instructionStartupKey(withManagedHookPeer(base, managedHookPeer{UID: 1001}), "codex", "live")
	b, _ := instructionStartupKey(withManagedHookPeer(base, managedHookPeer{UID: 1002}), "codex", "live")
	w, _ := instructionStartupKey(context.WithValue(base, verifiedUserScopedIdentityContextKey{}, "S-1-5-21-1"), "codex", "live")
	plain, _ := instructionStartupKey(base, "codex", "live")
	if a == b || a == w || a == plain || w == plain {
		t.Fatalf("keys of different callers collide: %+v %+v %+v %+v", a, b, w, plain)
	}
	if plain != (activeAgentContextKey{connector: "codex", sessionID: "live"}) {
		t.Fatalf("per-user key = %+v", plain)
	}
	dir := t.TempDir()
	legacy := sha256.Sum256([]byte("\x00codex\x00live"))
	if got, want := instructionLoadRecordPath(dir, plain), filepath.Join(dir, hex.EncodeToString(legacy[:])+".json"); got != want {
		t.Fatalf("per-user record name = %s, want the earlier builds' %s", got, want)
	}
	if instructionLoadRecordPath(dir, a) == instructionLoadRecordPath(dir, b) ||
		instructionLoadRecordPath(dir, a) == instructionLoadRecordPath(dir, plain) {
		t.Fatal("record names of different callers collide")
	}
	// The Claude Code route keys by the same function: B's SessionEnd
	// leaves A's load in place.
	api := &APIServer{}
	file := writeActiveAgentTestFile(t, t.TempDir(), "CLAUDE.md")
	ctxA := withAuthenticatedHookConnector(withManagedHookPeer(base, managedHookPeer{UID: 1001}), "claudecode")
	ctxB := withAuthenticatedHookConnector(withManagedHookPeer(base, managedHookPeer{UID: 1002}), "claudecode")
	api.applyClaudeCodeActiveAgentContext(ctxA, claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: "live", FilePath: file})
	api.applyClaudeCodeActiveAgentContext(ctxB, claudeCodeHookRequest{HookEventName: "SessionEnd", SessionID: "live"})
	api.applyClaudeCodeActiveAgentContext(ctxB, claudeCodeHookRequest{HookEventName: "SessionStart", SessionID: "live", CWD: filepath.Dir(file)})
	snapshot := api.applyClaudeCodeActiveAgentContext(ctxA, claudeCodeHookRequest{HookEventName: "PreToolUse", SessionID: "live", CWD: filepath.Dir(file)})
	if len(snapshot.files) != 1 || snapshot.files[0] != file {
		t.Fatalf("another user's end or start dropped A's load: %+v", snapshot)
	}
}
