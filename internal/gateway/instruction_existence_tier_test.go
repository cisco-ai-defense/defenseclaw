// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// instructionExistenceTiers: an instruction file proved only by existing
// now (a session without a snapshot, or a directory its snapshot does not
// record) blocks in the strict tier and is a warning with its finding in
// default and permissive (BALANCED-DEFAULTS).
var instructionExistenceTiers = []struct {
	pack   string
	blocks bool
}{{"default", false}, {"permissive", false}, {"strict", true}}

func instructionProtectionTierTestAPI(t *testing.T, connectorName, pack string) *APIServer {
	t.Helper()
	api := instructionProtectionTestAPI(t, connectorName, "action", "HIGH")
	installToolCallCorpusProfileConnector(t, connectorName, pack)
	api.scannerCfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), pack)
	return api
}

// checkExistenceTier checks a write proved only by existence: the finding is
// always there (a visible warning and an audit row), and it blocks only when
// the tier enforces existence.
func checkExistenceTier(t *testing.T, blocks bool, label, action string, findings []string, rule string) {
	t.Helper()
	if !findingStringHasRuleID(findings, rule) {
		t.Fatalf("%s: no %s warning: action=%q findings=%v", label, rule, action, findings)
	}
	if blocks != (action == guardrailActionBlock) {
		t.Fatalf("%s: action=%q findings=%v, want blocked=%t", label, action, findings, blocks)
	}
}

// Benign corpus (GAP-1416/GAP-1428 class): a 1.0.3 managed POSIX hook
// binary sends no startup evidence and no sighting, and the managed POSIX
// gateway does not take its own (it may not read the user's home). Only
// existence is known, so the second edit of an
// AGENTS.md the session created is a warning in default and permissive, not
// a block; the strict tier keeps the call-time proof.
func TestInstructionBenignOldHookWithoutSightingWarns(t *testing.T) {
	for _, tier := range instructionExistenceTiers {
		t.Run(tier.pack, func(t *testing.T) {
			s := newManagedHiddenHomeSession(t, false)
			dataDir := t.TempDir()
			s.gateway = func() *APIServer {
				api := instructionProtectionTierTestAPI(t, "codex", tier.pack)
				api.scannerCfg.DataDir = dataDir
				return api
			}
			oldHook := func(patch string) codexHookResponse {
				t.Helper()
				input := map[string]interface{}{"command": patch}
				facts, _ := instructionResolvedWriteContext(t, s.base, "apply_patch", input).Value(resolvedWritesContextKey{}).(map[string]string)
				delete(facts, hookpaths.ReachedInstructionsKey)
				return s.judge(context.WithValue(t.Context(), resolvedWritesContextKey{}, facts), codexHookRequest{
					HookEventName: "PreToolUse", SessionID: "live", CWD: s.base, ToolName: "apply_patch", ToolInput: input,
				})
			}
			s.start(false)
			if got := oldHook(sightingAddPatch); cogBlocked(got.Action, got.WouldBlock, got.Findings) {
				t.Fatalf("creating AGENTS.md was blocked: %+v", got)
			}
			writeActiveAgentTestFile(t, s.base, "AGENTS.md")
			for range 2 {
				got := oldHook(sightingUpdatePatch)
				checkExistenceTier(t, tier.blocks, "edit of the session's own AGENTS.md", got.Action, got.Findings, "COG-AGENTS-MD")
			}
		})
	}
}

// Protected-target corpus (GAP-1414, GAP-1127): CLAUDE.md and SOUL.md that
// the session loaded are hard links of one file. A write through a third
// name writes both, so the CRITICAL SOUL.md rule applies under a CRITICAL
// threshold, whichever name loaded last, from the gateway's own view and,
// behind ProtectHome, from the hook client's identities alone.
func TestInstructionProtectionHardLinkedLoadedNamesKeepEveryRule(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX hard links and a closed home")
	}
	for _, hide := range []bool{false, true} {
		for _, order := range [][]string{{"CLAUDE.md", "SOUL.md"}, {"SOUL.md", "CLAUDE.md"}} {
			name := "gateway file system " + strings.Join(order, " then ")
			if hide {
				name = "hook client identities " + strings.Join(order, " then ")
			}
			t.Run(name, func(t *testing.T) {
				if hide && os.Geteuid() == 0 {
					t.Skip("root reads a closed home")
				}
				home := filepath.Join(instructionIdentityTestRoot(t), "home")
				project := filepath.Join(home, "project")
				claude := writeActiveAgentTestFile(t, project, "CLAUDE.md")
				soul := filepath.Join(project, "SOUL.md")
				third := filepath.Join(project, "notes.txt")
				for _, link := range []string{soul, third} {
					if err := os.Link(claude, link); err != nil {
						t.Skipf("hard links unavailable: %v", err)
					}
				}
				api := instructionProtectionTestAPI(t, "claudecode", "action", "CRITICAL")
				api.scannerCfg.DataDir = t.TempDir()
				input := map[string]interface{}{"command": "printf changed >> '" + third + "'"}
				// The gateway's own view alone, or the hook client's alone.
				write := t.Context()
				if hide {
					write = instructionResolvedWriteContext(t, project, "Bash", input)
				}
				judge := func(ctx context.Context, req claudeCodeHookRequest) claudeCodeHookResponse {
					ctx = withAuthenticatedHookConnector(ctx, "claudecode")
					if hide {
						ctx = withManagedHookPeer(ctx, managedHookPeer{Home: home})
						if err := os.Chmod(home, 0); err != nil {
							t.Fatal(err)
						}
						defer func() { _ = os.Chmod(home, 0o700) }()
					}
					return api.evaluateClaudeCodeHook(ctx, req)
				}
				t.Cleanup(func() { _ = os.Chmod(home, 0o700) })
				for _, loaded := range order {
					file := filepath.Join(project, loaded)
					ctx := context.WithValue(t.Context(), resolvedWritesContextKey{},
						map[string]string{hookpaths.LoadedIdentityPrefix + file: hookpaths.FileIdentity(file)})
					judge(ctx, claudeCodeHookRequest{HookEventName: "InstructionsLoaded", SessionID: "linked", CWD: project, FilePath: file})
				}
				got := judge(write, claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "linked", CWD: project, ToolName: "Bash", ToolInput: input,
				})
				if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-SOUL") {
					t.Fatalf("a write through a third name of the loaded SOUL.md missed its CRITICAL rule: %+v", got)
				}
			})
		}
	}
}

// Protected-target corpus (GAP-1126): an openclaw.json the session loaded
// outside the standard load locations keeps its load, also across a
// gateway restart, so a write to it is a COG-OPENCLAW-JSON write.
func TestInstructionProtectionLoadedOpenClawJSONOutsideLoadLocations(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	imported := writeActiveAgentTestFile(t, filepath.Join(root, "imported"), "openclaw.json")
	dataDir := t.TempDir()
	newGateway := func() *APIServer {
		api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	newGateway().evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
		HookEventName: "InstructionsLoaded", SessionID: "claw", CWD: project, FilePath: imported,
	})
	input := map[string]interface{}{"file_path": imported, "content": "{}"}
	for range 2 { // the second call is a restarted gateway reading the saved load
		got := newGateway().evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "claw", CWD: project, ToolName: "Write", ToolInput: input,
		})
		if got.Action != guardrailActionBlock || !findingStringHasRuleID(got.Findings, "COG-OPENCLAW-JSON") {
			t.Fatalf("a loaded openclaw.json outside the load locations was writable: %+v", got)
		}
	}
}
