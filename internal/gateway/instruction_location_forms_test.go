// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1134, every write form: an instruction-named file that no agent loads
// from where it is, and that the session did not load, is ordinary. Action
// mode never blocks a write to it, observe mode never reports one, from the
// gateway's own view and from the hook client's evidence, also when the
// session loaded the file of that name in the project, and on the Codex
// hook. The same forms on the project's file stay COG-blocked when Claude
// Code reads it at every start (CLAUDE.md) or the session loaded it, so what
// decides is which file it is, not how it is written.
func TestInstructionProtectionUnloadedNameEveryWriteForm(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell forms; TestInstructionProtectionOnlyInLoadLocations has the Windows ones")
	}
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	source := writeActiveAgentTestFile(t, project, "notes.txt")
	every := []string{"printf x >> %s", "rm -f %s"}
	forms := append(every,
		"printf x > %s", "printf x >| %s", ": > %s", "printf x | tee %s", "printf x | tee -a %s",
		"cp "+source+" %s", "mv "+source+" %s", "install -m 0644 "+source+" %s",
		"sed -i s/a/b/ %s", "truncate -s 0 %s", "printf x | dd of=%s",
		"cd "+project+" && printf x >> %s",
	)
	for rule, name := range instructionRuleFiles {
		fixture := writeActiveAgentTestFile(t, filepath.Join(root, "fixtures"), name)
		instruction := writeActiveAgentTestFile(t, project, name)
		relative, err := filepath.Rel(project, fixture)
		if err != nil {
			t.Fatal(err)
		}
		action := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
		observe := instructionProtectionTestAPI(t, "claudecode", "observe", "HIGH")
		action.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
			HookEventName: "InstructionsLoaded", SessionID: "loaded", FilePath: instruction,
		})
		nameForms := every
		if name == "SOUL.md" || name == "CLAUDE.md" {
			nameForms = forms
		}
		for _, form := range nameForms {
			for _, target := range []struct{ label, path, rule string }{
				{"fixture", fixture, ""},
				{"relative fixture", relative, ""},
				{"project file", instruction, rule},
				{"unloaded project file", instruction, ""},
			} {
				input := map[string]interface{}{"command": strings.ReplaceAll(form, "%s", "'"+target.path+"'")}
				for source, ctx := range instructionFormContexts(t, project, input) {
					for _, run := range []struct {
						api     *APIServer
						session string
					}{{action, "unloaded"}, {action, "loaded"}, {observe, "unloaded"}} {
						// Claude Code reads only CLAUDE.md at every start; the
						// project's other instruction names are its files only
						// once the session loads them, openclaw.json included
						// (GAP-1126).
						loaded := run.session == "loaded"
						switch {
						case target.label == "project file" && !loaded && name != "CLAUDE.md",
							target.label == "unloaded project file" && (loaded || name == "CLAUDE.md"):
							continue
						}
						response := run.api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
							HookEventName: "PreToolUse", SessionID: run.session, CWD: project,
							ToolName: "Bash", ToolInput: input,
						})
						label := name + " " + target.label + " `" + form + "` " + response.Mode + " " + run.session + " (" + source + ")"
						if target.rule == "" {
							if cogBlocked(response.Action, response.WouldBlock, response.Findings) {
								t.Errorf("%s: an ordinary file was blocked: action=%q would_block=%v findings=%v",
									label, response.Action, response.WouldBlock, response.Findings)
							}
							continue
						}
						if response.Action != guardrailActionBlock && !response.WouldBlock || !findingStringHasRuleID(response.Findings, target.rule) {
							t.Errorf("%s: action=%q findings=%v, want a %s block", label, response.Action, response.Findings, target.rule)
						}
					}
				}
			}
		}
	}
	codex := instructionProtectionTestAPI(t, "codex", "action", "HIGH")
	for _, target := range []struct{ path, rule string }{
		{filepath.Join(root, "fixtures", "AGENTS.md"), ""},
		{filepath.Join(project, "AGENTS.md"), "COG-AGENTS-MD"},
	} {
		response := codex.evaluateCodexHook(withAuthenticatedHookConnector(t.Context(), "codex"), codexHookRequest{
			HookEventName: "PreToolUse", SessionID: "forms-codex", ToolName: "Bash", CWD: project,
			ToolInput: map[string]interface{}{"command": "printf x >> '" + target.path + "'"},
		})
		if target.rule == "" && cogBlocked(response.Action, response.WouldBlock, response.Findings) ||
			target.rule != "" && (response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, target.rule)) {
			t.Errorf("Codex append to %s: action=%q findings=%v, want blocked=%v", target.path, response.Action, response.Findings, target.rule != "")
		}
	}
}

// instructionFormContexts are the gateway's own view and, when the hook
// client resolves a write target for the command, its evidence.
func instructionFormContexts(t *testing.T, cwd string, input map[string]interface{}) map[string]context.Context {
	t.Helper()
	contexts := map[string]context.Context{"gateway file system": withAuthenticatedHookConnector(t.Context(), "claudecode")}
	body := mustJSON(t, map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "forms", "cwd": cwd,
		"tool_name": "Bash", "tool_input": input,
	})
	if targets, ok := hookpaths.Decode(hookpaths.Resolve(body)); ok && len(targets) != 0 {
		contexts["hook client evidence"] = withAuthenticatedHookConnector(
			context.WithValue(t.Context(), resolvedWritesContextKey{}, targets), "claudecode")
	}
	return contexts
}

// cogBlocked reports a block, or an observed one, that an instruction-file
// rule takes part in.
func cogBlocked(action string, wouldBlock bool, findings []string) bool {
	if action != guardrailActionBlock && !wouldBlock {
		return false
	}
	for rule := range instructionRuleFiles {
		if findingStringHasRuleID(findings, rule) {
			return true
		}
	}
	return false
}
