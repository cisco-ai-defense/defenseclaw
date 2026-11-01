// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Action mode protects the instruction files the session's agent really
// loads: the files the session reported loading (InstructionsLoaded, or the
// hook client's identity of one) and the files its own agent reads at every
// start. The name of a file another agent reads, in the same place, is an
// ordinary file of this session: Claude Code never reads SOUL.md or
// AGENTS.md, and Codex never reads CLAUDE.md. Writes and deletes of those are
// not blocked, whether the tool is allow-listed (STATIC-ALLOW) or not. These
// decision cases run on every OS; the Windows ones use PowerShell.
func TestInstructionProtectionOnlyTheAgentsLoadedFiles(t *testing.T) {
	const home = "/home/alice"
	type decision struct {
		connector, name, command, cwd, home, rule string
		loaded                                    []string
		loadedIdentity                            string
		dialect                                   actionfacts.Dialect
	}
	posix := func(connector, name, command, cwd, rule string, loaded ...string) decision {
		return decision{connector: connector, name: name, command: command, cwd: cwd, home: home,
			rule: rule, loaded: loaded, dialect: actionfacts.DialectPOSIX}
	}
	windows := func(connector, name, target, rule string) decision {
		return decision{connector: connector, name: name, command: `Set-Content -LiteralPath '` + target + `' -Value x`,
			cwd: `C:\Repo`, home: `C:\Users\alice`, rule: rule, dialect: actionfacts.DialectPowerShell}
	}
	var cases []decision
	for rule, name := range instructionRuleFiles {
		claudeRule, codexRule := "", ""
		switch name {
		case "CLAUDE.md":
			claudeRule = rule
		case "AGENTS.md":
			codexRule = rule
		}
		cases = append(cases,
			posix("claudecode", "Claude project append "+name, "printf x >> /repo/"+name, "/repo", claudeRule),
			posix("claudecode", "Claude project delete "+name, "rm -f /repo/"+name, "/repo", claudeRule),
			posix("claudecode", "Claude parent "+name, "printf x >> /repo/"+name, "/repo/src", claudeRule),
			posix("claudecode", "Claude .claude folder "+name, "printf x >> /repo/.claude/"+name, "/repo", claudeRule),
			posix("claudecode", "Claude loaded "+name, "printf x >> /repo/"+name, "/repo", rule, "/repo/"+name),
			posix("codex", "Codex project append "+name, "printf x >> /repo/"+name, "/repo", codexRule),
			posix("codex", "Codex parent "+name, "printf x >> /repo/"+name, "/repo/src", codexRule),
			posix("codex", "Codex .claude folder "+name, "printf x >> /repo/.claude/"+name, "/repo", ""),
			posix("openclaw", "OpenClaw workspace "+name, "printf x >> /home/alice/.openclaw/workspace/"+name, "/repo", rule),
			windows("claudecode", "Windows Claude project "+name, `C:\Repo\`+name, claudeRule),
			windows("codex", "Windows Codex project "+name, `C:\Repo\`+name, codexRule),
		)
	}
	cases = append(cases,
		posix("claudecode", "Claude global", "printf x >> /home/alice/.claude/CLAUDE.md", "/repo", "COG-CLAUDE-MD"),
		posix("claudecode", "Codex global from Claude", "printf x >> /home/alice/.codex/AGENTS.md", "/repo", ""),
		posix("claudecode", "OpenClaw persona from Claude", "printf x >> /home/alice/.openclaw/workspace/SOUL.md", "/repo", ""),
		posix("claudecode", "home outside the project", "printf x >> /home/alice/CLAUDE.md", "/repo", ""),
		posix("claudecode", "home above the project", "printf x >> /home/alice/CLAUDE.md", "/home/alice/proj", "COG-CLAUDE-MD"),
		posix("claudecode", "home SOUL.md above the project", "printf x >> /home/alice/SOUL.md", "/home/alice/proj", ""),
		posix("claudecode", "loaded file deleted", "rm -f /opt/persona/MEMORY.md", "/repo", "COG-MEMORY", "/opt/persona/MEMORY.md"),
		posix("codex", "Codex global", "printf x >> /home/alice/.codex/AGENTS.md", "/repo", "COG-AGENTS-MD"),
		posix("codex", "Claude global from Codex", "printf x >> /home/alice/.claude/CLAUDE.md", "/repo", ""),
		posix("opencode", "opencode global", "printf x >> /home/alice/.config/opencode/AGENTS.md", "/repo", "COG-AGENTS-MD"),
		posix("opencode", "opencode project SOUL.md", "printf x >> /repo/SOUL.md", "/repo", ""),
		posix("amp", "amp global", "printf x >> /home/alice/.config/amp/AGENTS.md", "/repo", "COG-AGENTS-MD"),
		posix("cursor", "Cursor project AGENTS.md", "printf x >> /repo/AGENTS.md", "/repo", "COG-AGENTS-MD"),
		posix("cursor", "Cursor project SOUL.md", "printf x >> /repo/SOUL.md", "/repo", ""),
		posix("openclaw", "OpenClaw config", "printf x >> /home/alice/.openclaw/openclaw.json", "/repo", "COG-OPENCLAW-JSON"),
		windows("claudecode", "Windows Claude case variant", `C:\REPO\claude.md`, "COG-CLAUDE-MD"),
		windows("claudecode", "Windows Codex global from Claude", `C:\Users\alice\.codex\AGENTS.md`, ""),
		windows("codex", "Windows Codex global", `C:\Users\alice\.codex\AGENTS.md`, "COG-AGENTS-MD"),
	)
	identified := posix("claudecode", "loaded, identified by the hook client", "printf x >> /repo/SOUL.md", "/repo", "COG-SOUL")
	identified.loadedIdentity = "/repo/SOUL.md"
	cases = append(cases, identified)

	for _, tc := range cases {
		for _, allowListed := range []bool{false, true} {
			name := tc.name
			if allowListed {
				name += " (allow-listed)"
			}
			t.Run(name, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, tc.connector, "default")
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = tc.connector
				cfg.Guardrail.BlockAt = "HIGH"
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
				if allowListed {
					allowTool(cfg, "Bash", "", "vetted")
				}
				args, err := json.Marshal(map[string]string{"command": tc.command})
				if err != nil {
					t.Fatal(err)
				}
				request := &ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: tc.connector}
				action := trustedActionRequest{
					Input: actionfacts.Input{Tool: "Bash", Args: args, CWD: tc.cwd, ActiveHome: tc.home,
						ActiveAgentFiles: tc.loaded, DialectHint: tc.dialect},
					LegacyText: string(args), Connector: tc.connector, EnforcementCapable: true,
				}
				action.ResolvedWriteTargets = syntheticExistingInstructionEvidence(t, action.Input, tc.rule)
				if tc.loadedIdentity != "" {
					action.ActiveAgentFileIdentities = map[string]string{tc.loadedIdentity: "1:2"}
				}
				verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(), request, action)
				if tc.rule == "" {
					if verdict.Action == guardrailActionBlock {
						t.Fatalf("%s: a file the agent does not load was blocked: %+v", tc.connector, verdict)
					}
					if allowListed && !findingStringHasRuleID(verdict.Findings, "STATIC-ALLOW") {
						t.Fatalf("%s: an allow-listed write to a file the agent does not load was not STATIC-ALLOW: %+v", tc.connector, verdict)
					}
					return
				}
				if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, tc.rule) {
					t.Fatalf("%s: verdict=%+v, want a %s block", tc.connector, verdict, tc.rule)
				}
			})
		}
	}
}

// The same rule by file identity on a real file system, from the gateway's
// own view and the managed hook client's evidence: another name of a file
// the agent does not load (a hard link, the project file through a
// symlinked working directory) is ordinary, also with the shell
// allow-listed. Another name of the file the agent loads, or of a file the
// session reported loading, is that instruction file.
func TestInstructionProtectionIdentityOnlyOfTheAgentsLoadedFiles(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	soul := writeActiveAgentTestFile(t, project, "SOUL.md")
	agents := writeActiveAgentTestFile(t, project, "AGENTS.md")
	claude := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	soulLink := instructionIdentityTestLink(t, soul, filepath.Join(root, "elsewhere", "soul-notes.txt"))
	agentsLink := instructionIdentityTestLink(t, agents, filepath.Join(root, "elsewhere", "agents-notes.txt"))
	claudeLink := instructionIdentityTestLink(t, claude, filepath.Join(root, "elsewhere", "claude-notes.txt"))
	linkedCWD := instructionIdentityTestSymlink(t, project, filepath.Join(root, "workdir"))
	for _, tc := range []struct {
		name, path, cwd, loaded, rule string
	}{
		{"hard link to an unloaded project SOUL.md", soulLink, project, "", ""},
		{"hard link to an unloaded project AGENTS.md", agentsLink, project, "", ""},
		{"unloaded project SOUL.md through a symlinked working directory", filepath.Join(linkedCWD, "SOUL.md"), linkedCWD, "", ""},
		{"hard link to the project CLAUDE.md", claudeLink, project, "", "COG-CLAUDE-MD"},
		{"hard link to a loaded project SOUL.md", soulLink, project, soul, "COG-SOUL"},
	} {
		for _, allowListed := range []bool{false, true} {
			for _, call := range instructionIdentityWrites(tc.path) {
				for source, ctx := range instructionIdentityContexts(t, tc.cwd, call.tool, call.input) {
					api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
					if allowListed {
						allowTool(api.scannerCfg, call.tool, "", "vetted")
					}
					session := "identity-" + call.tool
					if tc.loaded != "" {
						api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
							HookEventName: "InstructionsLoaded", SessionID: session, CWD: tc.cwd, FilePath: tc.loaded,
						})
					}
					response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: session, CWD: tc.cwd,
						ToolName: call.tool, ToolInput: call.input,
					})
					label := tc.name + " " + call.tool + " (" + source + ")"
					if allowListed {
						label += " allow-listed"
					}
					if tc.rule == "" {
						if cogBlocked(response.Action, response.WouldBlock, response.Findings) || response.Action == guardrailActionBlock {
							t.Errorf("%s was blocked: action=%q findings=%v", label, response.Action, response.Findings)
						}
						continue
					}
					if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, tc.rule) {
						t.Errorf("%s: action=%q findings=%v, want a %s block", label, response.Action, response.Findings, tc.rule)
					}
				}
			}
		}
	}
}

// A session's InstructionsLoaded proof survives a gateway restart: the
// restarted gateway restores what the session loaded and blocks a write to
// it. A session that ended or started again since, a session that loaded
// nothing and a record that names another session get nothing from it.
func TestInstructionLoadsSurviveGatewayRestart(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	soul := writeActiveAgentTestFile(t, project, "SOUL.md")
	dataDir := t.TempDir()
	gateway := func() *APIServer {
		api := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
		api.scannerCfg.DataDir = dataDir
		return api
	}
	lifecycle := func(api *APIServer, event, session string) {
		api.evaluateClaudeCodeHook(authenticatedClaudeCodeTestContext(), claudeCodeHookRequest{
			HookEventName: event, SessionID: session, CWD: project, FilePath: soul, Source: "resume",
		})
	}
	input := map[string]interface{}{"command": "printf x >> SOUL.md"}
	ctx := withAuthenticatedHookConnector(instructionResolvedWriteContext(t, project, "Bash", input), "claudecode")
	write := func(api *APIServer, session string) (string, []string) {
		response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: session, CWD: project, ToolName: "Bash", ToolInput: input,
		})
		return response.Action, response.Findings
	}
	first := gateway()
	for _, session := range []string{"running", "ended", "started-again"} {
		lifecycle(first, "InstructionsLoaded", session)
		if action, findings := write(first, session); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-SOUL") {
			t.Fatalf("%s before the restart: action=%q findings=%v", session, action, findings)
		}
	}
	lifecycle(first, "SessionEnd", "ended")
	lifecycle(first, "SessionStart", "started-again")
	forged := activeAgentContextKey{connector: "claudecode", sessionID: "forged"}
	record, err := json.Marshal(instructionLoadRecord{Connector: "claudecode", Session: "running", Files: []string{soul}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(instructionLoadRecordPath(first.instructionLoadDir(), forged), record, 0o600); err != nil {
		t.Fatal(err)
	}

	after := gateway()
	if action, findings := write(after, "running"); action != guardrailActionBlock || !findingStringHasRuleID(findings, "COG-SOUL") {
		t.Fatalf("a running session's loaded SOUL.md after the restart: action=%q findings=%v", action, findings)
	}
	for _, session := range []string{"ended", "started-again", "never-loaded", "forged"} {
		if action, findings := write(after, session); action == guardrailActionBlock {
			t.Errorf("%s after the restart was blocked: findings=%v", session, findings)
		}
	}
	// Without a data directory the proof stays in memory, as before.
	memoryOnly := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH")
	lifecycle(memoryOnly, "InstructionsLoaded", "memory")
	if memoryOnly.instructionLoadDir() != "" {
		t.Fatal("a gateway without a data directory has a load-record directory")
	}
	if action, findings := write(instructionProtectionTestAPI(t, "claudecode", "action", "HIGH"), "memory"); action == guardrailActionBlock {
		t.Fatalf("a load recorded nowhere was restored: findings=%v", findings)
	}
}
