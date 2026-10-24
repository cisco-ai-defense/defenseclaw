// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A file spelled with an instruction name is an instruction file only where
// agents load it from or when the session loaded it. Action mode protects
// those; a SOUL.md fixture, a CLAUDE.md template or an AGENTS.md copy
// anywhere else is ordinary and its writes and deletes are not blocked,
// with the tool allow-listed (STATIC-ALLOW) or not. These decision cases
// run on every OS; the Windows ones use the PowerShell dialect.
func TestInstructionProtectionOnlyInLoadLocations(t *testing.T) {
	const (
		cwd     = "/repo"
		home    = "/home/alice"
		winCWD  = `C:\Repo`
		winHome = `C:\Users\alice`
	)
	type decision struct {
		name, command, cwd, home, guestCWD, rule string
		loaded                                   []string
		loadedIdentity                           string
		dialect                                  actionfacts.Dialect
	}
	posix := func(name, command, workdir, rule string, loaded ...string) decision {
		return decision{name: name, command: command, cwd: workdir, home: home, rule: rule, loaded: loaded, dialect: actionfacts.DialectPOSIX}
	}
	windows := func(name, command, rule string) decision {
		return decision{name: name, command: command, cwd: winCWD, home: winHome, rule: rule, dialect: actionfacts.DialectPowerShell}
	}
	var cases []decision
	for rule, name := range instructionRuleFiles {
		cases = append(cases,
			posix("fixture append "+name, "printf x >> /tmp/fixtures/"+name, cwd, ""),
			posix("fixture write "+name, "printf x > /tmp/fixtures/"+name, cwd, ""),
			posix("fixture delete "+name, "rm -f /tmp/fixtures/"+name, cwd, ""),
			posix("project append "+name, "printf x >> /repo/"+name, cwd, rule),
			windows("Windows fixture write "+name, `Set-Content -LiteralPath 'C:\fixtures\`+name+`' -Value x`, ""),
			windows("Windows project write "+name, `Set-Content -LiteralPath 'C:\Repo\`+name+`' -Value x`, rule),
		)
	}
	cases = append(cases,
		posix("sibling directory sharing a prefix", "printf x >> /repository/CLAUDE.md", cwd, ""),
		posix("a .claude folder outside the project", "printf x >> /tmp/.claude/CLAUDE.md", cwd, ""),
		posix("home folder no agent loads from", "printf x >> /home/alice/Documents/SOUL.md", cwd, ""),
		posix("a loaded file's neighbor", "printf x >> /opt/persona/other/SOUL.md", cwd, "", "/opt/persona/SOUL.md"),
		posix("parent of the working directory", "printf x >> /repo/AGENTS.md", "/repo/src/pkg", "COG-AGENTS-MD"),
		posix("filesystem root above the working directory", "printf x >> /CLAUDE.md", cwd, "COG-CLAUDE-MD"),
		posix("project .claude folder from a subdirectory", "printf x >> /repo/.claude/CLAUDE.md", "/repo/src", "COG-CLAUDE-MD"),
		posix("home", "printf x >> /home/alice/CLAUDE.md", cwd, "COG-CLAUDE-MD"),
		posix("home .claude", "printf x >> /home/alice/.claude/CLAUDE.md", cwd, "COG-CLAUDE-MD"),
		posix("home .codex", "printf x >> /home/alice/.codex/AGENTS.md", cwd, "COG-AGENTS-MD"),
		posix("OpenClaw workspace", "printf x >> /home/alice/.openclaw/workspace/SOUL.md", cwd, "COG-SOUL"),
		posix("OpenClaw home", "printf x >> /home/alice/.openclaw/openclaw.json", cwd, "COG-OPENCLAW-JSON"),
		posix("opencode global", "printf x >> /home/alice/.config/opencode/AGENTS.md", cwd, "COG-AGENTS-MD"),
		posix("loaded by the session", "printf x >> /opt/persona/SOUL.md", cwd, "COG-SOUL", "/opt/persona/SOUL.md"),
		posix("loaded file deleted", "rm -f /opt/persona/MEMORY.md", cwd, "COG-MEMORY", "/opt/persona/MEMORY.md"),
		windows("Windows case-variant project", `Set-Content -LiteralPath 'C:\REPO\agents.md' -Value x`, "COG-AGENTS-MD"),
		windows("Windows home .codex", `Set-Content -LiteralPath 'C:\Users\alice\.codex\AGENTS.md' -Value x`, "COG-AGENTS-MD"),
		windows("Windows home Documents", `Set-Content -LiteralPath 'C:\Users\alice\Documents\SOUL.md' -Value x`, ""),
	)
	patch := func(target string) string {
		return "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: " + target + "\n+x\n*** End Patch\nPATCH"
	}
	// A patch envelope's targets are this host's paths
	// (hookpaths.ApplyPatchWriteTargets).
	if runtime.GOOS == "windows" {
		cases = append(cases,
			windows("patch to a fixture", patch(`C:\fixtures\AGENTS.md`), ""),
			windows("patch to the project", patch(`C:\Repo\AGENTS.md`), "COG-AGENTS-MD"),
		)
	} else {
		cases = append(cases,
			posix("patch to a fixture", patch("/tmp/fixtures/AGENTS.md"), cwd, ""),
			posix("patch to the project", patch("/repo/AGENTS.md"), cwd, "COG-AGENTS-MD"),
		)
	}
	loadedByClient := posix("loaded, identified by the hook client", "printf x >> /opt/persona/IDENTITY.md", cwd, "COG-IDENTITY")
	loadedByClient.loadedIdentity = "/opt/persona/IDENTITY.md"
	guest := posix("sandbox guest working directory", "printf x >> /sandbox/project/CLAUDE.md", "/host/mount/project", "COG-CLAUDE-MD")
	guest.guestCWD = "/sandbox/project"
	cases = append(cases, loadedByClient, guest)

	for _, tc := range cases {
		for _, allowListed := range []bool{false, true} {
			name := tc.name
			if allowListed {
				name += " (allow-listed)"
			}
			t.Run(name, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, "claudecode", "default")
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = "claudecode"
				cfg.Guardrail.BlockAt = "HIGH"
				cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
				if allowListed {
					allowTool(cfg, "Bash", "", "vetted")
				}
				args, err := json.Marshal(map[string]string{"command": tc.command})
				if err != nil {
					t.Fatal(err)
				}
				request := &ToolInspectRequest{Tool: "Bash", Args: args, Direction: "tool_call", Connector: "claudecode"}
				action := trustedActionRequest{
					Input: actionfacts.Input{Tool: "Bash", Args: args, CWD: tc.cwd, ActiveHome: tc.home,
						ActiveAgentFiles: tc.loaded, DialectHint: tc.dialect},
					LegacyText: string(args), Connector: "claudecode", EnforcementCapable: true,
					SandboxGuestCWD: tc.guestCWD,
				}
				if tc.loadedIdentity != "" {
					action.ActiveAgentFileIdentities = map[string]string{"1:2": tc.loadedIdentity}
				}
				verdict := (&APIServer{scannerCfg: cfg}).inspectTrustedToolPolicyCtx(t.Context(), request, action)
				if tc.rule == "" {
					if verdict.Action == guardrailActionBlock {
						t.Fatalf("an ordinary file was blocked: %+v", verdict)
					}
					if allowListed && !findingStringHasRuleID(verdict.Findings, "STATIC-ALLOW") {
						t.Fatalf("an allow-listed write to an ordinary file was not STATIC-ALLOW: %+v", verdict)
					}
					return
				}
				if verdict.Action != guardrailActionBlock || !findingStringHasRuleID(verdict.Findings, tc.rule) {
					t.Fatalf("verdict=%+v, want a %s block", verdict, tc.rule)
				}
			})
		}
	}
}

// The same rule on a real file system, from the gateway's own view and the
// managed hook client's evidence: an existing instruction-named file outside
// the load locations that the session did not load is ordinary, while a
// hard link of that name to the project's CLAUDE.md, and the project's file
// reached through a symlinked working directory, are the instruction file.
func TestInstructionProtectionOnlyInLoadLocationsOnDisk(t *testing.T) {
	root := instructionIdentityTestRoot(t)
	project := filepath.Join(root, "project")
	instruction := writeActiveAgentTestFile(t, project, "CLAUDE.md")
	fixture := writeActiveAgentTestFile(t, filepath.Join(root, "fixtures"), "CLAUDE.md")
	soul := writeActiveAgentTestFile(t, filepath.Join(root, "fixtures"), "SOUL.md")
	link := instructionIdentityTestLink(t, instruction, filepath.Join(root, "linked", "CLAUDE.md"))
	linkedCWD := instructionIdentityTestSymlink(t, project, filepath.Join(root, "workdir"))
	for _, tc := range []struct {
		name, path, cwd, rule string
	}{
		{"unloaded CLAUDE.md fixture", fixture, project, ""},
		{"unloaded SOUL.md fixture", soul, project, ""},
		{"hard link named CLAUDE.md elsewhere", link, project, "COG-CLAUDE-MD"},
		{"project file through a symlinked working directory", instruction, linkedCWD, "COG-CLAUDE-MD"},
	} {
		for _, call := range instructionIdentityWrites(tc.path) {
			for source, ctx := range instructionIdentityContexts(t, tc.cwd, call.tool, call.input) {
				response := instructionProtectionTestAPI(t, "claudecode", "action", "HIGH").evaluateClaudeCodeHook(
					ctx, claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "locations", CWD: tc.cwd,
						ToolName: call.tool, ToolInput: call.input,
					})
				if tc.rule == "" {
					if response.Action == guardrailActionBlock {
						t.Errorf("%s %s (%s) was blocked: findings=%v", call.tool, tc.name, source, response.Findings)
					}
					continue
				}
				if response.Action != guardrailActionBlock || !findingStringHasRuleID(response.Findings, tc.rule) {
					t.Errorf("%s %s (%s): action=%q findings=%v, want a %s block", call.tool, tc.name, source, response.Action, response.Findings, tc.rule)
				}
			}
		}
	}
}
