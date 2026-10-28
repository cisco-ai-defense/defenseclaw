// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0360: a custom pack copied from the 0.8.x default kept its pattern-only
// command rules, which 1.0 runs as candidate filters that never block: the
// operator's marker rule and the old built-in rules stopped enforcing, and
// doctor said PASS. The migration's rebase restores both. GAP-1225: the
// operator's own rule file of another category was left as it was, so its
// marker rule stopped blocking too and nothing said so.
func TestRebasedZeroEightPackKeepsTheOperatorRuleBlocking(t *testing.T) {
	old := t.TempDir()
	if err := os.MkdirAll(filepath.Join(old, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	// CMD-RM-RF keeps the shipped 0.8.x regex: an edited regex is the rule's
	// sole condition after the rebase (GAP-1004), so only an unedited copy
	// inherits the 1.0 expression.
	const rmRF08 = `'(?i)\brm\s+(?:-[a-zA-Z]*\s+)*(?:-[a-zA-Z]*)?(?:r[a-zA-Z]*f|f[a-zA-Z]*r)\b(?:\s+\S+)*\s+/` +
		`(?:$|["''\s,}\]]|(?:etc|bin|sbin|usr|var|home|root|opt|boot|lib(?:64)?|srv|mnt|dev|proc|sys)(?:$|/|["''\s,}\]]))'`
	commands := "version: 1\ncategory: command\nrules:\n" +
		"  - id: CMD-RM-RF\n    pattern: " + rmRF08 + "\n    title: \"Recursive delete\"\n    severity: CRITICAL\n    confidence: 0.9\n    tags: [destructive]\n" +
		"  - id: CMD-ACME-MARKER\n    pattern: acme-marker-7f3c\n    title: \"Acme marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [execution]\n" +
		"  - id: CMD-ACME-SPACED\n    pattern: 'acme\\s+spaced'\n    title: \"Acme spaced\"\n    severity: HIGH\n    confidence: 0.9\n    tags: [execution]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "commands.yaml"), []byte(commands), 0o644); err != nil {
		t.Fatal(err)
	}
	own := "version: 1\ncategory: acme-markers\nrules:\n" +
		"  - id: ACME-OWN-MARKER\n    pattern: 'acme\\.own-7f3c'\n    title: \"Own marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n" +
		"  - id: ACME-OWN-SPACED\n    pattern: 'acme\\s+own'\n    title: \"Own spaced\"\n    severity: HIGH\n    confidence: 0.9\n    tags: [marker]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "acme.yaml"), []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	blocks := func(pack *guardrail.RulePack, command string) bool {
		t.Helper()
		const connector = "rebase-0-8"
		if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
			t.Fatal(err)
		}
		defer RemoveConnectorRulePackOverrides(connector)
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{
				Tool: "Bash", Command: command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
			},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		return buildVerdict(findings, "tool_call").Action == guardrailActionBlock
	}
	const marker = "echo acme-marker-7f3c > /tmp/x.txt"
	const ownMarker = "echo acme.own-7f3c > /tmp/y.txt"

	before, err := guardrail.LoadRulePack(old)
	if err != nil {
		t.Fatal(err)
	}
	if summary := before.Summary(); blocks(before, marker) || blocks(before, ownMarker) ||
		summary.StaleRuleCount != 1 || summary.AlertOnlyRuleCount != 4 {
		t.Fatalf("the 0.8.x copy: summary %+v; want unblocked markers, 1 stale and 4 alert-only rules", summary)
	}

	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	if !slices.Equal(plan.Expressed, []string{"ACME-OWN-MARKER", "CMD-ACME-MARKER"}) ||
		!slices.Equal(plan.AlertOnly, []string{"ACME-OWN-SPACED", "CMD-ACME-SPACED"}) {
		t.Fatalf("expressed %v alert-only %v", plan.Expressed, plan.AlertOnly)
	}
	rebased := t.TempDir()
	for rel, data := range plan.Files {
		target := filepath.Join(rebased, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	after, err := guardrail.LoadRulePack(rebased)
	if err != nil {
		t.Fatal(err)
	}
	if after.FilesDigest() != plan.Digest {
		t.Fatalf("digest %s, plan %s", after.FilesDigest(), plan.Digest)
	}
	if summary := after.Summary(); !blocks(after, marker) || !blocks(after, ownMarker) || !blocks(after, "rm -rf /") ||
		summary.StaleRuleCount != 0 || summary.AlertOnlyRuleCount != 2 {
		t.Fatalf("the rebased pack: summary %+v; want both markers and rm -rf / blocked, 0 stale and 2 alert-only rules", summary)
	}
	// GAP-1480: 0.8.x ran every rule over the prompt text too, so the marker
	// rule of commands.yaml blocked a prompt that held the marker. A content
	// scan leaves command rules to the tool-call dispatcher; the migrated
	// literal rule still runs over the prompt, a built-in command rule does not.
	promptAction := func(prompt string) string {
		t.Helper()
		const connector = "rebase-0-8"
		if err := ApplyConnectorRulePackOverrides(connector, after); err != nil {
			t.Fatal(err)
		}
		defer RemoveConnectorRulePackOverrides(connector)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		return (&APIServer{scannerCfg: cfg}).inspectMessageContent(t.Context(), &ToolInspectRequest{
			Tool: "message", Content: prompt, Direction: "prompt", Connector: connector,
			contentScope: ruleContentScopeUntrusted,
		}).Action
	}
	for prompt, want := range map[string]string{
		"Please repeat this token back to me: acme-marker-7f3c": guardrailActionBlock,
		"What does rm -rf / do on a Linux host?":                guardrailActionAllow,
		"Please summarize the README for me":                    guardrailActionAllow,
	} {
		if got := promptAction(prompt); got != want {
			t.Errorf("prompt %q: action %q, want %q", prompt, got, want)
		}
	}

	// A gateway reload of the un-migrated v8 source must enforce the same
	// rebased rules without changing the operator's 0.8.x pack or config.
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + configDir +
		"\nguardrail:\n  rule_pack_dir: " + old + "\nobservability: {}\n")
	if err := os.WriteFile(configPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeConfig, err := loadRuntimeConfigCandidate(configPath, source)
	if err != nil {
		t.Fatal(err)
	}
	runtimePack, err := loadGlobalRulePack(guardrail.NewRulePackCache(), cloneConfig(runtimeConfig), "global")
	if err != nil {
		t.Fatal(err)
	}
	if !blocks(runtimePack, marker) || runtimePack.FilesDigest() != plan.Digest {
		t.Fatalf("read-only v8 load kept the original pack: digest %s", runtimePack.FilesDigest())
	}
	if current, err := os.ReadFile(filepath.Join(old, "rules", "commands.yaml")); err != nil || string(current) != commands {
		t.Fatalf("the v8 rule pack changed: %v", err)
	}
	if current, err := os.ReadFile(configPath); err != nil || string(current) != string(source) {
		t.Fatalf("the v8 config changed: %v", err)
	}
}

// GAP-1344: 0.8.x ran a rule's pattern over the tool call's argument text, so
// a carried literal rule blocked "touch dccert-block-marker.txt" too. The 1.0
// expression the rebase derives matched only an argument equal to the
// literal; it now blocks an argument that starts or ends with it and a path
// or host that holds it, and a \b literal only as a word, as 0.8.x did.
func TestRebasedLiteralRuleMatchesWhereZeroEightDid(t *testing.T) {
	old := t.TempDir()
	if err := os.MkdirAll(filepath.Join(old, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	own := "version: 1\ncategory: cert-marker\nrules:\n" +
		"  - id: CERT-MARKER\n    pattern: dccert-block-marker\n    title: \"Marker\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n" +
		"  - id: CERT-WORD\n    pattern: '\\bdcword\\b'\n    title: \"Word\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n" +
		// GAP-1478: the rule of the Windows upgrade smoke, a regex rule
		// (detection-only) and a literal rule with an expression of its own.
		"  - id: UPG6W089-MARKER-BLOCK\n    pattern: upg6w089-block-marker\n    title: \"Windows upgrade smoke marker command (block)\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [upgrade-smoke]\n" +
		"  - id: CERT-REGEX\n    pattern: 'dcregex-[0-9]+'\n    title: \"Regex\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n" +
		"  - id: CERT-EXPR\n    pattern: dcexpr-marker\n    expression: \"f.commands.exists(c, c.program == 'dcexpr-tool')\"\n    title: \"Expr\"\n    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "cert.yaml"), []byte(own), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil || !slices.Equal(plan.Expressed, []string{"CERT-MARKER", "CERT-WORD", "UPG6W089-MARKER-BLOCK"}) {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	rebased := t.TempDir()
	for rel, data := range plan.Files {
		target := filepath.Join(rebased, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pack, err := guardrail.LoadRulePack(rebased)
	if err != nil {
		t.Fatal(err)
	}
	const connector = "rebase-literal"
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatal(err)
	}
	defer RemoveConnectorRulePackOverrides(connector)
	for _, tc := range []struct {
		tool, command, args, rule    string
		blocked, powerShell, windows bool
	}{
		{tool: "Bash", command: "touch dccert-block-marker.txt", rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: "echo dccert-block-marker", rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: "ls /tmp/x/dccert-block-marker", rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: `echo "dccert-block-marker"`, rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: "printf %s%s first dccert-block-marker-3", rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: "curl -s https://dccert-block-marker.example/", rule: "CERT-MARKER", blocked: true},
		{tool: "Write", args: `{"file_path":"/home/alice/project/dccert-block-marker.txt","content":""}`, rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: ": > dccert-block-marker.txt", rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: "echo dccert-block", rule: "CERT-MARKER"},
		{tool: "Bash", command: "echo dcword", rule: "CERT-WORD", blocked: true},
		{tool: "Bash", command: "cat /tmp/dcword.txt", rule: "CERT-WORD", blocked: true},
		{tool: "Bash", command: "cat /tmp/dcwords.txt", rule: "CERT-WORD"},
		// GAP-1415: Codex on Windows sends a PowerShell script; a pipeline or
		// a second statement left it partial, so the rule was detection-only.
		{tool: "Bash", command: "New-Item -ItemType File -Name dccert-block-marker.txt -Force | Out-Null", rule: "CERT-MARKER", blocked: true, powerShell: true},
		{tool: "Bash", command: "$null = New-Item -Path . -Name dccert-block-marker.txt; Get-Item x", rule: "CERT-MARKER", blocked: true, powerShell: true},
		{tool: "Bash", command: "echo dccert-block-marker > m.txt", rule: "CERT-MARKER", blocked: true, powerShell: true},
		// The script Codex ran: a pipeline and a compound if/else after the
		// New-Item statement, whose own path holds the literal.
		{tool: "Bash", command: `New-Item -ItemType File -Path 'C:\Users\Public\rv17u\dccert-block-marker.txt' -Force | Out-Null; if (Test-Path -LiteralPath 'C:\Users\Public\rv17u\dccert-block-marker.txt') { 'worked' } else { 'failed' }`, rule: "CERT-MARKER", blocked: true, powerShell: true},
		// GAP-1469: the literal as a quoted string inside a call that is
		// parsed only in part (the retry Codex wrote after the first block,
		// a .NET method call), inside a longer argument, and in an inline
		// script.
		{tool: "Bash", command: `[System.IO.File]::WriteAllText((Join-Path (Get-Location) m.txt), 'dccert-block-marker')`, rule: "CERT-MARKER", blocked: true, powerShell: true},
		{tool: "Bash", command: `Set-Content -Path m.txt -Value 'dccert-block-marker'`, rule: "CERT-MARKER", blocked: true, powerShell: true},
		{tool: "Bash", command: "echo xdccert-block-markery", rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: `python3 -c "open('m', 'w').write('dccert-block-marker')"`, rule: "CERT-MARKER", blocked: true},
		{tool: "Write", args: `{"file_path":"/home/alice/project/m.txt","content":"dccert-block-marker"}`, rule: "CERT-MARKER", blocked: true},
		// GAP-1478: the Windows per-user upgrade smoke. Codex on Windows
		// sends its PowerShell as is (the dialect the hook picks, which is
		// not PowerShell for a .NET call), so the rule pattern runs over the
		// text of the call: every way to write the marker blocks, the
		// controls (no literal, a near miss) stay allowed.
		{tool: "Bash", command: "Set-Content -LiteralPath .\\upg6w-codex2.txt -Value 'upg6w089-block-marker' -NoNewline", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'upg6w-codex2.txt'), 'upg6w089-block-marker')", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "[System.IO.File]::AppendAllText('m.txt', 'upg6w089-block-marker')", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "[System.IO.File]::WriteAllText('C:\\Users\\Public\\upg6w089-block-marker.txt', 'x')", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "'upg6w089-block-marker' | Out-File -FilePath m.txt", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "Add-Content -Path m.txt -Value 'upg6w089-block-marker'", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "New-Item -ItemType File -Name upg6w089-block-marker.txt", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "New-Item -ItemType File -Path .\\upg6w089-block-marker.txt", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "@'\nupg6w089-block-marker\n'@ | Set-Content m.txt", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "$m = 'upg6w089-block-marker'; Set-Content -Path m.txt -Value $m", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "cmd /c echo upg6w089-block-marker > m.txt", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "bash -c \"echo upg6w089-block-marker\"", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "python -c \"open('m.txt', 'w').write('upg6w089-block-marker')\"", rule: "UPG6W089-MARKER-BLOCK", blocked: true, windows: true},
		{tool: "Bash", command: "[System.IO.File]::WriteAllText((Join-Path (Get-Location) 'upg6w-codex2.txt'), 'hello')", rule: "UPG6W089-MARKER-BLOCK", windows: true},
		{tool: "Bash", command: "Set-Content -Path m.txt -Value 'upg6w089-block-markr'", rule: "UPG6W089-MARKER-BLOCK", windows: true},
		{tool: "Write", args: `{"file_path":"C:\\Users\\dcw-std1\\m.txt","content":"upg6w089-block-marker"}`, rule: "UPG6W089-MARKER-BLOCK", blocked: true},
		{tool: "Bash", command: "echo upg6w089-block-marker", rule: "UPG6W089-MARKER-BLOCK", blocked: true},
		// Rules that were never a plain literal are not widened: a regex
		// rule stays detection-only, and a literal pattern with an
		// expression of its own blocks only what the expression says.
		{tool: "Bash", command: "echo dcregex-12", rule: "CERT-REGEX"},
		{tool: "Write", args: `{"file_path":"/home/alice/project/m.txt","content":"dcregex-12"}`, rule: "CERT-REGEX"},
		{tool: "Bash", command: "echo dcexpr-marker", rule: "CERT-EXPR"},
		{tool: "Write", args: `{"file_path":"/home/alice/project/m.txt","content":"dcexpr-marker"}`, rule: "CERT-EXPR"},
		{tool: "Bash", command: "dcexpr-tool run", rule: "CERT-EXPR", blocked: true},
		// GAP-1415 (rv18): Codex assigns the path to a variable first, and
		// Claude Code wraps the same script in powershell -Command; a control
		// of the same shape with another file name stays allowed.
		{tool: "Bash", command: `$path = 'C:\Users\Public\rv18u\dccert-block-marker.txt'; New-Item -Path $path -ItemType File -Force | Out-Null; $item = Get-Item -LiteralPath $path; [pscustomobject]@{ Path = $item.FullName; Exists = $true; Length = $item.Length }`, rule: "CERT-MARKER", blocked: true, powerShell: true},
		{tool: "Bash", command: `$path = 'C:\Users\Public\rv18u\dccert-notes.txt'; New-Item -Path $path -ItemType File -Force | Out-Null; $item = Get-Item -LiteralPath $path; [pscustomobject]@{ Path = $item.FullName; Exists = $true; Length = $item.Length }`, rule: "CERT-MARKER", powerShell: true},
		{tool: "Bash", command: `powershell -Command "New-Item -ItemType File -Path 'C:\Users\Public\rv18u\dccert-block-marker.txt' -Force | Out-Null; Get-Item 'C:\Users\Public\rv18u\dccert-block-marker.txt' | Select-Object Name, Length"`, rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: `powershell -Command New-Item -ItemType File -Path C:\Users\Public\rv18u\dccert-block-marker.txt -Force | Out-Null; Get-Item C:\Users\Public\rv18u\dccert-block-marker.txt | Select-Object Name, Length`, rule: "CERT-MARKER", blocked: true},
		{tool: "Bash", command: `powershell -Command "New-Item -ItemType File -Path 'C:\Users\Public\rv18u\dccert-notes.txt' -Force | Out-Null; Get-Item 'C:\Users\Public\rv18u\dccert-notes.txt' | Select-Object Name, Length"`, rule: "CERT-MARKER"},
	} {
		input := actionfacts.Input{
			Tool: tc.tool, Command: tc.command, CWD: "/home/alice/project",
			ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
		}
		if tc.powerShell {
			input.DialectHint = actionfacts.DialectPowerShell
		}
		if tc.windows {
			input.DialectHint = selectWindowsShellDialect(tc.tool, tc.command, input)
		}
		legacy := tc.command
		if tc.args != "" {
			input.Args, legacy = json.RawMessage(tc.args), tc.args
		}
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: input, LegacyText: legacy, Connector: connector, EnforcementCapable: true,
		})
		matched := slices.ContainsFunc(findings, func(f RuleFinding) bool { return f.RuleID == tc.rule && f.contributesToEnforcement() })
		if blocked := matched && buildVerdict(findings, "tool_call").Action == guardrailActionBlock; blocked != tc.blocked {
			t.Errorf("%s %s%s: blocked by %s = %v, want %v", tc.tool, tc.command, tc.args, tc.rule, blocked, tc.blocked)
		}
	}
}

// GAP-1314: a 0.8.x copy of the default pack whose operator changed the
// CMD-RM-RF pattern to a marker blocked that marker on 0.8.x. The rebase gave
// the rule a literal expression under the built-in ID, and the gateway's
// semantic owner and match validation of CMD-RM-RF (recursive deletes only)
// dropped every match of it. The edited rule now gets an ID of its own and
// keeps the operator's title, so it blocks the marker, while the shipped
// CMD-RM-RF still blocks a recursive delete of the root.
func TestRebasedEditedBuiltinRuleBlocksUnderItsOwnID(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join("..", "guardrail", "legacy08", "commands.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	legacy = bytes.ReplaceAll(legacy, []byte("\r\n"), []byte("\n")) // a Windows checkout
	edit := func(data []byte, id, pattern, rest string) []byte {
		t.Helper()
		block := regexp.MustCompile(`(?m)^  - id: ` + id + `\n    pattern: .*\n    title: .*\n    severity: .*\n`)
		if !block.Match(data) {
			t.Fatalf("no %s in the 0.8.x commands.yaml", id)
		}
		return block.ReplaceAllLiteral(data, []byte("  - id: "+id+"\n    pattern: "+pattern+"\n"+rest))
	}
	commands := edit(legacy, "CMD-RM-RF", "dccert-rmrf-marker", "    title: \"Operator marker\"\n    severity: CRITICAL\n")
	commands = edit(commands, "CMD-ENV-DUMP", `'dccert\s+env'`, "    title: \"Operator env marker\"\n    severity: HIGH\n")
	old := t.TempDir()
	if err := os.MkdirAll(filepath.Join(old, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(old, "rules", "commands.yaml"), commands, 0o644); err != nil {
		t.Fatal(err)
	}
	// GAP-1358: rule IDs are unique across the pack. A rule of another file
	// that has the ID the rename would give made the rebased copy fail to
	// load, and the upgrade pinned the 0.8.x pack, whose edited rule no
	// longer blocked.
	acme := "version: 1\ncategory: acme\nrules:\n  - id: CUSTOM-CMD-RM-RF\n    pattern: 'acme[0-9]+marker'\n" +
		"    title: \"Acme marker\"\n    severity: LOW\n    confidence: 0.5\n    tags: [acme]\n"
	if err := os.WriteFile(filepath.Join(old, "rules", "acme.yaml"), []byte(acme), 0o644); err != nil {
		t.Fatal(err)
	}
	plan, err := guardrail.PlanRulePackRebase(old)
	if err != nil || plan == nil {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	if !slices.Equal(plan.Renamed, []string{"CMD-RM-RF -> CUSTOM-CMD-RM-RF-2", "CMD-ENV-DUMP -> CUSTOM-CMD-ENV-DUMP"}) ||
		!slices.Equal(plan.Expressed, []string{"CUSTOM-CMD-RM-RF-2"}) || !slices.Equal(plan.AlertOnly, []string{"CUSTOM-CMD-RM-RF", "CUSTOM-CMD-ENV-DUMP"}) {
		t.Fatalf("renamed %v expressed %v alert-only %v", plan.Renamed, plan.Expressed, plan.AlertOnly)
	}
	rebased := t.TempDir()
	for rel, data := range plan.Files {
		target := filepath.Join(rebased, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pack, err := guardrail.LoadRulePack(rebased)
	if err != nil {
		t.Fatal(err)
	}
	const connector = "rebase-edited-builtin"
	if err := ApplyConnectorRulePackOverrides(connector, pack); err != nil {
		t.Fatal(err)
	}
	defer RemoveConnectorRulePackOverrides(connector)
	for _, tc := range []struct {
		command, rule, title string
		blocked              bool
	}{
		{command: "echo dccert-rmrf-marker", rule: "CUSTOM-CMD-RM-RF-2", title: "Operator marker", blocked: true},
		{command: "rm -rf /", rule: "CMD-RM-RF", title: "Recursive force delete from critical root path", blocked: true},
		{command: "echo hello"},
	} {
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{
				Tool: "Bash", Command: tc.command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
			},
			LegacyText: tc.command, Connector: connector, EnforcementCapable: true,
		})
		verdict := buildVerdict(findings, "tool_call")
		matched := tc.rule == "" || slices.ContainsFunc(findings, func(f RuleFinding) bool {
			return f.RuleID == tc.rule && f.Title == tc.title && f.contributesToEnforcement()
		})
		if blocked := verdict.Action == guardrailActionBlock; !matched || blocked != tc.blocked {
			t.Errorf("%s: verdict %s (%s), want blocked %v by %s", tc.command, verdict.Action, verdict.Reason,
				tc.blocked, tc.rule)
		}
	}
}

// GAP-1359: a guardrail profile copied the configuration through JSON, which
// dropped RuntimeV8RulePackRebase, so a user matched to the profile scanned
// with the 0.8.x pack as it was and an edited rule that blocked for every
// other user let the same tool call through.
func TestRuntimeV8RebaseReachesGuardrailProfiles(t *testing.T) {
	legacy, err := os.ReadFile(filepath.Join("..", "guardrail", "legacy08", "commands.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	legacy = bytes.ReplaceAll(legacy, []byte("\r\n"), []byte("\n")) // a Windows checkout
	block := regexp.MustCompile(`(?m)^  - id: CMD-RM-RF\n    pattern: .*\n`)
	if !block.Match(legacy) {
		t.Fatal("no CMD-RM-RF in the 0.8.x commands.yaml")
	}
	commands := block.ReplaceAllLiteral(legacy, []byte("  - id: CMD-RM-RF\n    pattern: dccert-profile-marker\n"))
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rules", "commands.yaml"), commands, 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := guardrail.RulePackDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{RuntimeV8RulePackRebase: true}
	cfg.Guardrail.RulePack = "acme"
	cfg.Guardrail.CustomPacks = map[string]config.CustomRulePack{"acme": {Path: dir, Digest: "sha256:" + digest}}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"devs": {Description: "inherits the pack"}}
	cache := guardrail.NewRulePackCache()
	base, err := loadGlobalRulePack(cache, cfg, "guardrail")
	if err != nil {
		t.Fatal(err)
	}
	set, err := newGuardrailProfileSet(cfg, cache, true)
	if err != nil {
		t.Fatal(err)
	}
	profile := set.packs[effectiveRulePackKey(set.profiles["devs"].Config, "")]
	for _, tc := range []struct {
		name string
		pack *guardrail.RulePack
	}{{"unprofiled user", base}, {"profile devs", profile}} {
		if tc.pack == nil {
			t.Fatalf("%s: no rule pack", tc.name)
		}
		const connector = "rebase-profile"
		if err := ApplyConnectorRulePackOverrides(connector, tc.pack); err != nil {
			t.Fatal(err)
		}
		const command = "echo dccert-profile-marker"
		findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
			Input: actionfacts.Input{
				Tool: "Bash", Command: command, CWD: "/home/alice/project",
				ActiveHome: "/home/alice", DialectHint: actionfacts.DialectPOSIX,
			},
			LegacyText: command, Connector: connector, EnforcementCapable: true,
		})
		RemoveConnectorRulePackOverrides(connector)
		if verdict := buildVerdict(findings, "tool_call"); verdict.Action != guardrailActionBlock {
			t.Errorf("%s: verdict %s (%s), want the edited 0.8.x rule to block", tc.name, verdict.Action, verdict.Reason)
		}
	}
}
