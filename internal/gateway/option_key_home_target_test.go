// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2399: the shell expands HOME anywhere in a word, so dd of=$HOME/f
// and of=${HOME}/f write the file of=~/f, of=~<login>/f and the absolute
// spelling name. A write to active DefenseClaw state through that spelling
// blocks, with the proof the observe self-protection exception reads.
func TestOptionKeyHomeSpellingOfActiveStateIsTheHomePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home")
	}
	home := filepath.Join(t.TempDir(), "dcku")
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"), cwd} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		filepath.Join(home, ".defenseclaw", "config.yaml"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(cwd, "a.txt"),
	} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	state := []string{
		"dd if=a.txt of=$HOME/.defenseclaw/config.yaml",
		"dd if=a.txt of=${HOME}/.defenseclaw/config.yaml",
		"dd if=a.txt of=$HOME/.defenseclaw/hooks/f.sh",
		"dd if=a.txt of=${HOME}/.defenseclaw/hooks/f.sh",
		`dd if=a.txt of="$HOME/.defenseclaw/config.yaml"`,
		`dd if=a.txt of="${HOME}"/.defenseclaw/config.yaml`,
		"dd if=a.txt of=$HOME/.defenseclaw/config.yaml status=none",
	}
	allow := []string{
		"dd if=a.txt of=$HOME/project/b.img",
		"dd if=a.txt of=${HOME}/project/b.img",
		"dd if=$HOME/.defenseclaw/config.yaml of=copy.yaml",
		"dd if=a.txt of=b.img",
		"make PREFIX=$HOME/.local",
		"echo of=$HOME/.defenseclaw/config.yaml",
		"git status --short",
	}
	for _, connectorName := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connectorName)
		judge := func(command string) []RuleFinding {
			input := actionfacts.Input{
				Tool: "Bash", Command: command, CWD: cwd,
				ActiveHome: home, DialectHint: actionfacts.DialectPOSIX,
			}
			return dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, Connector: connectorName, EnforcementCapable: true,
			})
		}
		for _, command := range state {
			findings := judge(command)
			if buildVerdict(findings, "tool_call").Action != "block" {
				t.Errorf("%s %q: not blocked (%v)", connectorName, command, FindingStrings(findings))
				continue
			}
			proven := false
			for _, finding := range findings {
				if finding.RuleID == "tamper.detector_state_write" && finding.contributesToEnforcement() &&
					finding.proof.authorizes(finding.RuleID) &&
					(finding.proof.kind == findingProofActionFactsSemantic ||
						finding.proof.kind == findingProofActionFactsSubgraph ||
						finding.proof.kind == findingProofActiveStateMutation) {
					proven = true
				}
			}
			if !proven {
				t.Errorf("%s %q: no proven state write for observe (%v)", connectorName, command, FindingStrings(findings))
			}
		}
		if findings := judge("dd if=a.txt of=$HOME/.ssh/authorized_keys"); buildVerdict(findings, "tool_call").Action != "block" {
			t.Errorf("%s dd of=$HOME/.ssh/authorized_keys: not blocked (%v)", connectorName, FindingStrings(findings))
		}
		for _, command := range allow {
			if findings := judge(command); buildVerdict(findings, "tool_call").Action == "block" {
				t.Errorf("%s %q: blocked, want allow (%v)", connectorName, command, FindingStrings(findings))
			}
		}
	}
}
