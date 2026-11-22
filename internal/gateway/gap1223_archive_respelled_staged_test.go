// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

// gap1223Respell respells the program word of a command as the shell still
// reads it: a quote pair inside it, a backslash inside it, the whole word in
// double quotes, or upper case (the program on a case-blind file system).
func gap1223Respell(command, how string) string {
	word, rest, _ := strings.Cut(command, " ")
	switch how {
	case "quote":
		word = word[:1] + "''" + word[1:]
	case "bslash":
		word = word[:1] + `\` + word[1:]
	case "dq":
		word = `"` + word + `"`
	case "upper":
		word = strings.ToUpper(word)
	}
	return word + " " + rest
}

// rel-1-0-10:GAP-1223 (P1, s7-winresrev round 1). An extraction into the
// DefenseClaw state, or of a named member into it, is the proven state write
// whatever the spelling of the program word, as on rel: no raw-text gate
// stands in front of the archive reading. The write takes the GAP-0747 owner
// tiering (2026-11-15T15:20Z): a HIGH alert with the state finding in the
// default, permissive and managed default packs, a block in strict and
// managed strict.
func TestGAP1223RespelledExtractorIntoTheStateBlocks(t *testing.T) {
	home, cwd := gap1173WindowsStateHome(t)
	gap1173WriteArchive(t, filepath.Join(cwd, "plain.zip"), "notes.txt", "docs/a.md")
	gap1173WriteArchive(t, filepath.Join(cwd, "plain.tgz"), "notes.txt", "docs/a.md")
	commands := []string{
		"unzip -o plain.zip -d ~/.defenseclaw",
		"unzip -o plain.zip -d ~ .defenseclaw/config.yaml",
		"tar -xzf plain.tgz -C ~ .defenseclaw/config.yaml",
		"tar -xzf plain.tgz -C ~/.defenseclaw",
		"tar -xzf plain.tgz --directory ~/.defenseclaw/hooks",
		"unzip -o plain.zip -d ~/.defenseclaw/policies",
		"tar -xzf plain.tgz -C ~ --wildcards '.defenseclaw/*'",
		"unzip -o plain.zip '.defenseclaw/*' -d ~",
	}
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			for _, command := range commands {
				for _, how := range []string{"plain", "quote", "bslash", "dq", "upper"} {
					call := command
					if how != "plain" {
						call = gap1223Respell(command, how)
					}
					action, findings := boundedDecideClaudeCode(t, api, boundedEnv{home: home, cwd: cwd},
						boundedLaneCall{tool: "Bash", input: map[string]any{"command": call}})
					want := gap1173WantFor("write", tier.name, action, findings)
					if action != want || !findingStringHasRuleID(findings, "tamper.detector_state_write") {
						t.Errorf("%s %s [%s]: action %q, want %s with the state finding: %v", tier.name, how, call, action, want, findings)
					}
				}
			}
		})
	}
}

// rel-1-0-10:GAP-1224 (P2, s7-winresrev round 1). A whole-archive extraction
// into a folder that holds the state is read from the archive only when no
// earlier statement of the command may write it: a cp or mv onto the archive
// name before it means the archive the extraction opens is not the file at
// hook time, so it takes the unknown tier (alert in the default, permissive
// and managed packs, block in strict). The archive that is not there at all
// keeps the words verdict, and an archive no other statement names is still
// listed.
func TestGAP1224StagedArchiveIsNotListedAtHookTime(t *testing.T) {
	home, cwd := gap1173WindowsStateHome(t)
	gap1173WriteArchive(t, filepath.Join(cwd, "state.tar"), ".defenseclaw/config.yaml", "notes.txt")
	gap1173WriteArchive(t, filepath.Join(cwd, "state.zip"), ".defenseclaw/config.yaml", "notes.txt")
	gap1173WriteArchive(t, filepath.Join(cwd, "plain.tar"), "notes.txt", "docs/a.md")
	gap1173WriteArchive(t, filepath.Join(cwd, "plain.zip"), "notes.txt", "docs/a.md")
	rows := []struct{ kind, command string }{
		{"unknown", "cp state.tar plain.tar && tar -xf plain.tar -C ~"},
		{"unknown", "mv state.zip plain.zip && unzip -o plain.zip -d ~"},
		{"unknown", "cp state.tar plain.tar; tar -xf plain.tar -C ~"},
		{"unknown", `cp state.tar plain.tar && python3 -c 'import tarfile, os; tarfile.open("plain.tar").extractall(os.path.expanduser("~"))'`},
		{"keep", "cp state.tar fresh.tar && tar -xf fresh.tar -C ~"},
		{"keep", "mkdir -p out && tar -xf plain.tar -C ~"},
		{"keep", "ls && tar -xf plain.tar -C ~"},
		{"write", "ls && tar -xf state.tar -C ~"},
	}
	for _, tier := range boundedTestTiers {
		t.Run(tier.name, func(t *testing.T) {
			api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
			for _, r := range rows {
				action, findings := boundedDecideClaudeCode(t, api, boundedEnv{home: home, cwd: cwd},
					boundedLaneCall{tool: "Bash", input: map[string]any{"command": r.command}})
				want := gap1173WantFor(r.kind, tier.name, action, findings)
				state := findingStringHasRuleID(findings, "tamper.detector_state_write")
				if action != want || (r.kind == "keep") == state {
					t.Errorf("%s %s [%s]: action %q state finding %t, want %q: %v", tier.name, r.kind, r.command, action, state, want, findings)
				}
			}
		})
	}
}
