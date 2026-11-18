// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1260Rows are the rel-1-0-10:GAP-1260 rows (review round 3 of
// s7/g1209fix: V59, W03, W08, X05; Y rows of fix round 4) in the spelling of
// the home C:\Users\Alice. want is the verdict in the default and the strict
// pack: block (a proven overwrite of the detector config), unknown (alert in
// default, block in strict: a source whose name the call does not fix, and
// may be a state name, moved or copied into the state root or a state
// folder), allow (a new entry that is no state file, a base name no state
// entry has, or a folder out of the state).
func gap1260Rows() []struct{ id, want, command string } {
	return []struct{ id, want, command string }{
		// Git Bash passes //?/C:/... as written (the glob matches nothing),
		// and Windows opens it as C:/...: the file lands on the config.
		{"V59", "block", `mv -t //?/C:/Users/Alice/.defenseclaw config.yaml`},
		{"Y09", "block", `mv --target-directory=//?/C:/Users/Alice/.defenseclaw config.yaml`},
		{"W03", "unknown", `mv -t "$HOME/.defenseclaw" "$F"`},
		{"W08", "unknown", `mv -t "$HOME/.defenseclaw" $(ls backup)`},
		{"X05", "unknown", `cp -t "$HOME/.defenseclaw" "$1"`},
		{"Y10", "unknown", `mv -t //?/C:/Users/Alice/.defenseclaw "$F"`},
		{"Y12", "unknown", `install -t "$HOME/.defenseclaw" "$@"`},
		{"Y20", "block", `mv -t "$HOME/.defenseclaw" "$D/config.yaml"`},
		{"Y21", "unknown", `mv -t "$HOME/.defenseclaw" "$D"/conf*`},
		{"Y06", "allow", `mv -t //?/C:/Users/Alice/.defenseclaw notes.txt`},
		{"Y07", "allow", `mv -t "$HOME/backup" "$F"`},
		{"Y18", "allow", `mv --suffix="$S" -t "$HOME/.defenseclaw" notes.txt`},
		{"V35", "allow", `mv -t "$HOME/.defenseclaw" backup/notes.txt`},
		// A base name no state entry has: a new entry, as for notes.txt.
		{"X12", "allow", `mv -t "$HOME/.defenseclaw" "$F.txt"`},
		{"Y17", "allow", `mv -t "$HOME/.defenseclaw" notes*.txt`},
	}
}

// gap1260Want maps a row's want to the action of profile.
func gap1260Want(want, profile string) string {
	if want == "unknown" {
		if profile == "strict" {
			return "block"
		}
		return "alert"
	}
	return want
}

// gap1260Rule is the finding a row's verdict rests on: the state write of a
// proven overwrite, the evaluation limit of the unknown tier.
func gap1260Rule(want string) string {
	switch want {
	case "block":
		return "tamper.detector_state_write"
	case "unknown":
		return "ACTION-COMPOUND-LIMIT"
	}
	return ""
}

// TestGAP1260TargetDirectoryUnknownSources pins rel-1-0-10:GAP-1260 on the
// reading the Windows hooks give a Bash or shell_command call of a drive
// home, on every OS. At e1633b41c9 the target-directory reading skipped any
// word with no static value: the folder //?/C:/... (a glob character) and
// the sources "$F" and $(ls x) were dropped, so these calls were allowed.
func TestGAP1260TargetDirectoryUnknownSources(t *testing.T) {
	const home = `C:\Users\Alice`
	resolved := map[string]string{"C:/Users/Alice/.defenseclaw": "C:/Users/Alice/.defenseclaw"}
	for _, name := range []string{"config.yaml", "notes.txt"} {
		value := "C:/Users/Alice/.defenseclaw/" + name
		resolved[value] = value
	}
	for _, profile := range []string{"default", "strict"} {
		connector := "gap1260-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, row := range gap1260Rows() {
			for _, tool := range []string{"Bash", "shell_command"} {
				args, _ := json.Marshal(map[string]string{"command": row.command})
				request := trustedActionRequest{
					Input:      actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home},
					LegacyText: string(args), Connector: connector,
					EnforcementCapable: true, ResolvedWriteTargets: resolved,
				}
				withWindowsShellDialect(&request, true)
				findings := dispatchTrustedAction(t.Context(), request)
				// The profile maps the limit finding to the unknown tier, as
				// the hook does (guardrailActionForProfile).
				action, ids := operandBoundTierAction(findings, profile == "strict"), findingIDs(findings)
				if want := gap1260Want(row.want, profile); action != want {
					t.Errorf("%s %s %s: action %q %v, want %s", row.id, profile, tool, action, ids, want)
				}
				if rule := gap1260Rule(row.want); rule != "" && !slices.Contains(ids, rule) {
					t.Errorf("%s %s %s: findings %v, want %s", row.id, profile, tool, ids, rule)
				}
			}
		}
	}
}

// TestGAP1260TargetDirectoryHookRoute pins rel-1-0-10:GAP-1260 on the
// Claude Code hook route of a Windows host (a real drive home).
func TestGAP1260TargetDirectoryHookRoute(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the drive-home reading needs a Windows home; TestGAP1260TargetDirectoryUnknownSources reads it on every OS")
	}
	h := newGAP0048Home(t)
	spell := strings.NewReplacer("C:/Users/Alice", filepath.ToSlash(strings.TrimRight(h.home, `\`)))
	for _, profile := range []string{"default", "strict"} {
		judge := newHookConfigJudgeWith(t, "claudecode", profile, false)
		for _, row := range gap1260Rows() {
			got := judge(h.project, false, "Bash", map[string]any{"command": spell.Replace(row.command)})
			action := hookConfigAction(got)
			if action == "deny" {
				action = "block"
			}
			if want := gap1260Want(row.want, profile); action != want {
				t.Errorf("%s %s: %s, want %s", row.id, profile, got, want)
			}
		}
	}
}
