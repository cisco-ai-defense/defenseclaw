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

// gap1250Rows are the rel-1-0-10:GAP-1250 rows in the spellings of a
// Windows home: GNU mv, cp with a target directory that names the state
// root (dir), and the file moved or copied into it. block marks a file
// that lands on a state file name (a real overwrite of the detector
// config); the rest name a new file the state rule allows (S23, F03).
func gap1250Rows(dir string) []struct {
	id, command string
	block       bool
} {
	return []struct {
		id, command string
		block       bool
	}{
		{"F01", `mv -t "$HOME\.defenseclaw" config.yaml`, true},
		{"G01", `mv -t "$HOME/.defenseclaw" config.yaml`, true},
		{"G02", `cp -t "$HOME\.defenseclaw" config.yaml`, true},
		{"G08", `mv -t '` + dir + `' config.yaml`, true},
		{"G09", "mv -t " + strings.ReplaceAll(dir, `\`, "/") + " config.yaml", true},
		{"G10", `mv --target-directory="$HOME\.defenseclaw" config.yaml`, true},
		{"G11", `mv -t "` + dir + `" config.yaml`, true},
		{"T01", `mv -f -t"$HOME\.defenseclaw" -- config.yaml`, true},
		{"T02", `cp -at "$HOME\.defenseclaw" notes.txt config.yaml`, true},
		{"S23", `mv -t $HOME\.defenseclaw notes.txt`, false},
		{"F03", `mv -t "$HOME/.defenseclaw" notes.txt`, false},
		{"T03", `mv -t "$HOME\.defenseclaw" notes.txt`, false},
		{"T04", `mv -S config.yaml -t "$HOME\.defenseclaw" notes.txt`, false},
	}
}

// TestGAP1250TargetDirectoryStateWrite pins rel-1-0-10:GAP-1250 on the
// reading the Windows hooks give a Bash or shell_command call of a drive
// home (withWindowsShellDialect), on every OS. Git Bash runs mv -t DIR FILE
// as a move of FILE to DIR/FILE, so a config.yaml moved or copied into the
// state root overwrites the detector config, in every spelling of the
// folder: "$HOME\x", "$HOME/x", 'C:\x', C:/x, "C:\x", --target-directory=,
// an attached value and a cluster. At rel 1d8131d4e8 only the PowerShell
// misreading of -t blocked it (the GAP-1209 false block); 53afe6eefd
// dropped that reading and allowed it. A new file name in the state root
// stays allowed, as a plain move of it is (S23, F03).
func TestGAP1250TargetDirectoryStateWrite(t *testing.T) {
	const home = `C:\Users\Alice`
	resolved := map[string]string{"C:/Users/Alice/.defenseclaw": "C:/Users/Alice/.defenseclaw"}
	for _, name := range []string{"config.yaml", "notes.txt"} {
		value := "C:/Users/Alice/.defenseclaw/" + name
		resolved[value] = value
	}
	for _, profile := range []string{"default", "strict"} {
		connector := "gap1250-" + profile
		installToolCallCorpusProfileConnector(t, connector, profile)
		for _, row := range gap1250Rows(home + `\.defenseclaw`) {
			for _, tool := range []string{"Bash", "shell_command"} {
				args, _ := json.Marshal(map[string]string{"command": row.command})
				request := trustedActionRequest{
					Input:      actionfacts.Input{Tool: tool, Args: args, CWD: home + `\project`, ActiveHome: home},
					LegacyText: string(args), Connector: connector,
					EnforcementCapable: true, ResolvedWriteTargets: resolved,
				}
				withWindowsShellDialect(&request, true)
				findings := dispatchTrustedAction(t.Context(), request)
				verdict := buildVerdict(findings, "tool_call")
				ids := findingIDs(findings)
				// A proven state write blocks in the strict profile and is a HIGH
				// alert in the default one (GAP-0747 owner tiering
				// 2026-11-15T15:20Z).
				wantAction := gap0747WantAction(profile == "strict")
				if row.block && (operandBoundTierAction(findings, profile == "strict") != wantAction || !slices.Contains(ids, "tamper.detector_state_write")) {
					t.Errorf("%s %s %s: action %q %v, want %s by tamper.detector_state_write", row.id, profile, tool, operandBoundTierAction(findings, profile == "strict"), ids, wantAction)
				}
				if !row.block && verdict.Action != "allow" {
					t.Errorf("%s %s %s: action %q %v, want allow", row.id, profile, tool, verdict.Action, ids)
				}
			}
		}
	}
}

// TestGAP1250TargetDirectoryHookRoute pins rel-1-0-10:GAP-1250 on the
// Claude Code hook route of a Windows host, where the home is a drive path:
// a Bash mv or cp -t into the state root of a state file name is the state
// write (a HIGH alert in default, a block in strict), and a new file name stays allowed, as does a
// file moved into the agent settings folder (R17, R18; the GAP-1209 row
// TestAgentHookConfigRenameOverWithoutClientEvidence).
func TestGAP1250TargetDirectoryHookRoute(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("the drive-home reading needs a Windows home; TestGAP1250TargetDirectoryStateWrite reads it on every OS")
	}
	h := newGAP0048Home(t)
	settings := filepath.Dir(h.userSettings)
	rows := gap1250Rows(filepath.Join(h.home, ".defenseclaw"))
	rows = append(rows,
		struct {
			id, command string
			block       bool
		}{"R17", "mv -t " + settings + " notes.txt", false},
		struct {
			id, command string
			block       bool
		}{"R18", `mv -t "` + settings + `" notes.txt`, false},
	)
	for _, profile := range []string{"default", "strict"} {
		judge := newHookConfigJudgeWith(t, "claudecode", profile, false)
		for _, row := range rows {
			got := judge(h.project, false, "Bash", map[string]any{"command": row.command})
			action := hookConfigAction(got)
			// A proven state write blocks in strict and is a HIGH alert in the
			// default profile (GAP-0747 owner tiering 2026-11-15T15:20Z).
			wantAction := gap0747WantAction(profile == "strict")
			gotWant := action == wantAction || wantAction == "block" && action == "deny"
			if row.block && (!gotWant || !strings.Contains(got, "tamper.detector_state_write")) {
				t.Errorf("%s %s: %s, want %s by tamper.detector_state_write", row.id, profile, got, wantAction)
			}
			if !row.block && action != "allow" {
				t.Errorf("%s %s: %s, want allow", row.id, profile, got)
			}
		}
	}
}
