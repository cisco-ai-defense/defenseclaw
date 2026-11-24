// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1138: on Windows a .NET open of an agent hook config or of the
// DefenseClaw state through File.Open or a FileStream constructor with a
// write FileMode or FileAccess, a FileInfo instance open, New-Object
// -TypeName IO.StreamWriter -ArgumentList or a StreamWriter over a stream
// variable was not read as a write by the shared PowerShell write reader
// (GAP-1115), so neither the hook-config guard nor the state proof judged it.
// Each is judged as the redirect is, per-user and behind a managed gateway,
// in the default and the strict pack; a read-only open and every open of a
// project file stay allowed, and a mode or path known only at run time is
// never allowed.
func TestGAP1138DotNetFileOpensCodexAndClaudeCode(t *testing.T) {
	gap1138WindowsRun(t, []string{"codex", "claudecode"}, gap1138Forms, func(pack string) []string {
		if pack == "strict" {
			return []string{"absolute"}
		}
		return []string{"absolute", "$HOME"}
	}, nil)
}

// GAP-1138 through the Devin exec and Antigravity run_command routes.
func TestGAP1138DotNetFileOpensDevinAndAntigravity(t *testing.T) {
	gap1138WindowsRun(t, []string{"devin", "antigravity"}, gap1138Forms, func(pack string) []string {
		if pack == "strict" {
			return nil
		}
		return []string{"absolute"}
	}, nil)
}

// The other spellings of the home and the file (GAP-1138 review notes):
// $env:USERPROFILE, ~ (a cmdlet path only: a .NET argument does not expand
// it) and a path relative to the working directory, for the write cmdlets,
// the redirect and the .NET writes and opens of the shared reader. Behind a
// managed gateway too: the relative state spelling of a .NET write, a
// Get-Item open and New-Item -Value, and the bare ~ of Get-Item, were
// allowed there (rel-1-0-10:GAP-1191: the gateway asked the client map
// without hookpaths.OperandPath, and the client listed no bare ~ word).
func TestGAP1138PowerShellWriteSpellings(t *testing.T) {
	var forms []gap1138Form
	for _, form := range gap1115Forms {
		switch form.id {
		case "redirect", "Add-Content -Path", "Set-Content", "Out-File", "New-Item -Value",
			"Copy-Item -Destination", "File WriteAllText", "StreamWriter new", "Get-Content":
			verdict := "read"
			if form.write {
				verdict = "write"
			}
			forms = append(forms, gap1138Form{form.id, form.text, verdict, slices.Contains([]string{"File WriteAllText", "StreamWriter new"}, form.id)})
		}
	}
	for _, form := range gap1138Forms {
		switch form.id {
		case "File.Open Append", "File.Open Open Read", "New-Object FileStream -ArgumentList", "Get-Item CreateText",
			"New-Object StreamWriter -ArgumentList":
			forms = append(forms, form)
		}
	}
	gap1138WindowsRun(t, []string{"codex", "claudecode"}, forms, func(pack string) []string {
		if pack == "strict" {
			return nil
		}
		return []string{"$env:USERPROFILE", "~", "relative"}
	}, nil)
}

// gap1138WindowsRun judges forms through each connector of conns, for every
// target of gap1138Targets, in each spelling spellings gives for the pack,
// per-user and behind a managed gateway. known, when not nil, names the open
// gap of a cell whose wrong answer is logged, not failed.
func gap1138WindowsRun(t *testing.T, conns []string, forms []gap1138Form, spellings func(pack string) []string,
	known func(peer bool, target gap1138Target, spelling string) string) {
	home, project := gap1138Home(t)
	checked, skipped, open := 0, 0, 0
	for _, pack := range []string{"default", "strict"} {
		if len(spellings(pack)) == 0 {
			continue
		}
		for _, conn := range conns {
			t.Run(pack+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, pack)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = conn
				store, logger := testStoreAndLogger(t)
				handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
				for _, target := range gap1138Targets() {
					abs := filepath.Join(home, target.rel)
					for _, spelling := range spellings(pack) {
						for _, form := range forms {
							word := ""
							switch spelling {
							case "absolute":
								word = "'" + abs + "'"
							case "$HOME":
								word = `"$HOME\` + target.rel + `"`
							case "$env:USERPROFILE":
								word = `"$env:USERPROFILE\` + target.rel + `"`
							case "~":
								if !form.netPath {
									word = `~\` + target.rel
								}
							case "relative":
								if rel, err := filepath.Rel(project, abs); err == nil {
									word = "'" + rel + "'"
								}
							}
							if word == "" {
								skipped++
								continue
							}
							for _, peer := range []bool{false, true} {
								got := gap1138Judge(t, handler, conn, fmt.Sprintf(form.text, word), home, project, peer, false)
								checked++
								problem := gap1138Check(got, form, target, pack)
								if problem == "" {
									continue
								}
								if known != nil {
									if gap := known(peer, target, spelling); gap != "" {
										open++
										t.Logf("known (%s): peer=%v %s %s %s: %s", gap, peer, target.name, spelling, form.id, problem)
										continue
									}
								}
								t.Errorf("peer=%v %s %s %s: %s\n%.600s", peer, target.name, spelling, form.id, problem, got)
							}
						}
					}
				}
			})
		}
	}
	t.Logf("cells checked: %d, spellings that do not apply: %d, wrong cells of an open gap: %d", checked, skipped, open)
}
