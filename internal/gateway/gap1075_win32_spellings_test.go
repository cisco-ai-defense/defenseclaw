// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap1075Spelling is a Win32 spelling of the file dir\name: Win32 opens the
// file itself for every one of them. dir is "" for a target that names the
// file from its own folder (a bare or drive-relative name).
type gap1075Spelling struct {
	id string
	// last spells the last name; folder spells the folder name (nil: the
	// spelling needs a folder and is skipped for a target without one).
	last   func(name string) string
	folder func(dir string) string
	// normalized: Win32 normalizes the spelling (dots, spaces), which it
	// does not for the exact extended-length prefix.
	normalized bool
}

func gap1075Suffix(id, suffix string, normalized bool) gap1075Spelling {
	return gap1075Spelling{id: id, last: func(name string) string { return name + suffix }, normalized: normalized}
}

func gap1075Folder(id, suffix string, normalized bool) gap1075Spelling {
	return gap1075Spelling{id: id, folder: func(dir string) string { return dir + suffix }, normalized: normalized}
}

// gap1075Spellings: the default data stream in any case, with the trailing
// dots and spaces Win32 strips after it, the empty stream name, the trailing
// dots and spaces alone, and the index alias of the folder (rel-1-0-10:
// GAP-1060, GAP-1075; cmd ground truth on Windows: each replaces the file).
var gap1075Spellings = []gap1075Spelling{
	gap1075Suffix("dsU", "::$DATA", false), gap1075Suffix("dsL", "::$data", false),
	gap1075Suffix("dsMixed", "::$DaTa", false),
	gap1075Suffix("dsDot", "::$DATA.", false), gap1075Suffix("dsSpace", "::$DATA ", false),
	gap1075Suffix("dsDotSpace", "::$data . ", false),
	gap1075Suffix("colon", ":", true), gap1075Suffix("colonDot", ":.", true),
	gap1075Suffix("colonSpace", ": ", true),
	gap1075Suffix("dot", ".", true), gap1075Suffix("dots", "..", true),
	gap1075Suffix("space", " ", true), gap1075Suffix("dotSpace", ". ", true),
	gap1075Folder("dirIdx", "::$INDEX_ALLOCATION", false),
	gap1075Folder("dirIdxL", "::$index_allocation", false),
	gap1075Folder("dirI30", ":$I30:$INDEX_ALLOCATION", false),
	gap1075Folder("dirDot", ".", true),
}

// gap1075Routes are the Windows write routes that turn operand text into a
// path fact: PowerShell redirection, the PowerShell content and item
// cmdlets, and cmd (redirection and the file commands), plus the read routes
// for the private key.
var gap1075Routes = []struct {
	id, text string
	read     bool
}{
	{"gt", "echo x > '%s'", false}, {"gtgt", "echo x >> '%s'", false}, {"tee", "echo x | tee '%s'", false},
	{"setc", "Set-Content -Path '%s' -Value x", false}, {"setcLit", "Set-Content -LiteralPath '%s' -Value x", false},
	{"addc", "Add-Content '%s' x", false}, {"outf", "Out-File -FilePath '%s' -InputObject x", false},
	{"teeObj", "'x' | Tee-Object -FilePath '%s'", false}, {"clc", "Clear-Content '%s'", false},
	{"copy", "Copy-Item notes.txt '%s'", false}, {"move", "Move-Item notes.txt '%s'", false},
	{"rm", "Remove-Item '%s'", false},
	{"cmdGt", `cmd /c "echo x> "%s""`, false}, {"cmdGtgt", `cmd /c "echo x>> "%s""`, false},
	{"cmdCopy", `cmd /c copy /y notes.txt "%s"`, false}, {"cmdMove", `cmd.exe /c move /y notes.txt "%s"`, false},
	{"cmdDel", `cmd /c del /f "%s"`, false},
	{"read", "Get-Content '%s'", true}, {"cmdRead", `cmd /c type "%s"`, true},
}

// TestGAP1075Win32SpellingsOfThePlainFile: on the PowerShell tool, every
// Win32 spelling that opens the DefenseClaw config (or the private key) gets
// the verdict of the plain spelling, on every write route (PowerShell
// redirection and cmdlets, cmd) and read route, in the default, permissive
// and strict packs (rel-1-0-10:GAP-1075, the class of GAP-1060). The
// PowerShell and cmd readings took the "::" of a stream for a provider
// qualifier and rejected the trailing dots and spaces Win32 strips, so they
// minted no path fact and the call allowed in every tier. The same spellings
// of an ordinary project file keep its verdict.
func TestGAP1075Win32SpellingsOfThePlainFile(t *testing.T) {
	const home = `C:\Users\Alice`
	project := home + `\project`
	cfgDir := home + `\.defenseclaw`
	keyDir := home + `\.ssh`
	type target struct {
		id, dir, sep, name, cwd string
		read                    bool
		extended                bool
	}
	targets := []target{
		{id: "cfgBack", dir: cfgDir, sep: `\`, name: "config.yaml", cwd: project},
		{id: "cfgFwd", dir: strings.ReplaceAll(cfgDir, `\`, "/"), sep: "/", name: "config.yaml", cwd: project},
		{id: "cfgRel", dir: `..\.defenseclaw`, sep: `\`, name: "config.yaml", cwd: project},
		{id: "cfgProv", dir: `Microsoft.PowerShell.Core\FileSystem::` + cfgDir, sep: `\`, name: "config.yaml", cwd: project},
		{id: "cfgDevice", dir: `\\.\` + cfgDir, sep: `\`, name: "config.yaml", cwd: project},
		{id: "cfgExt", dir: `\\?\` + cfgDir, sep: `\`, name: "config.yaml", cwd: project, extended: true},
		{id: "cfgBare", name: "config.yaml", cwd: cfgDir},
		{id: "cfgDriveRel", name: home[:2] + "config.yaml", cwd: cfgDir},
		{id: "keyBack", dir: keyDir, sep: `\`, name: "id_ed25519", cwd: project, read: true},
	}
	spell := func(tg target, sp gap1075Spelling) (string, bool) {
		if tg.extended && sp.normalized {
			return "", false // \\?\ is not normalized: another file
		}
		switch {
		case sp.last != nil:
			if tg.dir == "" {
				return sp.last(tg.name), true
			}
			return tg.dir + tg.sep + sp.last(tg.name), true
		case tg.dir != "":
			return sp.folder(tg.dir) + tg.sep + tg.name, true
		}
		return "", false
	}
	cells := 0
	for _, posture := range []string{"default", "permissive", "strict"} {
		connectorName := "gap1075-" + posture
		installToolCallCorpusProfileConnector(t, connectorName, posture)
		decide := func(command, cwd string) (string, []string) {
			args, _ := json.Marshal(map[string]string{"command": command})
			input := actionfacts.Input{Tool: "PowerShell", Args: args, CWD: cwd, ActiveHome: home}
			input.DialectHint = agentHookWindowsShellDialect(input)
			findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
				Input: input, LegacyText: string(args), Connector: connectorName, EnforcementCapable: true,
			})
			return buildVerdict(findings, "tool_call").Action, findingIDs(findings)
		}
		for _, route := range gap1075Routes {
			for _, tg := range targets {
				if route.read != tg.read {
					continue
				}
				plainText := tg.name
				if tg.dir != "" {
					plainText = tg.dir + tg.sep + tg.name
				}
				want, ids := decide(fmt.Sprintf(route.text, plainText), tg.cwd)
				if want == "allow" {
					t.Fatalf("%s/%s|%s: the plain spelling allows %v", posture, route.id, tg.id, ids)
				}
				for _, sp := range gap1075Spellings {
					text, ok := spell(tg, sp)
					if !ok {
						continue
					}
					cells++
					if got, ids := decide(fmt.Sprintf(route.text, text), tg.cwd); got != want {
						t.Errorf("%s/%s|%s|%s: action %s %v, want %s as the plain spelling", posture, route.id, tg.id, sp.id, got, ids, want)
					}
				}
			}
			if route.read {
				continue
			}
			benign := target{id: "benign", dir: project, sep: `\`, name: "out.txt", cwd: project}
			want, _ := decide(fmt.Sprintf(route.text, project+`\out.txt`), project)
			for _, sp := range gap1075Spellings {
				text, _ := spell(benign, sp)
				if got, ids := decide(fmt.Sprintf(route.text, text), project); got == "block" && want != "block" {
					t.Errorf("%s/%s|benign|%s: block %v, the plain project file %s", posture, route.id, sp.id, ids, want)
				}
			}
		}
	}
	t.Logf("GAP1075 Win32 spelling cells checked: %d", cells)
}
