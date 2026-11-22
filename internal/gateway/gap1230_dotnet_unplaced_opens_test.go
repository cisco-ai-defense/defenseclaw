// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap1230Forms are the .NET opens and writes the GAP-1138 reader neither
// placed nor sent to the unknown tier (review s7-g1138rev, rows P01-P16),
// derived from the gap1138Forms rows: a Get-ChildItem or dir result as the
// receiver, a typed FileInfo variable, a method on a [IO.FileInfo]::new(..)
// or New-Object IO.FileInfo result, a pipeline item, File.OpenHandle,
// New-Object -ArgumentList @(..), and the FileInfo Delete and CopyTo writes;
// the controls the reader already read (C01-C03); a System.IO write it does
// not classify (U01); and .NET reads of the same receivers, which stay reads
// (R01-R04).
func gap1230Forms(t *testing.T) []gap1138Form {
	t.Helper()
	form := func(id string) string {
		for _, f := range gap1138Forms {
			if f.id == id {
				return f.text
			}
		}
		t.Fatalf("no gap1138Forms row %q", id)
		return ""
	}
	rep := func(id, old, repl string) string {
		text := form(id)
		if !strings.Contains(text, old) {
			t.Fatalf("%s: %q is not in the row", id, old)
		}
		return strings.Replace(text, old, repl, 1)
	}
	ctor := "[IO.FileInfo]::new(%s)"
	return []gap1138Form{
		{"C01 Get-Item CreateText", form("Get-Item CreateText"), "write", false},
		{"C02 variable path", "$p = %s; " + rep("File.Open Append", "(%s,", "($p,"), "write", true},
		{"C03 gi -LiteralPath variable", "$f = Get-Item -LiteralPath %s; $f.OpenWrite().Close()", "write", false},
		{"P01 Get-ChildItem CreateText", rep("Get-Item CreateText", "(Get-Item ", "(Get-ChildItem "), "unknown", false},
		{"P02 dir CreateText", rep("Get-Item CreateText", "(Get-Item ", "(dir "), "unknown", false},
		{"P03 typed FileInfo variable", rep("FileInfo new OpenWrite", "$f = "+ctor, "[IO.FileInfo]$f = %s"), "unknown", true},
		{"P04 chained constructor OpenWrite", ctor + ".OpenWrite().Close()", "unknown", true},
		{"P05 New-Object group Open", rep("New-Object FileInfo Open Append", "$f = New-Object System.IO.FileInfo(%s); $s = $f.Open(", "$s = (New-Object System.IO.FileInfo(%s)).Open("), "unknown", true},
		{"P06 pipeline item", "Get-Item %s | ForEach-Object { $_.CreateText().Close() }", "unknown", false},
		{"P07 File.OpenHandle", rep("File.OpenWrite", "OpenWrite(%s)", "OpenHandle(%s, 'Append', 'Write')"), "unknown", true},
		{"P08 -ArgumentList array", rep("New-Object FileStream -ArgumentList", "-ArgumentList %s, 'Append'", "-ArgumentList @(%s, 'Append')"), "unknown", true},
		{"P11 Get-ChildItem variable OpenWrite", "$f = Get-ChildItem %s; $f.OpenWrite().Close()", "unknown", false},
		{"P13 FileInfo Delete", "(Get-Item %s).Delete()", "unknown", false},
		{"P14 FileInfo CopyTo onto", "(Get-Item 'notes.txt').CopyTo(%s, $true) | Out-Null", "unknown", true},
		{"P15 full type chained", "[System.IO.FileInfo]::new(%s).AppendText().Close()", "unknown", true},
		{"P16 OpenHandle then FileStream", "$h = [IO.File]::OpenHandle(%s, 'OpenOrCreate', 'Write'); $s = [IO.FileStream]::new($h, 'Write'); $s.Close()", "unknown", true},
		{"U01 unclassified System.IO write", rep("File.OpenWrite", "OpenWrite(%s).Close()", "WriteAllTextAsync(%s, 'zz').Wait()"), "unknown", true},
		{"R01 Get-ChildItem OpenRead", rep("Get-Item OpenRead", "(Get-Item ", "(Get-ChildItem "), "read", false},
		{"R02 chained constructor OpenText", ctor + ".OpenText().Close()", "read", true},
		{"R03 OpenHandle default read", rep("File.OpenWrite", "OpenWrite(%s)", "OpenHandle(%s)"), "read", true},
		{"R04 System.IO read", rep("File.OpenRead", "OpenRead(%s).Close()", "ReadAllLines(%s) | Out-Null"), "read", true},
	}
}

// GAP-1230: each gap1230Forms row of an agent hook config or the DefenseClaw
// state is the write rule of the file or the unknown tier of the pack, never
// allowed, per-user and behind a managed gateway, in default/claudecode,
// default/codex and strict/codex: through the pwsh -Command launcher route on
// Linux and macOS (also with the home closed to the managed gateway) and
// natively on Windows. Every row of a project file stays allowed, and the
// read rows raise no protected-write rule.
func TestGAP1230UnplacedDotNetOpens(t *testing.T) {
	home, project := gap1138Home(t)
	forms := gap1230Forms(t)
	checked := 0
	for _, pack := range []string{"default", "strict"} {
		for _, conn := range []string{"claudecode", "codex"} {
			if pack == "strict" && conn != "codex" {
				continue
			}
			t.Run(pack+"/"+conn, func(t *testing.T) {
				installToolCallCorpusProfileConnector(t, conn, pack)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = conn
				store, logger := testStoreAndLogger(t)
				handler := (&APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}).handleAgentHook(conn)
				for _, form := range forms {
					for _, target := range gap1138Targets() {
						abs := filepath.Join(home, target.rel)
						command := fmt.Sprintf(form.text, "'"+abs+"'")
						if runtime.GOOS != "windows" {
							// The script is single-quoted for the POSIX shell; its
							// own strings are double-quoted.
							script := strings.ReplaceAll(fmt.Sprintf(form.text, `"`+abs+`"`), "'", `"`)
							command = "pwsh -NoProfile -Command '" + script + "'"
						}
						for _, peer := range []bool{false, true} {
							got := gap1138Judge(t, handler, conn, command, home, project, peer, runtime.GOOS != "windows")
							checked++
							if problem := gap1138Check(got, form, target, pack); problem != "" {
								t.Errorf("peer=%v %s %s: %s\n%.600s", peer, target.name, form.id, problem, got)
							}
						}
					}
				}
			})
		}
	}
	t.Logf("cells checked: %d", checked)
}
