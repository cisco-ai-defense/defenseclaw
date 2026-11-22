// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// gap1257Row is a review row of the GAP-1230 reader (s7-g1230rev P17-P20);
// dir opens the folder of the target, not the target.
type gap1257Row struct {
	form gap1138Form
	dir  bool
}

// gap1257Rows: a FileInfo write on a Get-ChildItem result of the folder that
// holds a protected file (member enumeration runs it on every child), the
// same through a variable, a FileInfo variable re-bound in a script block,
// and a typed variable of a variable.
func gap1257Rows() []gap1257Row {
	return []gap1257Row{
		{gap1138Form{"P17 gci directory CreateText", "(Get-ChildItem %s).CreateText() | ForEach-Object { $_.Close() }", "unknown", false}, true},
		{gap1138Form{"P18 gci directory variable Delete", "$f = Get-ChildItem %s; $f.Delete()", "unknown", false}, true},
		{gap1138Form{"P19 re-bound FileInfo variable", "$f = Get-Item 'notes.txt'; Get-Item %s | ForEach-Object { $f = $_ }; $f.OpenWrite().Close()", "unknown", false}, false},
		{gap1138Form{"P20 typed variable of a variable", "$p = %s; [IO.FileInfo]$f = $p; $f.OpenWrite().Close()", "unknown", false}, false},
	}
}

// gap1257Benign are ordinary project .NET reads and writes, and reads of a
// hook config next to project writes (s7-g1230rev B01-B20): allowed in every
// pack, per-user and behind a managed gateway (rel-1-0-10:GAP-1258).
var gap1257Benign = []struct{ id, text string }{
	{"B01 pipeline Delete logs", "Get-ChildItem *.log | ForEach-Object { $_.Delete() }"},
	{"B02 recurse filter Delete", "Get-ChildItem -Recurse -Filter *.tmp | ForEach-Object { $_.Delete() }"},
	{"B03 foreach CopyTo", "$files = Get-ChildItem 'src'; foreach ($f in $files) { $f.CopyTo('bin/' + $f.Name, $true) | Out-Null }"},
	{"B04 pipeline MoveTo", "Get-ChildItem 'bin' | ForEach-Object { $_.MoveTo('obj/' + $_.Name) }"},
	{"B05 File.SetLastWriteTime", "[IO.File]::SetLastWriteTime('out.txt', [DateTime]::Now)"},
	{"B06 Directory.CreateDirectory", "[IO.Directory]::CreateDirectory('build') | Out-Null"},
	{"B07 ZipFile.ExtractToDirectory", "Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::ExtractToDirectory('pkg.zip', 'out')"},
	{"B08 pipeline Open read", "Get-ChildItem 'notes.txt' | ForEach-Object { $s = $_.Open('Open', 'Read'); $s.Close() }"},
	{"B09 pipeline OpenText", "Get-ChildItem 'src' -Recurse | ForEach-Object { $r = $_.OpenText(); $r.ReadToEnd() | Out-Null; $r.Close() }"},
	{"B10 hash OpenRead", "$sha = [Security.Cryptography.SHA256]::Create(); Get-ChildItem 'src' | ForEach-Object { $s = $_.OpenRead(); $sha.ComputeHash($s) | Out-Null; $s.Close() }"},
	{"B11 System.IO reads", "[IO.File]::ReadAllText('notes.txt') | Out-Null; [IO.Directory]::GetFiles('.') | Out-Null; [IO.File]::Exists('out.txt')"},
	{"B12 StreamWriter project", "$w = [IO.StreamWriter]::new('out.txt'); $w.WriteLine('x'); $w.Close()"},
	{"B13 read hook config + delete logs", "$cfg = Get-Content ~/.claude/settings.json -Raw; Get-ChildItem *.log | ForEach-Object { $_.Delete() }"},
	{"B14 hook config pipeline OpenText", "Get-Item ~/.claude/settings.json | ForEach-Object { $r = $_.OpenText(); $r.ReadToEnd() | Out-Null; $r.Close() }"},
	{"B15 hook config pipeline Open read", "Get-Item ~/.claude/settings.json | ForEach-Object { $s = $_.Open('Open', 'Read'); $s.Close() }"},
	{"B16 codex sessions cleanup", "Get-ChildItem ~/.codex/sessions -Recurse -Filter *.jsonl | ForEach-Object { $_.Delete() }"},
	{"B17 typed FileInfo project", "[IO.FileInfo]$f = 'out.txt'; $f.AppendText().Close()"},
	{"B18 gci chained CopyTo", "(Get-ChildItem 'out.txt').CopyTo('out.bak', $true) | Out-Null"},
	{"B19 Stream.CopyTo", "$a = [IO.File]::OpenRead('notes.txt'); $b = [IO.File]::Create('out.txt'); $a.CopyTo($b); $a.Close(); $b.Close()"},
	{"B20 String.Replace", "$t = (Get-Content 'notes.txt' -Raw).Replace('a', 'b'); Set-Content 'out.txt' $t"},
}

// gap1257Handlers runs judge in default/claudecode, default/codex and
// strict/codex with the corpus profile of the pack installed.
func gap1257Handlers(t *testing.T, judge func(t *testing.T, pack, conn string, handler func(command string, peer bool) string)) {
	t.Helper()
	home, project := gap1138Home(t)
	gap1257Fixtures(t, home, project)
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
				judge(t, pack, conn, func(command string, peer bool) string {
					return gap1138Judge(t, handler, conn, command, home, project, peer, runtime.GOOS != "windows")
				})
			})
		}
	}
}

// gap1257Fixtures makes the project files the benign rows read and write.
func gap1257Fixtures(t *testing.T, home, project string) {
	t.Helper()
	for _, name := range []string{
		filepath.Join(project, "a.log"), filepath.Join(project, "b.tmp"), filepath.Join(project, "src", "a.cs"),
		filepath.Join(project, "bin", "x.dll"), filepath.Join(home, ".codex", "sessions", "s.jsonl"),
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// gap1257Command is text as the shell tool runs it: natively on Windows,
// else in a pwsh -Command launcher (single-quoted for the POSIX shell, its
// own strings double-quoted).
func gap1257Command(text string) string {
	if runtime.GOOS == "windows" {
		return text
	}
	return "pwsh -NoProfile -Command '" + strings.ReplaceAll(text, "'", `"`) + "'"
}

// GAP-1257: each gap1257Rows row of an agent hook config or the DefenseClaw
// state (or of the folder holding it) is the write rule of the file or the
// unknown tier of the pack, never allowed, per-user and behind a managed
// gateway, in default/claudecode, default/codex and strict/codex: through the
// pwsh -Command launcher on Linux and macOS and natively on Windows. Every
// row of a project file stays allowed.
func TestGAP1257FileInfoChildAndRebound(t *testing.T) {
	checked := 0
	gap1257Handlers(t, func(t *testing.T, pack, conn string, judge func(string, bool) string) {
		home := os.Getenv("HOME")
		for _, row := range gap1257Rows() {
			for _, target := range gap1138Targets() {
				abs := filepath.Join(home, target.rel)
				if row.dir {
					abs = filepath.Dir(abs)
				}
				command := gap1257Command(fmt.Sprintf(row.form.text, "'"+abs+"'"))
				for _, peer := range []bool{false, true} {
					got := judge(command, peer)
					checked++
					if problem := gap1138Check(got, row.form, target, pack); problem != "" {
						t.Errorf("peer=%v %s %s: %s\n%.600s", peer, target.name, row.form.id, problem, got)
					}
				}
			}
		}
	})
	t.Logf("cells checked: %d", checked)
}

// GAP-1258: every gap1257Benign row is allowed with no protected-write rule
// and no unknown tier, in every pack, per-user and behind a managed gateway.
func TestGAP1258BenignDotNetRows(t *testing.T) {
	rules := []string{agentHookConfigWriteRuleID, agentHookConfigDisableRuleID, "tamper.detector_state_write", evaluationLimitRuleID}
	gap1257Handlers(t, func(t *testing.T, pack, conn string, judge func(string, bool) string) {
		for _, row := range gap1257Benign {
			for _, peer := range []bool{false, true} {
				got := judge(gap1257Command(row.text), peer)
				action := hookConfigAction(got)
				for _, rule := range rules {
					if strings.Contains(got, rule) {
						action += " " + rule
					}
				}
				if action != "allow" {
					t.Errorf("peer=%v %s: %s, want allow\n%.600s", peer, row.id, action, got)
				}
			}
		}
	})
}
