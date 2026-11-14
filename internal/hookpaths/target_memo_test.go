// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestTargetMemoWalkAnswersAsAFreshWalk is the exactness proof of the memo
// walk (rel-1-0-2:GAP-0568): resolved through one shared memo, in any order,
// every path answers what a fresh ResolveWriteTarget answers, through
// directory and file links, link chains, a dangling link, a link loop, ".."
// after a link and after a missing component.
func TestTargetMemoWalkAnswersAsAFreshWalk(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "a", "b", "c"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "a", "b", "c", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		"la":  "a",
		"lb":  filepath.Join(root, "a", "b"),
		"l1":  "l2",
		"l2":  "l3",
		"l3":  filepath.Join("a", "b", "c"),
		"lf":  filepath.Join("a", "b", "c", "f"),
		"ld":  filepath.Join("missing", "x"),
		"lo1": "lo2",
		"lo2": "lo1",
		"lu":  filepath.Join("a", "b", ".."),
	} {
		if err := os.Symlink(target, filepath.Join(root, link)); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
	}
	var paths []string
	for _, rel := range []string{
		"a/b/c/f", "a/b/c/new", "la/b/c/f", "la/../a/b", "lb/c/f", "lb/../b/c", "l1/f", "l1/../c",
		"lf", "ld", "ld/../y", "lo1", "lo1/x", "lu/b/c", "missing/../a", "missing/new",
		"a/./b//c/", "a/b/c/f/../f", "la/b/../../la/b", ".", "",
	} {
		paths = append(paths, filepath.Join(root, filepath.FromSlash(rel)))
	}
	// The raw spelling (no Clean) keeps "..", "." and empty components.
	paths = append(paths, root+string(filepath.Separator)+"la"+string(filepath.Separator)+".."+string(filepath.Separator)+"a",
		root+string(filepath.Separator)+"missing"+string(filepath.Separator)+".."+string(filepath.Separator)+"a",
		root+string(filepath.Separator)+"."+string(filepath.Separator)+"a"+string(filepath.Separator)+string(filepath.Separator)+"b")
	type answer struct {
		resolved string
		ok       bool
	}
	want := make(map[string]answer, len(paths))
	for _, path := range paths {
		resolved, ok := ResolveWriteTarget(path)
		want[path] = answer{resolved, ok}
	}
	orders := [][]string{paths, reversed(paths)}
	shuffled := append([]string(nil), paths...)
	random := rand.New(rand.NewPCG(568, 2026))
	random.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	orders = append(orders, shuffled)
	for round, order := range orders {
		memo := NewTargetMemo()
		for pass := 0; pass < 2; pass++ {
			for _, path := range order {
				resolved, ok := memo.resolveWriteTarget(path)
				if got := (answer{resolved, ok}); got != want[path] {
					t.Errorf("order %d pass %d: %s answered %+v through the memo, %+v fresh", round, pass, path, got, want[path])
				}
			}
		}
	}
}

func reversed(values []string) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[len(values)-1-i] = value
	}
	return out
}

// gap0568Assignments is a0=1; a1=1; ... a<n-1>=1, the benign form that
// missed the Windows hook window (rel-1-0-2:GAP-0568).
func gap0568Assignments(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("a%d=1", i)
	}
	return strings.Join(parts, "; ")
}

// gap0568Evaluation reads command as the gateway's evaluation does: the
// state scan and both target decisions on the whole call, then again on
// each statement alone (the simple-command passes), all with one memo. It
// returns the memo's file system work.
func gap0568Evaluation(t *testing.T, command, cwd, home string) int {
	t.Helper()
	memo := NewTargetMemo()
	read := func(text string) {
		if memo.ActionStateTargetMention(text, cwd, home) {
			t.Fatalf("%.60q named active state", text)
		}
		if memo.ActionCommandDecisionWithDialectAndGlobFacts(text, cwd, home, actionfacts.DialectPOSIX, nil) != "" ||
			memo.ActionCommandDecisionInShell(text, cwd, home, nil, true) != "" {
			t.Fatalf("%.60q named a protected target", text)
		}
	}
	read(command)
	for _, statement := range strings.Split(command, "; ") {
		read(statement)
	}
	return memo.Work()
}

// TestTargetMemoAssignmentChainWorkIsLinear pins rel-1-0-2:GAP-0568 with a
// work counter, not a clock: an evaluation of a chain of n assignments, the
// whole call and each statement alone, walks each distinct path prefix and
// checks each distinct candidate once, so its work grows linearly in n
// with a small constant. Before the memo every reading and every
// statement pass walked the working directory and the home again for each
// word: on Windows about 70,000 file system calls for 100 statements.
// Both a Windows home read by its spelling and this host's own temporary
// home (the file system walk) are measured.
func TestTargetMemoAssignmentChainWorkIsLinear(t *testing.T) {
	native := t.TempDir()
	if err := os.MkdirAll(filepath.Join(native, "project"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, place := range []struct{ name, home, cwd string }{
		{"windows-spelled", `C:\Users\Alice`, `C:\Users\Alice\project`},
		{"native", native, filepath.Join(native, "project")},
	} {
		t.Run(place.name, func(t *testing.T) {
			work := map[int]int{}
			for _, n := range []int{32, 64, 128} {
				work[n] = gap0568Evaluation(t, gap0568Assignments(n), place.cwd, place.home)
			}
			t.Logf("work: n=32 %d, n=64 %d, n=128 %d", work[32], work[64], work[128])
			if first, second := work[64]-work[32], work[128]-work[64]; second > 2*first+16 {
				t.Errorf("work grew faster than linear: +%d for 32 more statements, then +%d for 64 more", first, second)
			}
			if limit := 8*128 + 256; work[128] > limit {
				t.Errorf("128 statements cost %d units of work, want at most %d (each distinct path and candidate once)", work[128], limit)
			}
		})
	}
}

// TestClientStatementBudgetHeader pins the hook client's side of the
// statement budget (rel-1-0-2:GAP-0568): a POSIX call over 128 statements
// gets only the incomplete-evidence header (truncated marker and cwd), one
// at the budget gets the full map, and an over-budget call that names the
// DefenseClaw state folder is still described in full, so a gateway behind
// ProtectHome can prove the state write that observe mode blocks.
// TestPowerShellStateReadingHoldsOnlyAPossibleStateWrite is
// rel-1-0-6:GAP-0448 (review r6 findings 1 and 2): an over-budget
// PowerShell call is held only when a segment that names the state folder
// may write; reading, testing or printing it, or a defense or claw word,
// keeps nothing. A helper whose body only prints keeps its POSIX call
// reducible. Also review r6 mutation MC1: the client reads a PowerShell
// parse as PowerShell whatever the tool.
func TestPowerShellStateReadingHoldsOnlyAPossibleStateWrite(t *testing.T) {
	lines := func(n int, form string) string {
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprintf(form, i)
		}
		return strings.Join(parts, "\n")
	}
	st := "~/.defenseclaw/config.yaml"
	wh := lines(200, "Write-Host 'step %d'")
	for _, call := range []string{
		wh + "\nGet-Content " + st,
		"Get-Content $HOME/.defenseclaw/config.yaml\n" + wh,
		wh + "\nTest-Path " + st,
		wh + "\ndefenseclaw status",
		"Set-Location ~/src/defenseclaw\n" + lines(200, "Write-Output %d"),
		lines(200, "Write-Output 'defense %d'"),
		wh + "\n$l = & git -C ~/src/defenseclaw log -1",
		wh + "\n$c = Get-Content " + st + " 2>$null",
	} {
		if reduced, overflow, ok := StateNamingReading(call, "/home/u", true); !ok || overflow || reduced != "" {
			t.Errorf("%.50q: ok %t overflow %t reduced %.30q, want nothing kept", call[max(0, len(call)-50):], ok, overflow, reduced)
		}
	}
	for _, call := range []string{
		wh + "\nSet-Content -Path " + st + " -Value x",
		wh + "\nRemove-Item " + st,
		wh + "\n'x' | Out-File ~\\.defenseclaw\\config.yaml",
		wh + "\nGet-Content " + st + " > " + st + ".bak",
		wh + "\nGet-Content (Set-Content " + st + " x)",
		wh + "\n$p = '~/.defense' + 'claw/config.yaml'; Set-Content $p x",
		wh + `; echo "claw\"; Set-Content -Path ` + st + ` -Value x; \""`,
		wh + "\nSet-Content ~/.defense?law/config.yaml x",
		wh + "\nSet-Content ~/.d*claw/config.yaml x",
		wh + "\nsc " + st + " x",
	} {
		if _, overflow, ok := StateNamingReading(call, "/home/u", true); !ok || !overflow {
			t.Errorf("%.50q: ok %t overflow %t, want the call held", call[max(0, len(call)-50):], ok, overflow)
		}
	}
	pad := gap0568Assignments(200)
	if _, overflow, _ := StateNamingStatements(`log() { echo "$@"; }; `+pad+`; log "checking defenseclaw status"`, "/home/u"); overflow {
		t.Error("a call of a print-only helper made an overflow")
	}
	if _, overflow, _ := StateNamingStatements(`f() { printf c >> "$1"; }; `+pad+"; f "+st, "/home/u"); !overflow {
		t.Error("a call of a writing helper did not make an overflow")
	}
	for _, tool := range []string{"exec_command", "Bash", "shell"} {
		if !clientPowerShellReading("codex", tool, actionfacts.Facts{Parse: actionfacts.ParseResult{Dialect: actionfacts.DialectPowerShell}}) {
			t.Errorf("%s with a PowerShell parse: not read as PowerShell", tool)
		}
		if clientPowerShellReading("claudecode", tool, actionfacts.Facts{Parse: actionfacts.ParseResult{Dialect: actionfacts.DialectPOSIX}}) {
			t.Errorf("%s with a POSIX parse: read as PowerShell", tool)
		}
	}
}

func TestClientStatementBudgetHeader(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	header := func(command string) map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "budget", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(body))
		if !ok {
			t.Fatalf("%.40q: header does not decode", command)
		}
		return targets
	}
	incomplete := func(targets map[string]string) bool {
		if targets[TruncatedKey] != "1" {
			return false
		}
		for key := range targets {
			if key != TruncatedKey && key != CWDKey {
				return false
			}
		}
		return true
	}
	// Review r5 mutation MW1: an over-budget call whose naming statements
	// only read sends the incomplete marker, not a description of an empty
	// reduced call.
	if got := header(gap0568Assignments(200) + strings.Repeat("; cat ~/.defenseclaw/config.yaml 2>/dev/null", 130)); !incomplete(got) {
		t.Errorf("read-only over-budget call: header %v, want only the incomplete marker and cwd", got)
	}
	// rel-1-0-6:GAP-0413: a PowerShell-tool call is not reduced by the
	// POSIX read-only proof; over the budget the client sends only the
	// incomplete marker, even where the POSIX reading would keep a writer.
	psPad := make([]string, 0, 330)
	for i := range 200 {
		psPad = append(psPad, fmt.Sprintf("$a%d=1", i))
	}
	for i := range 130 {
		psPad = append(psPad, fmt.Sprintf(`echo "claw%d"`, i))
	}
	psBody, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "budget", "cwd": cwd,
		"tool_name": "PowerShell", "tool_input": map[string]any{"command": strings.Join(psPad, "; ") + "; Set-Content -Path ~/.defenseclaw/config.yaml -Value x"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := Decode(Resolve(psBody)); !ok || !incomplete(got) {
		t.Errorf("PowerShell-tool over-budget state write: header %v, want only the incomplete marker and cwd", got)
	}
	if got := header(gap0568Assignments(129)); !incomplete(got) {
		t.Errorf("129 assignments: header %v, want only the incomplete marker and cwd", got)
	}
	if got := header(gap0568Assignments(128)); incomplete(got) || got[TruncatedKey] != "" {
		t.Errorf("128 assignments: header %v, want the full map", got)
	}
	state := filepath.Join(home, ".defenseclaw", "config.yaml")
	// The path is single-quoted in the shell command: a Windows path is
	// written with backslashes, which an unquoted Bash word reads as
	// escapes (rel-1-0-6:GAP-0440). The header still names the path itself.
	stateWord := "'" + state + "'"
	got := header(gap0568Assignments(200) + "; printf changed >> " + stateWord)
	if incomplete(got) {
		t.Fatalf("over-budget state write: header %v, want the call described", got)
	}
	if _, listed := got[state]; !listed {
		t.Errorf("over-budget state write: header %v does not list %s", got, state)
	}
	// Review r3 mutation MC: the header is built from the reduced call, so
	// the padding's own write targets (past the 64 KiB analysis bound, so
	// no path fact lists them) are not described. The call is also past the
	// reading budget of shellparse (parsed nodes), which no reader parses:
	// its map is the reduced reading of BudgetStateReading, the state listed
	// and the truncated marker (TestClientHeaderOfAnOverBudgetCall...).
	var writes []string
	for i := range 30000 {
		writes = append(writes, fmt.Sprintf("echo x > ordinary/f%d.txt", i))
	}
	reducedHeader := header(strings.Join(writes, "; ") + "; printf changed >> " + stateWord)
	if _, listed := reducedHeader[state]; !listed || reducedHeader[TruncatedKey] != "1" {
		t.Errorf("over-budget state write after 30000 writes: header %v, want the state listed and the truncated marker", reducedHeader)
	}
	for key := range reducedHeader {
		if strings.Contains(key, "ordinary/f") {
			t.Errorf("header lists the padding target %s: the full call was described, not its reduced reading", key)
			break
		}
	}
	// Past the bound of statements that may write, the client sends only
	// the incomplete header; read-only statements past it are dropped and
	// the state write is still described (review r4 finding 2).
	var writers, reads []string
	for i := range StateNamingStatementsMax + 2 {
		writers = append(writers, fmt.Sprintf("echo claw%d >> notes.txt", i))
		reads = append(reads, fmt.Sprintf("echo claw%d", i))
	}
	if got := header(gap0568Assignments(200) + "; " + strings.Join(writers, "; ") + "; printf changed >> " + stateWord); !incomplete(got) {
		t.Errorf("over-budget call past the bound of writing statements: header %v, want only the incomplete marker and cwd", got)
	}
	if got := header(gap0568Assignments(200) + "; " + strings.Join(reads, "; ") + "; printf changed >> " + stateWord); incomplete(got) {
		t.Errorf("over-budget state write after 130 read-only naming statements: header %v, want the write described", got)
	} else if _, listed := got[state]; !listed {
		t.Errorf("over-budget state write after 130 read-only naming statements: header %v does not list %s", got, state)
	}
	// Review R2-2: the state name with a quote inside it is still described.
	quoted := header(gap0568Assignments(200) + "; printf changed >> ~/.defense''claw/config.yaml")
	if incomplete(quoted) {
		t.Errorf("over-budget quote-split state write: header %v, want the call described", quoted)
	}
}

// TestClientStateStatementsAreBounded is review R2-5 of rel-1-0-2:GAP-0568:
// an over-budget call that may name the state is described only through
// its statements that may name it and the directory changes that place
// them, at most StateNamingStatementsMax, so padding the call cannot push
// the description past the hook window.
func TestClientStateStatementsAreBounded(t *testing.T) {
	padding := make([]string, 3000)
	for i := range padding {
		padding[i] = fmt.Sprintf("echo claw%d", i)
	}
	// Only prints and reads name the state: nothing can write it, so
	// nothing is kept or described (a 130-read call took 3.0-3.5 s on
	// dc-win2 when its reads filled the bound).
	for _, call := range []string{
		gap0568Assignments(500) + "; cd sub; " + strings.Join(padding, "; "),
		gap0568Assignments(200) + strings.Repeat("; cat ~/.defenseclaw/config.yaml 2>/dev/null", 130),
	} {
		if reduced, overflow, ok := StateNamingStatements(call, "/home/u"); !ok || overflow || reduced != "" {
			t.Errorf("read-only call: ok %t overflow %t reduced %.60q, want ok, no overflow and nothing kept", ok, overflow, reduced)
		}
	}
	state := "printf c >> ~/.defenseclaw/config.yaml"
	reduced, overflow, ok := StateNamingStatements(gap0568Assignments(500)+"; cd sub; "+strings.Join(padding, "; ")+"; "+state, "/home/u")
	if !ok || overflow {
		t.Fatalf("POSIX call: ok %t overflow %t, want ok and no overflow (the dropped statements only print)", ok, overflow)
	}
	// Reads are never kept: only the directory change and the write.
	if want := "cd sub; " + state; reduced != want {
		t.Errorf("reduced call %.80q: want %q (no assignments, no prints)", reduced, want)
	}
	// Statements that may write are kept first, in order: a delete after
	// 3000 printing statements is kept (review r4 finding 2).
	for _, writer := range []string{"/bin/rm -f ~/.defenseclaw/config.yaml", `\rm -f ~/.defenseclaw/config.yaml`,
		`"rm" -f ~/.defenseclaw/config.yaml`, "sh -c 'rm -f ~/.defenseclaw/config.yaml'", "unlink ~/.defenseclaw/config.yaml",
		"find ~/.defenseclaw -name config.yaml -delete", "printf c | /usr/bin/tee -a ~/.defenseclaw/config.yaml",
		"shred -u ~/.defenseclaw/config.yaml"} {
		reduced, overflow, _ := StateNamingStatements(strings.Join(padding, "; ")+"; "+writer, "/home/u")
		// A pipeline is split into its stages; the stage that names the
		// state is kept.
		stage := writer[strings.LastIndex(writer, "| ")+1:]
		if overflow || !strings.HasSuffix(reduced, strings.TrimSpace(stage)) {
			t.Errorf("%s after 3000 printing statements: overflow %t, reduced ends %q; want the writer kept", writer, overflow, reduced[max(0, len(reduced)-60):])
		}
	}
	writers := make([]string, StateNamingStatementsMax+1)
	for i := range writers {
		writers[i] = fmt.Sprintf("echo claw%d >> notes.txt", i)
	}
	if _, overflow, _ := StateNamingStatements(strings.Join(writers, "; "), "/home/u"); !overflow {
		t.Error("129 writing statements that name the state did not overflow")
	}
	for _, read := range []string{"cat ~/.defenseclaw/config.yaml 2>/dev/null", "defenseclaw status 2>&1", "grep -c claw1 README.md 2>/dev/null", "echo claw >/dev/null"} {
		if !stateStatementReadOnly(read, "/home/u") {
			t.Errorf("%q: not proven read-only", read)
		}
	}
	for _, write := range []string{"echo claw > x", "defenseclaw uninstall", "x=$(rm f)", "printf c | tee -a f", "rm -f claw"} {
		if stateStatementReadOnly(write, "/home/u") {
			t.Errorf("%q: proven read-only", write)
		}
	}
	// Review r5 mutation MP: a directory change is kept before the reads
	// that fill the bound, so the relative write it places stays placed.
	stateReads := make([]string, StateNamingStatementsMax-1)
	for i := range stateReads {
		stateReads[i] = "cat ~/.defenseclaw/config.yaml 2>/dev/null"
	}
	placed, overflow, _ := StateNamingStatements(gap0568Assignments(200)+"; "+strings.Join(stateReads, "; ")+"; cd ~/.defenseclaw; printf c >> ../.defenseclaw/config.yaml", "/home/u")
	if overflow || placed != "cd ~/.defenseclaw; printf c >> ../.defenseclaw/config.yaml" {
		t.Errorf("cd after 127 reads: overflow %t, reduced ends %q; want the cd kept with the write", overflow, placed[max(0, len(placed)-60):])
	}
	// rel-1-0-6:GAP-0414: a kept call of a function the call defines is not
	// reducible.
	for _, call := range []string{
		gap0568Assignments(200) + "; " + strings.Join(stateReads, "; ") + `; f() { printf c >> "$1"; }; f ~/.defenseclaw/config.yaml`,
		gap0568Assignments(200) + `; function f { printf c >> "$1"; }; f ~/.defenseclaw/config.yaml`,
	} {
		if _, overflow, ok := StateNamingStatements(call, "/home/u"); !ok || !overflow {
			t.Errorf("%.60q...: ok %t overflow %t, want an overflow (the definition holds the write)", call[len(call)-60:], ok, overflow)
		}
	}
	if _, overflow, _ := StateNamingStatements(gap0568Assignments(200)+`; f() { echo hi; }; f; printf c >> ~/.defenseclaw/config.yaml`, "/home/u"); overflow {
		t.Error("a defined function the kept statements do not call made an overflow")
	}
	state = "printf c >> ~/.defense''claw/config.yaml"
	if reduced, overflow, _ := StateNamingStatements(gap0568Assignments(200)+"; "+state, "/home/u"); reduced != state || overflow {
		t.Errorf("reduced call %q (overflow %t), want only %q", reduced, overflow, state)
	}
	if _, overflow, _ := StateNamingStatements(strings.Join(writers[:StateNamingStatementsMax], "; "), "/home/u"); overflow {
		t.Error("exactly the bound overflowed")
	}
	for _, text := range []string{"~/.DefenseClaw", `~/.defense\claw`, "~/.defense?law", "e=claw"} {
		if !MayNameState(text) {
			t.Errorf("%q: not taken as naming the state", text)
		}
	}
	if MayNameState("echo hello; ls -la") {
		t.Error("an ordinary call was taken as naming the state")
	}
}
