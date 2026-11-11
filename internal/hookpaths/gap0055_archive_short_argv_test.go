// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// gap0055Commands are the shell forms of gas-ux-r1 GAP-0055: a program
// lookup (command -v, command -V) and an archive program reached with no
// arguments, bare or through a wrapper. 1.0.7 and 1.0.8 panicked in
// archiveMayLink on the unzip forms (index out of range [0] with length 0):
// the per-user gateway failed closed with no rule id and the managed hook
// client crashed.
var gap0055Commands = []string{
	"command -v unzip",
	"command -v unzip && command -v tar",
	"command -v unzip; command -v tar",
	"command -v unzip || exit 1",
	"command -v unzip && command -v tar && command -v 7z",
	"command -V unzip",
	"command -pv unzip",
	"command unzip",
	"env unzip",
	"sudo unzip",
	"sudo -n unzip",
	"nohup unzip",
	"unzip",
	"busybox unzip",
	"exec -a",
	"exec -a name",
	"sh -c 'command -v unzip'",
	"bash -lc 'command -v unzip && command -v tar'",
}

// gap0055Wrappers put a program behind a lookup, a wrapper, a nested shell,
// a substitution, a pipe or a list.
var gap0055Wrappers = []string{
	"command -v %s", "command -V %s", "command -pv %s", "type %s", "type -p %s", "hash %s",
	"env %s", "env -u X %s", "sudo %s", "sudo -n %s", "nice %s", "nice -n 5 %s", "nohup %s",
	"exec %s", "exec -a x %s", "command %s", "builtin %s", "xargs %s", "busybox %s", "time %s",
	"timeout 5 %s", "sh -c '%s'", "bash -lc '%s'", "x=$(%s)", "echo a | %s", "true && %s",
	"%s; echo hi > out.txt",
}

var (
	gap0055WordLiteral   = regexp.MustCompile(`^[A-Za-z.:][A-Za-z0-9._+-]{0,23}$`)
	gap0055OptionLiteral = regexp.MustCompile(`^(-[A-Za-z0-9-]{1,23}=?|/[A-Za-z]{1,3})$`)
)

// gap0055SourceLiterals are the program-shaped and option-shaped string
// literals of this package's own source: every word a program-specific
// branch compares an argv word with. A new branch is swept without a test
// change.
func gap0055SourceLiterals(t *testing.T) (words, options []string) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	wordSet, optionSet := map[string]bool{}, map[string]bool{}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING {
				if value, err := strconv.Unquote(literal.Value); err == nil {
					wordSet[value] = wordSet[value] || gap0055WordLiteral.MatchString(value)
					optionSet[value] = optionSet[value] || gap0055OptionLiteral.MatchString(value)
				}
			}
			return true
		})
	}
	for value, ok := range wordSet {
		if ok {
			words = append(words, value)
		}
	}
	for value, ok := range optionSet {
		if ok {
			options = append(options, value)
		}
	}
	sort.Strings(words)
	sort.Strings(options)
	return words, options
}

// gap0055NoPanic runs read and reports a panic as a test failure, so one
// panicking form does not hide the others.
func gap0055NoPanic(t *testing.T, name string, read func()) {
	t.Helper()
	defer func() {
		if recovered := recover(); recovered != nil {
			t.Errorf("%s: panic: %v", name, recovered)
		}
	}()
	read()
}

// gap0055BoundedSweep is true in a race build, where one hook client
// evidence call (Resolve) costs several times what it does in a plain build.
// Every other build, native Windows included, reads every form through
// Resolve: the sweep is split into gap0055SweepParts tests so the Windows
// shard packer can run the parts side by side (GAP-0749). A part took about
// 215 s on a hosted Windows runner when there were eight; sixteen keep each
// part near 110 s, so the packer can fill a shard step with small parts
// (GAP-0963).
var gap0055BoundedSweep = gap0055RaceBuild

// gap0055SweepParts is the number of tests the sweep is split into; part i
// reads the forms whose index is i modulo this number. A test of each part
// follows TestGAP0055ProgramBranchesShortArgvNoPanic (TestGAP0749SweepPartsAreAllRun).
const gap0055SweepParts = 16

// gap0055ResolveBudget bounds the forms a bounded sweep reads through
// Resolve, so a source that grows more program-specific words cannot push it
// past what a slow runner reads.
const gap0055ResolveBudget = 22000

// gap0055Form is one command of the sweep. A form with resolve set is read
// through Resolve; a bounded sweep reads the others through the parsers and
// decision readers Resolve is built on (gap0055ReadParsers). Every form is
// read one way or the other: a bounded sweep drops no form.
type gap0055Form struct {
	command string
	resolve bool
}

// gap0055Argvs are the argument lists each word is run with: none, one and
// two arguments, an option, a bare dash and a double dash, an empty word and
// a variable.
var gap0055Argvs = []string{"", " -v", " -", " --", " a", " a b", " ''", " $X"}

// gap0055SweepForms is every form of the sweep: the GAP-0055 commands, each
// word of the source behind each argv and each wrapper, and each program of
// the package with each option, last and after one operand. A bounded sweep
// reads through Resolve: every GAP-0055 command, every bare argv form of every
// word, every argv and wrapper form of an archive program (where the GAP-0055 panic was), each
// wrapper behind every fourth word, and one eighth of the program-option pairs,
// spread so that each program meets a spread of options and each option a
// spread of programs.
func gap0055SweepForms(words, options []string, bounded bool) (forms []gap0055Form, programs []string) {
	add := func(command string, resolve bool) {
		forms = append(forms, gap0055Form{command, resolve || !bounded})
	}
	for _, command := range gap0055Commands {
		add(command, true)
	}
	// The archive programs are swept as words, whether or not the source
	// spells them as one (7zr starts with a digit).
	swept := slices.Clone(words)
	for _, program := range archivePrograms {
		if !slices.Contains(swept, program) {
			swept = append(swept, program)
		}
	}
	for wordIndex, word := range swept {
		for _, argv := range gap0055Argvs {
			add(word+argv, true)
		}
		for wrapperIndex, wrapper := range gap0055Wrappers {
			add(fmt.Sprintf(wrapper, word), slices.Contains(archivePrograms, word) || (wordIndex+wrapperIndex)%4 == 0)
		}
	}
	for _, list := range [][]string{archivePrograms, copyPrograms, linkPrograms, renamePrograms, cdPrograms, multicallPrograms,
		braceOperandPrograms, dataPrograms, hiddenDirectoryPrograms, knownWordPrograms, readOnlyLinkWordPrograms, readerPrograms,
		{"env", "sudo", "doas", "nice", "exec", "timeout", "xargs", "command", "builtin", "nohup", "time", "stdbuf",
			"sh", "bash", "eval", "find", "git", "printf", "sed", "awk", "python3", "node", "perl", "cmd", "powershell", "pwsh"}} {
		for _, program := range list {
			if !slices.Contains(programs, program) {
				programs = append(programs, program)
			}
		}
	}
	for programIndex, program := range programs {
		for optionIndex, option := range options {
			add(program+" "+option, (programIndex+optionIndex)%16 == 0)
			add(program+" a "+option, (programIndex+optionIndex)%16 == 8)
		}
	}
	return forms, programs
}

// gap0055ReadParsers reads a form the way Resolve does without its file
// system evidence: the link reader (with and without the disk), the archive
// reader, the command decision in the Windows and the hook client dialects
// and every other reader Resolve runs on the command text
// (gap0749ResolveReaders). These hold every program-specific branch that
// reads an argv word by position; what Resolve adds is file system probes
// that do not depend on the form.
func gap0055ReadParsers(command, cwd, home string) {
	commandLinksRead(command, cwd, home, nil, false, false, false)
	commandLinksRead(command, cwd, home, nil, false, false, true)
	ArchiveBeforeWrite(command, home)
	ActionCommandAuditReasonWithDialect(command, cwd, home, "")
	gap0749ResolveReaders(command, cwd, home)
}

// gap0055SweepPart runs one part of the class test of GAP-0055 (the tests
// TestGAP0055ProgramBranchesShortArgvNoPanicPart0 to Part15 run every form):
// a program-specific branch that reads an argv word by position, or skips
// an option's value, without checking that the word is there. Every word
// and option the package's branches compare with is run with zero, one and
// two arguments, alone and behind each lookup and wrapper, and every option
// is put last with its value missing, through the hook client's evidence
// (Resolve) and the extraction check. None may panic. A race build reads a spread of the forms through Resolve and the rest
// through the readers it is built on (gap0055BoundedSweep): every form is
// read.
func gap0055SweepPart(t *testing.T, part int) {
	t.Helper()
	words, options := gap0055SourceLiterals(t)
	if len(words) < 400 || len(options) < 200 {
		t.Fatalf("source literals: %d words, %d options; the harvest is broken", len(words), len(options))
	}
	cwd, home := t.TempDir(), t.TempDir()
	forms, programs := gap0055SweepForms(words, options, gap0055BoundedSweep)
	var mu sync.Mutex
	reported := map[string]bool{}
	failures := 0
	jobs := make(chan gap0055Form)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for form := range jobs {
				command := form.command
				payload, err := json.Marshal(map[string]any{"session_id": "gap0055", "hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
				if err != nil {
					panic(err)
				}
				func() {
					defer func() {
						if recovered := recover(); recovered != nil {
							mu.Lock()
							defer mu.Unlock()
							failures++
							if key := fmt.Sprint(recovered); !reported[key] && len(reported) < 40 {
								reported[key] = true
								t.Errorf("%q: panic: %v", command, recovered)
							}
						}
					}()
					if form.resolve {
						Resolve(payload)
						ArchiveBeforeWrite(command, home)
					} else {
						gap0055ReadParsers(command, cwd, home)
					}
				}()
			}
		}()
	}
	read := 0
	for index, form := range forms {
		if index%gap0055SweepParts == part {
			jobs <- form
			read++
		}
	}
	close(jobs)
	wg.Wait()
	t.Logf("part %d of %d: %d words, %d options, %d programs, %d of %d commands, %d panics", part, gap0055SweepParts, len(words), len(options), len(programs), read, len(forms), failures)
}

func TestGAP0055ProgramBranchesShortArgvNoPanicPart0(t *testing.T)  { gap0055SweepPart(t, 0) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart1(t *testing.T)  { gap0055SweepPart(t, 1) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart2(t *testing.T)  { gap0055SweepPart(t, 2) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart3(t *testing.T)  { gap0055SweepPart(t, 3) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart4(t *testing.T)  { gap0055SweepPart(t, 4) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart5(t *testing.T)  { gap0055SweepPart(t, 5) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart6(t *testing.T)  { gap0055SweepPart(t, 6) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart7(t *testing.T)  { gap0055SweepPart(t, 7) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart8(t *testing.T)  { gap0055SweepPart(t, 8) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart9(t *testing.T)  { gap0055SweepPart(t, 9) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart10(t *testing.T) { gap0055SweepPart(t, 10) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart11(t *testing.T) { gap0055SweepPart(t, 11) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart12(t *testing.T) { gap0055SweepPart(t, 12) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart13(t *testing.T) { gap0055SweepPart(t, 13) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart14(t *testing.T) { gap0055SweepPart(t, 14) }
func TestGAP0055ProgramBranchesShortArgvNoPanicPart15(t *testing.T) { gap0055SweepPart(t, 15) }

// TestGAP0055ArchiveProgramsShortArgvNoPanic: the archive readers take an
// argv of any length, with static flags of any length.
func TestGAP0055ArchiveProgramsShortArgvNoPanic(t *testing.T) {
	for _, program := range archivePrograms {
		for _, argv := range [][]string{nil, {"-v"}, {"-v", "a.zip"}, {"a"}, {"a", "b"}, {"x"}, {"-x"}} {
			for _, static := range [][]bool{makeStatic(len(argv)), nil, makeStatic(len(argv) / 2)} {
				name := fmt.Sprintf("%s/%q/static=%d", program, argv, len(static))
				gap0055NoPanic(t, "archiveMayLink "+name, func() { archiveMayLink(program, argv, static) })
				gap0055NoPanic(t, "archiveCopiesLinks "+name, func() { archiveCopiesLinks(program, argv, static) })
			}
		}
	}
	if archiveMayLink("unzip", nil, nil) {
		t.Error("a bare unzip prints its usage; it extracts nothing")
	}
	for _, argv := range [][]string{{"x.zip"}, {"-o", "x.zip"}, {"x.zip", "-d", "out"}} {
		if !archiveMayLink("unzip", argv, makeStatic(len(argv))) {
			t.Errorf("unzip %q extracts", argv)
		}
	}
}

// FuzzGAP0055CommandLinksRead: the link reader and the hook client's
// evidence never panic. The seeds are the GAP-0055 forms and every archive
// program bare, as a lookup and wrapped.
func FuzzGAP0055CommandLinksRead(f *testing.F) {
	for _, command := range gap0055Commands {
		f.Add(command)
	}
	for _, program := range archivePrograms {
		for _, wrapper := range gap0055Wrappers {
			f.Add(fmt.Sprintf(wrapper, program))
		}
	}
	cwd, home := f.TempDir(), f.TempDir()
	f.Fuzz(func(t *testing.T, command string) {
		if len(command) > 2048 {
			t.Skip()
		}
		commandLinksRead(command, cwd, home, nil, false, false, true)
		commandLinksRead(command, cwd, home, nil, false, false, false)
		ArchiveBeforeWrite(command, home)
		payload, err := json.Marshal(map[string]any{"session_id": "gap0055", "hook_event_name": "PreToolUse", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Skip()
		}
		Resolve(payload)
	})
}

// TestGAP0749BoundedSweepReadsEveryFormAndStaysInBudget: the bounded sweep
// (race builds) reads every form of the full sweep, holds the
// forms it reads through Resolve to a budget a slow runner finishes in its
// shard step, and reads through Resolve every bare argv form of every word and
// every argv and wrapper form of an archive program; each wrapper, program and option meets Resolve
// in a spread of forms. The full sweep, all through Resolve in one test, ran past the
// 1020 s step of the Windows shard pk3 (GAP-0749).
func TestGAP0749BoundedSweepReadsEveryFormAndStaysInBudget(t *testing.T) {
	words, options := gap0055SourceLiterals(t)
	full, programs := gap0055SweepForms(words, options, false)
	bounded, boundedPrograms := gap0055SweepForms(words, options, true)
	if len(bounded) != len(full) || len(boundedPrograms) != len(programs) {
		t.Fatalf("the bounded sweep reads %d forms and %d programs, the full sweep %d and %d", len(bounded), len(boundedPrograms), len(full), len(programs))
	}
	deep := make(map[string]bool, len(bounded))
	resolved := 0
	for index, form := range bounded {
		if form.command != full[index].command {
			t.Fatalf("form %d is %q in the bounded sweep and %q in the full one", index, form.command, full[index].command)
		}
		// The benign twin: a run that is not bounded reads every form through Resolve.
		if !full[index].resolve {
			t.Fatalf("an unbounded run reads %q only through the parsers", form.command)
		}
		if form.resolve {
			resolved++
			deep[form.command] = true
		}
	}
	t.Logf("bounded sweep: %d forms, %d through Resolve, budget %d", len(bounded), resolved, gap0055ResolveBudget)
	if resolved > gap0055ResolveBudget {
		t.Fatalf("the bounded sweep reads %d forms through Resolve; the budget is %d: thin the spread, not the budget", resolved, gap0055ResolveBudget)
	}
	if resolved >= len(full) {
		t.Fatalf("the bounded sweep reads all %d forms through Resolve", len(full))
	}
	for _, command := range gap0055Commands {
		if !deep[command] {
			t.Errorf("GAP-0055 command %q is not read through Resolve", command)
		}
	}
	for _, word := range words {
		for _, argv := range gap0055Argvs {
			if !deep[word+argv] {
				t.Errorf("bare form %q is not read through Resolve", word+argv)
			}
		}
	}
	for _, program := range archivePrograms {
		for _, argv := range gap0055Argvs {
			if !deep[program+argv] {
				t.Errorf("archive program form %q is not read through Resolve", program+argv)
			}
		}
		for _, wrapper := range gap0055Wrappers {
			if !deep[fmt.Sprintf(wrapper, program)] {
				t.Errorf("archive program form %q is not read through Resolve", fmt.Sprintf(wrapper, program))
			}
		}
	}
	for _, wrapper := range gap0055Wrappers {
		seen := 0
		for _, word := range words {
			if deep[fmt.Sprintf(wrapper, word)] {
				seen++
			}
		}
		if seen < len(words)/8 {
			t.Errorf("wrapper %q is read through Resolve behind %d of %d words", wrapper, seen, len(words))
		}
	}
	pairs := func(program, option string) int {
		n := 0
		for _, form := range []string{program + " " + option, program + " a " + option} {
			if deep[form] {
				n++
			}
		}
		return n
	}
	for _, program := range programs {
		seen := 0
		for _, option := range options {
			seen += pairs(program, option)
		}
		if seen < len(options)/16 {
			t.Errorf("program %q is read through Resolve with %d of %d options", program, seen, len(options))
		}
	}
	for _, option := range options {
		seen := 0
		for _, program := range programs {
			seen += pairs(program, option)
		}
		if seen < len(programs)/16 {
			t.Errorf("option %q is read through Resolve behind %d of %d programs", option, seen, len(programs))
		}
	}
}

// TestGAP0749SweepPartsAreAllRun: the sweep is run by exactly
// gap0055SweepParts tests, one per part, so no part of the forms is left to a
// test that does not exist.
func TestGAP0749SweepPartsAreAllRun(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "gap0055_archive_short_argv_test.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := map[int]bool{}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !strings.HasPrefix(fn.Name.Name, "TestGAP0055ProgramBranchesShortArgvNoPanicPart") {
			continue
		}
		part, err := strconv.Atoi(strings.TrimPrefix(fn.Name.Name, "TestGAP0055ProgramBranchesShortArgvNoPanicPart"))
		if err != nil || found[part] {
			t.Fatalf("%s is not part %d once", fn.Name.Name, part)
		}
		found[part] = true
	}
	for part := range gap0055SweepParts {
		if !found[part] {
			t.Errorf("part %d of the sweep has no test", part)
		}
	}
	if len(found) != gap0055SweepParts {
		t.Errorf("%d part tests, want %d", len(found), gap0055SweepParts)
	}
}
