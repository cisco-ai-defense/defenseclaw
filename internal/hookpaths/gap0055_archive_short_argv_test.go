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

// TestGAP0055ProgramBranchesShortArgvNoPanic is the class test of GAP-0055:
// a program-specific branch that reads an argv word by position, or skips
// an option's value, without checking that the word is there. Every word
// and option the package's branches compare with is run with zero, one and
// two arguments, alone and behind each lookup and wrapper, and every option
// is put last with its value missing, through the hook client's evidence
// (Resolve) and the extraction check. None may panic. A race build runs a
// fixed stride of the forms and every archive program form.
func TestGAP0055ProgramBranchesShortArgvNoPanic(t *testing.T) {
	words, options := gap0055SourceLiterals(t)
	if len(words) < 400 || len(options) < 200 {
		t.Fatalf("source literals: %d words, %d options; the harvest is broken", len(words), len(options))
	}
	cwd, home := t.TempDir(), t.TempDir()
	commands := append([]string(nil), gap0055Commands...)
	for _, word := range words {
		for _, argv := range []string{"", " -v", " -", " --", " a", " a b", " ''", " $X"} {
			commands = append(commands, word+argv)
		}
		for _, wrapper := range gap0055Wrappers {
			commands = append(commands, fmt.Sprintf(wrapper, word))
		}
	}
	var programs []string
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
	for _, program := range programs {
		for _, option := range options {
			commands = append(commands, program+" "+option, program+" a "+option)
		}
	}
	if gap0055RaceBuild {
		var sample []string
		for i, command := range commands {
			if i%11 == 0 || slices.Contains(archivePrograms, strings.Fields(command + " x")[0]) {
				sample = append(sample, command)
			}
		}
		commands = sample
	}
	var mu sync.Mutex
	reported := map[string]bool{}
	failures := 0
	jobs := make(chan string)
	var wg sync.WaitGroup
	for range runtime.GOMAXPROCS(0) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for command := range jobs {
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
					Resolve(payload)
					ArchiveBeforeWrite(command, home)
				}()
			}
		}()
	}
	for _, command := range commands {
		jobs <- command
	}
	close(jobs)
	wg.Wait()
	t.Logf("%d words, %d options, %d programs, %d commands, %d panics", len(words), len(options), len(programs), len(commands), failures)
}

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
