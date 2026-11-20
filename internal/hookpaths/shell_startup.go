// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ShellStartupHeader carries the shell startup of the agent's process from
// the hook client to the gateway. The client runs in the agent's
// environment; a per-user gateway runs in its service's, so it cannot read
// the startup the agent's shell has (rel-1-0-10 GAP-0293 review F6).
const ShellStartupHeader = "X-DefenseClaw-Shell-Startup"

// shadowablePrograms are the programs a safe proof reads: an exported
// function of one of these names, or command_not_found_handle, changes what
// the proved statement runs.
var shadowablePrograms = []string{"touch", "gtouch", "mv", "gmv", "install", "ginstall", "sed", "gsed", "command_not_found_handle"}

// ShellStartup is what the agent's shell startup can do to a proved
// statement: a startup file (BASH_ENV, ENV), an exported function that
// replaces a program a proof reads, an export spelled neither name%% nor
// name() (unknown).
type ShellStartup struct {
	File, Other bool
	Functions   []string
	// glob are the bash glob options of the agent's environment (BASHOPTS,
	// SHELLOPTS, GLOBIGNORE), for a gateway that does not run in it.
	glob shellGlobOptions
}

// CurrentShellStartup reads the startup from this process's environment.
func CurrentShellStartup() ShellStartup {
	var s ShellStartup
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		s.File = true
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		function, exported := strings.CutPrefix(name, "BASH_FUNC_")
		if !exported {
			continue
		}
		function, modern := strings.CutSuffix(function, "%%")
		if !modern {
			var patched bool
			if function, patched = strings.CutSuffix(function, "()"); !patched {
				s.Other = true
				continue
			}
		}
		base := function[strings.LastIndexByte(function, '/')+1:]
		if slices.Contains(shadowablePrograms, base) && !slices.Contains(s.Functions, base) {
			s.Functions = append(s.Functions, base)
		}
	}
	slices.Sort(s.Functions)
	s.glob = shellGlobOptionsFromEnv(os.Getenv)
	return s
}

// globLetters are the option letters of the header's g= field.
var globLetters = []struct {
	letter byte
	field  func(*shellGlobOptions) *bool
}{
	{'d', func(o *shellGlobOptions) *bool { return &o.dotGlob }},
	{'c', func(o *shellGlobOptions) *bool { return &o.noCaseGlob }},
	{'n', func(o *shellGlobOptions) *bool { return &o.nullGlob }},
	{'f', func(o *shellGlobOptions) *bool { return &o.failGlob }},
	{'z', func(o *shellGlobOptions) *bool { return &o.noGlob }},
	{'s', func(o *shellGlobOptions) *bool { return &o.globStar }},
	{'e', func(o *shellGlobOptions) *bool { return &o.extGlob }},
	{'i', func(o *shellGlobOptions) *bool { return &o.globIgnore }},
	{'u', func(o *shellGlobOptions) *bool { return &o.unknown }},
}

func (o shellGlobOptions) encode() string {
	var out []byte
	for _, entry := range globLetters {
		if *entry.field(&o) {
			out = append(out, entry.letter)
		}
	}
	return string(out)
}

func decodeGlobOptions(text string) (shellGlobOptions, bool) {
	var o shellGlobOptions
	for i := 0; i < len(text); i++ {
		found := false
		for _, entry := range globLetters {
			if entry.letter == text[i] {
				*entry.field(&o) = true
				found = true
			}
		}
		if !found {
			return o, false
		}
	}
	return o, true
}

// Encode is the header value: f=<0|1>;o=<0|1>;fn=<names>;g=<glob letters>.
func (s ShellStartup) Encode() string {
	flag := func(on bool) string {
		if on {
			return "1"
		}
		return "0"
	}
	return "f=" + flag(s.File) + ";o=" + flag(s.Other) + ";fn=" + strings.Join(s.Functions, ",") + ";g=" + s.glob.encode()
}

// DecodeShellStartup reads Encode's value. A malformed value is not ok.
func DecodeShellStartup(value string) (ShellStartup, bool) {
	var s ShellStartup
	if len(value) > 256 {
		return s, false
	}
	parts := strings.Split(value, ";")
	if len(parts) != 3 && len(parts) != 4 {
		return s, false
	}
	for i, prefix := range []string{"f=", "o=", "fn="} {
		rest, found := strings.CutPrefix(parts[i], prefix)
		if !found {
			return s, false
		}
		switch i {
		case 0, 1:
			if rest != "0" && rest != "1" {
				return s, false
			}
			if i == 0 {
				s.File = rest == "1"
			} else {
				s.Other = rest == "1"
			}
		case 2:
			if rest == "" {
				continue
			}
			for _, name := range strings.Split(rest, ",") {
				if !slices.Contains(shadowablePrograms, name) {
					return s, false
				}
				s.Functions = append(s.Functions, name)
			}
		}
	}
	if len(parts) == 4 {
		letters, found := strings.CutPrefix(parts[3], "g=")
		if !found {
			return s, false
		}
		glob, ok := decodeGlobOptions(letters)
		if !ok {
			return s, false
		}
		s.glob = glob
	}
	return s, true
}

// UnknownShellStartup is the startup a gateway assumes for a header it
// cannot read: it withholds every safe proof.
func UnknownShellStartup() ShellStartup {
	return ShellStartup{File: true, Other: true, glob: shellGlobOptions{unknown: true}}
}

// mayChange reports a startup that can change what a statement running one
// of programs does.
func (s ShellStartup) mayChange(programs ...string) bool {
	if s.File || s.Other || slices.Contains(s.Functions, "command_not_found_handle") {
		return true
	}
	for _, name := range s.Functions {
		if slices.Contains(programs, name) {
			return true
		}
	}
	return false
}

// shellStartupCodeRunners are the programs that run code text the walk
// does not read as calls (a string, a file, a trap action or a child shell,
// which imports every exported function): when a statement names one, any
// exported function may run.
var shellStartupCodeRunners = map[string]bool{
	"eval": true, "source": true, ".": true, "trap": true, "fc": true,
	"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true,
}

// shellStartupUnknown reports a shell startup that can change what a
// statement runs: a startup file (BASH_ENV, ENV), an exported function for
// which calls reports true (bash runs a function instead of the program or
// builtin of that name; it accepts slashes in a function name, so
// /usr/bin/touch can be one), or command_not_found_handle, which runs for a
// missing program. An export spelled neither name%% (bash 4.3+) nor name()
// (older patched bash) is unknown. A function no statement calls changes
// nothing, so an unrelated export (environment-modules' module, an
// account's own helpers) leaves a proof intact (rel-1-0-10:GAP-0276). It
// reads this process's environment, for the variable-target and
// overwritten-redirect proofs (shellStartupUnknownForCommand); the touch -h
// and replace-verb proofs read a ShellStartup (mayChange), which a per-user
// gateway takes from the client's header.
func shellStartupUnknown(calls func(function string) bool) bool {
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		return true
	}
	for _, entry := range os.Environ() {
		name, _, _ := strings.Cut(entry, "=")
		function, exported := strings.CutPrefix(name, "BASH_FUNC_")
		if !exported {
			continue
		}
		function, modern := strings.CutSuffix(function, "%%")
		if !modern {
			var patched bool
			if function, patched = strings.CutSuffix(function, "()"); !patched {
				return true
			}
		}
		if function == "command_not_found_handle" || calls(function) {
			return true
		}
	}
	return false
}

// shellStartupUnknownForCommand is shellStartupUnknown for the statements
// of command: an exported function counts when a call of command is named
// for it (its spelling or its last path element), and every exported
// function counts when a call's program word is not a fixed name, when a
// word of a call names a program that runs code text
// (shellStartupCodeRunners), or when command does not parse. The command is
// parsed only when a function is exported.
func shellStartupUnknownForCommand(command string) bool {
	var names map[string]bool
	var any, read bool
	return shellStartupUnknown(func(function string) bool {
		if !read {
			read = true
			file, ok := parseShell(command)
			if !ok {
				file = nil
			}
			names, any = shellStartupCallNames(file)
		}
		return any || names[function] || names[function[strings.LastIndexByte(function, '/')+1:]]
	})
}

// shellStartupCallNames are the names the calls of file run (each program
// word, and its last path element), and any when one may run a function
// the walk cannot name.
func shellStartupCallNames(file *syntax.File) (names map[string]bool, any bool) {
	if file == nil {
		return nil, true
	}
	names = map[string]bool{}
	add := func(name string) {
		names[name] = true
		names[name[strings.LastIndexByte(name, '/')+1:]] = true
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if any {
			return false
		}
		switch node := node.(type) {
		case *syntax.CallExpr:
			for index, word := range node.Args {
				text := word.Lit()
				if text == "" {
					if index == 0 {
						any = true
					}
					continue
				}
				if index == 0 {
					add(text)
				}
				if shellStartupCodeRunners[text[strings.LastIndexByte(text, '/')+1:]] {
					any = true
				}
			}
		case *syntax.DeclClause:
			if node.Variant != nil {
				add(node.Variant.Value)
			}
		case *syntax.LetClause:
			add("let")
		}
		return true
	})
	return names, any
}
