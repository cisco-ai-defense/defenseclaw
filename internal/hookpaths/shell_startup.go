// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"slices"
	"strings"
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
	return s
}

// Encode is the header value: f=<0|1>;o=<0|1>;fn=<names>.
func (s ShellStartup) Encode() string {
	flag := func(on bool) string {
		if on {
			return "1"
		}
		return "0"
	}
	return "f=" + flag(s.File) + ";o=" + flag(s.Other) + ";fn=" + strings.Join(s.Functions, ",")
}

// DecodeShellStartup reads Encode's value. A malformed value is not ok.
func DecodeShellStartup(value string) (ShellStartup, bool) {
	var s ShellStartup
	if len(value) > 256 {
		return s, false
	}
	parts := strings.Split(value, ";")
	if len(parts) != 3 {
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
	return s, true
}

// UnknownShellStartup is the startup a gateway assumes for a header it
// cannot read: it withholds every safe proof.
func UnknownShellStartup() ShellStartup { return ShellStartup{File: true, Other: true} }

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
