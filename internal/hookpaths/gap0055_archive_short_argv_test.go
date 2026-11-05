// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"strings"
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
	"sh -c 'command -v unzip'",
	"bash -lc 'command -v unzip && command -v tar'",
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

// TestGAP0055ArchiveProgramsShortArgvNoPanic: every archive program with
// zero, one and two arguments, called directly, through a wrapper and as a
// lookup, is read without a panic, by the link reader, the extraction
// check and the hook client's evidence (Resolve).
func TestGAP0055ArchiveProgramsShortArgvNoPanic(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	argvs := [][]string{nil, {"-v"}, {"-v", "a.zip"}, {"a"}, {"a", "b"}, {"x"}, {"-x"}}
	commands := append([]string(nil), gap0055Commands...)
	for _, program := range archivePrograms {
		for _, argv := range argvs {
			name := fmt.Sprintf("%s/%q", program, argv)
			gap0055NoPanic(t, "archiveMayLink "+name, func() { archiveMayLink(program, argv, makeStatic(len(argv))) })
			gap0055NoPanic(t, "archiveCopiesLinks "+name, func() { archiveCopiesLinks(program, argv, makeStatic(len(argv))) })
			call := strings.TrimSpace(program + " " + strings.Join(argv, " "))
			commands = append(commands, call, "command "+call, "env "+call, "sudo "+call, "command -v "+call)
		}
	}
	for _, command := range commands {
		gap0055NoPanic(t, "commandLinks "+command, func() { commandLinks(command, cwd, home, nil, false, false) })
		gap0055NoPanic(t, "ArchiveBeforeWrite "+command, func() { ArchiveBeforeWrite(command+"; echo hi > out.txt", home) })
		payload, err := json.Marshal(map[string]any{"session_id": "gap0055", "hook_event_name": "PreToolUse", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		gap0055NoPanic(t, "Resolve "+command, func() { Resolve(payload) })
	}
}

// TestGAP0055LookupRunsNoLinkProgram: command -v and command -V only print
// how their operands resolve, so a lookup of ln, cp or an archive program,
// with or without more operands, leaves the command's links known. The
// same programs run through command, command -p, sudo or env, or behind a
// lookup option the hook cannot read, keep the opaque reading.
func TestGAP0055LookupRunsNoLinkProgram(t *testing.T) {
	cwd, home := t.TempDir(), t.TempDir()
	for _, command := range []string{
		"command -v unzip",
		"command -v unzip && command -v tar",
		"command -v unzip x.zip",
		"command -V unzip x.zip",
		"command -pv unzip x.zip",
		"command -v -p unzip x.zip",
		"command -v ln cp unzip",
		"command -v tar xf a.tar",
		"sudo command -v unzip x.zip",
		"env command -v unzip x.zip",
		"command -v unzip >/dev/null 2>&1 || exit 1",
	} {
		links := commandLinks(command, cwd, home, nil, false, false)
		if !links.known || links.opaque || links.globalOpaque {
			t.Errorf("%s: known=%t opaque=%t globalOpaque=%t, want a known reading", command, links.known, links.opaque, links.globalOpaque)
		}
	}
	for _, command := range []string{
		"command unzip x.zip",
		"command -p unzip x.zip",
		"sudo unzip x.zip -d out",
		"command -v$X unzip x.zip",
		"command $OPT unzip x.zip",
	} {
		if links := commandLinks(command, cwd, home, nil, false, false); links.known {
			t.Errorf("%s: known reading, want the opaque reading of a program that runs", command)
		}
	}
}

// FuzzGAP0055CommandLinksRead: the link reader never panics. The seeds are
// the GAP-0055 forms and every archive program bare and as a lookup.
func FuzzGAP0055CommandLinksRead(f *testing.F) {
	for _, command := range gap0055Commands {
		f.Add(command)
	}
	for _, program := range archivePrograms {
		f.Add(program)
		f.Add("command -v " + program)
		f.Add("env " + program + " -v")
	}
	cwd, home := f.TempDir(), f.TempDir()
	f.Fuzz(func(t *testing.T, command string) {
		if len(command) > 2048 {
			t.Skip()
		}
		commandLinksRead(command, cwd, home, nil, false, false, true)
		commandLinksRead(command, cwd, home, nil, false, false, false)
		ArchiveBeforeWrite(command, home)
	})
}
