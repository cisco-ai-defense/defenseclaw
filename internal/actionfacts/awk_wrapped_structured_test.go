// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0859: an awk program behind an exact wrapper reaches
// analyzeStructuredArgv, which reads the commands it starts like the shell
// parser does for a bare call (GAP-0499).
func TestWrappedAwkProgramCommandsAreRead(t *testing.T) {
	const program = `awk 'BEGIN{system("touch /home/a/.ssh/authorized_keys")}'`
	for _, wrapper := range []string{"", "env ", "sudo ", "timeout 5 ", "nice "} {
		facts := Analyze(Input{Tool: "shell", Command: wrapper + program, CWD: "/home/a", ActiveHome: "/home/a"})
		var programs []string
		for _, command := range facts.Commands {
			programs = append(programs, command.Program)
		}
		if !slices.Contains(programs, "touch") {
			t.Errorf("%q: programs %v, want the touch the awk program starts", wrapper+program, programs)
		}
	}
}

// rel-1-0-10:GAP-0859: the shell words of the program a static wrapper runs
// keep their run-time expansion through the wrapper, so an awk program with
// a shell hole is read as dynamic behind every wrapper of the shared set,
// as the bare call is (awkprog.DynamicReason, the unknown tier at the
// gateway), and an ordinary wrapped awk program stays static.
func TestWrappedAwkProgramKeepsTheShellWords(t *testing.T) {
	programs := []struct {
		text    string
		dynamic bool
	}{
		{`awk -v c="$X" 'BEGIN{system(c)}'`, true},
		{`awk "BEGIN{system(\"ls $X\")}"`, true},
		{`awk "BEGIN{system(\"ls $(date)\")}"`, true},
		{`awk 'BEGIN{system("ls")}'`, false},
	}
	wrappers := []string{"", "env ", "sudo ", "sudo -u root ", "command ", "exec ", "nice ", "nice -n 5 ",
		"time ", "timeout 5 ", "nohup ", "sudo timeout 5 ", "env nice -n 5 "}
	dynamic := func(command string) (awk, dyn bool) {
		facts := Analyze(Input{Tool: "shell", Command: command, CWD: "/home/a", ActiveHome: "/home/a"})
		for _, c := range facts.Commands {
			if IsAwkCall(c) {
				awk = true
				dyn = dyn || AwkCall(c).Read().Dynamic
			}
		}
		return awk, dyn
	}
	for _, program := range programs {
		for _, wrapper := range wrappers {
			awk, dyn := dynamic(wrapper + program.text)
			if !awk || dyn != program.dynamic {
				t.Errorf("%q: awk call %t dynamic %t, want an awk call, dynamic %t (as the bare call)", wrapper+program.text, awk, dyn, program.dynamic)
			}
		}
	}
	// A wrapper word that expands is not read through.
	if awk, _ := dynamic(`env -u "$X" awk 'BEGIN{system("ls")}'`); awk {
		t.Errorf("a wrapper word that expands was read through")
	}
}

// rel-1-0-10:GAP-0859: behind the wrappers whose child the path facts do not
// read (env NAME=value, chroot, nsenter, xargs, and the prefix wrappers the
// gateway wrapper twin reads: stdbuf, setsid, unbuffer, ionice, taskset,
// flock, doas), the awk call is still found
// with its shell words, so a shell hole in its program is dynamic, as in the
// bare call.
func TestAwkCallBehindContextWrappers(t *testing.T) {
	for _, wrapper := range []string{"env X=1 ", "chroot / ", "nsenter -t 1 -m ", "xargs ", "sudo env X=1 ", "xargs -I {} ",
		"stdbuf -o0 ", "setsid ", "unbuffer ", "unbuffer -p ", "ionice -c3 ", "taskset 1 ", "flock /tmp/lock ", "doas ", "setsid nohup timeout 5 "} {
		for _, program := range []struct {
			text    string
			dynamic bool
		}{
			{`awk -v c="$X" 'BEGIN{system(c)}'`, true},
			{`awk 'BEGIN{system("ls")}'`, false},
		} {
			facts := Analyze(Input{Tool: "shell", Command: wrapper + program.text, CWD: "/home/a", ActiveHome: "/home/a"})
			found, dynamic := false, false
			for _, command := range facts.Commands {
				if inner, ok := AwkCallBehindWrappers(command); ok {
					found = true
					dynamic = dynamic || AwkCall(inner).Read().Dynamic
				}
			}
			if !found || dynamic != program.dynamic {
				t.Errorf("%q: awk call found %t dynamic %t, want found, dynamic %t", wrapper+program.text, found, dynamic, program.dynamic)
			}
		}
	}
}
