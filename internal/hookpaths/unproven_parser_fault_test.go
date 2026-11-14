// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The bound rule's misuse check panics in this package's tests (TestAdopters).
func init() { bounded.PanicOnMisuse(true) }

// rel-1-0-10:GAP-0437: an assignment whose $(( arithmetic has a syntax error
// made the recovering parse behind UnprovenProtectedWrite panic. The reader
// now gets ErrParserFault and returns the proof-bound class, so every caller
// takes the profile's evaluation-limit path instead of the panic.
func TestUnprovenProtectedWriteParserFaultIsBound(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	for _, command := range []string{
		"h=$((t d",
		"h=$((t d))",
		"echo ssh-ed25519 AAAA k >> ~/.ssh/authorized_keys\nh=$((t d",
	} {
		if got := UnprovenProtectedWrite(command, cwd, home); got != "shell-parse-bound" {
			t.Errorf("UnprovenProtectedWrite(%q) = %q, want shell-parse-bound", command, got)
		}
		// A Windows home is read by the Windows decision first, which
		// gives its own unknown class; the POSIX reading is the bound.
		got := ActionCommandAuditReason(command, cwd, home)
		if got == "" || runtime.GOOS != "windows" && got != "shell-parse-bound" {
			t.Errorf("ActionCommandAuditReason(%q) = %q, want shell-parse-bound (an unknown class on Windows)", command, got)
		}
		if !ShellParseBound("claudecode", "Bash", command, cwd, home) {
			t.Errorf("ShellParseBound(%q) = false, want true", command)
		}
	}
}

// FuzzUnprovenProtectedWrite drives the recovering-parse proof (parse,
// render each recovered call, re-read it to depth 4) with arbitrary agent
// text. It must never panic.
func FuzzUnprovenProtectedWrite(f *testing.F) {
	for _, seed := range []string{
		"h=$((t d", "h=$((t d))", "echo a > out; if", "x=$((1+2)) y=$[3*4] cp a ~/.ssh/b",
		"cat <<E | tee ~/.bashrc\nbody\nE\n", "f() { echo x >> ~/.profile; }; f; fi",
		"python -c 'open(\"x\",\"w\")' ; done", "a[1]=x b+=y c=$(echo $((d e))) > ~/.ssh/k",
		"${x:-$((y z))} >> ~/.zshrc", "eval \"$(( a b ))\"", "bash -c 'echo > ~/.ssh/config' ;;",
	} {
		f.Add(seed)
	}
	home := "/home/fuzz"
	cwd := "/home/fuzz/work"
	f.Fuzz(func(t *testing.T, command string) {
		_ = UnprovenProtectedWrite(command, cwd, home)
	})
}
