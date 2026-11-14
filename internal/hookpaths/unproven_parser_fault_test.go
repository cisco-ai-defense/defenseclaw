// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// The bound rule's misuse check panics in this package's tests (TestAdopters).
func init() { bounded.PanicOnMisuse(true) }

// rel-1-0-10:GAP-0437, GAP-0486: an assignment whose $(( arithmetic has a
// syntax error made the recovering parse behind UnprovenProtectedWrite
// panic. The reader now gets ErrParserFault and returns the parser-fault
// class, whatever else the command holds, so every caller blocks it.
func TestUnprovenProtectedWriteParserFaultIsAFault(t *testing.T) {
	home := t.TempDir()
	cwd := t.TempDir()
	for _, command := range []string{
		"h=$((t d",
		"h=$((t d))",
		"echo ssh-ed25519 AAAA k >> ~/.ssh/authorized_keys\nh=$((t d",
	} {
		if got := UnprovenProtectedWrite(command, cwd, home); got != UnprovenParserFault {
			t.Errorf("UnprovenProtectedWrite(%q) = %q, want %s", command, got, UnprovenParserFault)
		}
		// A Windows home is read by the Windows decision first, which
		// gives its own unknown class; the POSIX reading is the fault.
		got := ActionCommandAuditReason(command, cwd, home)
		if got == "" || runtime.GOOS != "windows" && got != UnprovenParserFault {
			t.Errorf("ActionCommandAuditReason(%q) = %q, want %s (an unknown class on Windows)", command, got, UnprovenParserFault)
		}
		if got := ShellParseReason("claudecode", "Bash", command, cwd, home); got != UnprovenParserFault {
			t.Errorf("ShellParseReason(%q) = %q, want %s", command, got, UnprovenParserFault)
		}
		if title := UnprovenWriteTitle(UnprovenParserFault); title == "" {
			t.Errorf("the parser-fault class has no title")
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

// rel-1-0-10:GAP-0487: the fuzz corpus entry ad64e538f1aab24f (kept under
// testdata/fuzz/FuzzUnprovenProtectedWrite, so go test runs it as a seed)
// made the recovering parse loop forever. It now returns at once as a
// parser fault, and no goroutine is left running.
func TestUnprovenProtectedWriteRecoveringParseHangIsAFault(t *testing.T) {
	command := fuzzCorpusString(t, "FuzzUnprovenProtectedWrite", "ad64e538f1aab24f")
	goroutines := runtime.NumGoroutine()
	done := make(chan string, 1)
	go func() { done <- UnprovenProtectedWrite(command, "/home/fuzz/work", "/home/fuzz") }()
	select {
	case got := <-done:
		if got != UnprovenParserFault {
			t.Errorf("UnprovenProtectedWrite(corpus ad64e538f1aab24f) = %q, want %s", got, UnprovenParserFault)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("UnprovenProtectedWrite(corpus ad64e538f1aab24f) did not return in 10 s")
	}
	for i := 0; i < 50 && runtime.NumGoroutine() > goroutines; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > goroutines {
		t.Errorf("%d goroutine(s) left running after the reading (before %d)", n, goroutines)
	}
}

// fuzzCorpusString reads the string of a "go test fuzz v1" corpus entry.
func fuzzCorpusString(t *testing.T, target, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "fuzz", target, name))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if rest, ok := strings.CutPrefix(line, "string("); ok {
			value, err := strconv.Unquote(strings.TrimSuffix(rest, ")"))
			if err != nil {
				t.Fatal(err)
			}
			return value
		}
	}
	t.Fatalf("corpus %s/%s has no string", target, name)
	return ""
}
