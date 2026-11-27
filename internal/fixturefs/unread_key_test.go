// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package fixturefs

import (
	"os"
	"strings"
	"testing"
)

// The key that tells which goroutine runs inside Unread is chosen per GOOS
// (substrate-1 GAP-0997): Linux and Windows pin the goroutine to its thread
// and use the thread id, which is one system call; every other platform, macOS
// in particular, keeps the goroutine number read from a stack capture on each
// Map call while a decision runs. The thread-id key is not proven on macOS (no
// macOS test run covers it), and a wrong key would make other goroutines read
// as Unread, which weakens verdicts. This test reads the per-GOOS files, so it
// pins the macOS choice from a Linux run too.
func TestUnreadKeyStrategyPerPlatform(t *testing.T) {
	cases := []struct {
		file       string
		constraint string
		wantStack  bool
		wantThread []string
	}{
		{"unread_key_linux.go", "//go:build linux", false, []string{"syscall.Gettid()", "runtime.LockOSThread()"}},
		{"unread_key_windows.go", "//go:build windows", false, []string{"windows.GetCurrentThreadId()", "runtime.LockOSThread()"}},
		{"unread_key_other.go", "//go:build !linux && !windows", true, nil},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			raw, err := os.ReadFile(c.file)
			if err != nil {
				t.Fatal(err)
			}
			src := string(raw)
			if !strings.Contains(src, c.constraint+"\n") {
				t.Fatalf("%s: build constraint %q is gone; the platforms that use this key changed", c.file, c.constraint)
			}
			if got := strings.Contains(src, "runtime.Stack("); got != c.wantStack {
				t.Fatalf("%s: uses the stack capture = %v, want %v", c.file, got, c.wantStack)
			}
			for _, want := range c.wantThread {
				if !strings.Contains(src, want) {
					t.Fatalf("%s: missing %q, the thread-id key", c.file, want)
				}
			}
			if c.wantStack {
				for _, bad := range []string{"Gettid", "GetCurrentThreadId", "LockOSThread", "SYS_THREAD_SELFID"} {
					if strings.Contains(src, bad) {
						t.Fatalf("%s: uses %q: a thread-id key on a platform with no test run to prove it (see docs/TESTING.md)", c.file, bad)
					}
				}
			}
		})
	}
}
