// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

// No real group query, namespace creation, child process or payload image is used.
// a wrapper that silently substitutes Getpgid(0) must not satisfy this test.
func TestTreeGroupUsesAllowedRawSyscallAndPreservesError(t *testing.T) {
	for _, test := range []struct {
		name  string
		group uintptr
		errno unix.Errno
		pid   int
		want  bool
	}{
		{"positive-nonleader", 41, 0, 42, true},
		{"error-with-positive-return", 41, unix.EPERM, 42, false},
		{"failed-syscall-return", ^uintptr(0), unix.EPERM, 42, false},
		{"zero-group", 0, 0, 42, false},
		{"leader", 42, 0, 42, false},
		{"invalid-pid-t", ^uintptr(0), 0, 42, false},
		{"invalid-process-id", 41, 0, 0, false},
	} {
		calls := 0
		raw := func(number, a1, a2, a3 uintptr) (uintptr, uintptr, unix.Errno) {
			calls++
			// This numeric assertion is independent of the selected x/sys name:
			// AXIS's pinned amd64 BPF allows 111 and refuses Getpgid 121.
			if number != 111 || a1 != 0 || a2 != 0 || a3 != 0 {
				t.Fatal("fixed group query selected a different syscall or arguments")
			}
			return test.group, 0, test.errno
		}
		if got := fixedTreeGroup(raw, test.pid); got != test.want {
			t.Fatalf("%s: wrong group precondition", test.name)
		}
		wantCalls := 1
		if test.pid <= 0 {
			wantCalls = 0
		}
		if calls != wantCalls {
			t.Fatalf("%s: raw syscall substitution or unexpected call count", test.name)
		}
	}
}
