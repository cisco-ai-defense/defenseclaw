// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package namespaceinit

import (
	"errors"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestAllThreadCapabilityDropStopsOnUnsupportedBarrier(t *testing.T) {
	// This injected barrier models three runtime threads, never native syscalls.
	for fail := 0; fail <= 3; fail++ {
		calls := 0
		ambient, caps, nnp := [3]bool{true, true, true}, [3]bool{true, true, true}, [3]bool{}
		barrier := func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
			calls++
			if calls == fail {
				return 0, 0, unix.ENOTSUP
			}
			switch calls {
			case 1:
				if trap != unix.SYS_PRCTL || a1 != unix.PR_CAP_AMBIENT || a2 != unix.PR_CAP_AMBIENT_CLEAR_ALL {
					t.Fatal("ambient barrier missing")
				}
				ambient = [3]bool{}
			case 2:
				if trap != unix.SYS_CAPSET || a1 == 0 || a2 == 0 {
					t.Fatal("capset barrier missing")
				}
				caps = [3]bool{}
			case 3:
				if trap != unix.SYS_PRCTL || a1 != unix.PR_SET_NO_NEW_PRIVS || a2 != 1 {
					t.Fatal("NNP barrier missing")
				}
				nnp = [3]bool{true, true, true}
			default:
				t.Fatal("unexpected per-thread fallback")
			}
			return 0, 0, 0
		}
		err := clearCapabilities(barrier)
		if fail != 0 {
			if !errors.Is(err, unix.ENOTSUP) || calls != fail {
				t.Fatal("unsupported all-thread barrier did not stop bootstrap")
			}
		} else if err != nil || ambient != [3]bool{} || caps != [3]bool{} || nnp != [3]bool{true, true, true} {
			t.Fatal("all-thread clear did not finish")
		}
	}
}
