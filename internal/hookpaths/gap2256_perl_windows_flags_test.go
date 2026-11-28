// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strconv"
	"strings"
	"testing"
)

// The Windows sysopen flag reading runs on every platform: the tables are
// not build-tagged. A Windows Perl defines the MSVC-only Fcntl names, and a
// raw number may carry MSVC (Strawberry, ActivePerl), Cygwin/MSYS or the
// Go-Windows values of the named flags (rel-1-0-10:GAP-2256).
func TestGAP2256WindowsPerlSysopenFlags(t *testing.T) {
	number := func(term string) (uint64, bool) {
		if value, err := strconv.ParseUint(term, 0, 64); err == nil {
			return value, true
		}
		for _, item := range perlCommonFlags {
			if item.name == term {
				return uint64(perlGoWindowsFlag(item.name)), true
			}
		}
		for _, item := range perlWindowsFlags {
			if item.name == term {
				return item.value, true
			}
		}
		return 0, false
	}
	cases := []struct {
		flags string
		write bool
	}{
		{"O_WRONLY|O_NOINHERIT", true},
		{"O_WRONLY|O_CREAT|O_RAW", true},
		{"O_RDWR|O_RANDOM", true},
		{"O_WRONLY|O_SEQUENTIAL", true},
		{"O_RDONLY|O_TEMPORARY", true},
		{"O_RDONLY|O_CREAT", true},
		{"O_RDONLY|O_TRUNC", true},
		{"O_RDONLY|O_APPEND", true},
		{"0x100", true}, // MSVC _O_CREAT
		{"0x8", true},   // MSVC and MSYS _O_APPEND
		{"0x40", true},  // Go-Windows O_CREAT, MSVC _O_TEMPORARY
		{"0x200", true}, // _O_TRUNC; MSYS O_CREAT
		{"0x400", true}, // Go-Windows O_APPEND; MSYS O_TRUNC
		{"0x101", true},
		{"O_RDONLY", false},
		{"O_RDONLY|O_NOINHERIT", false},
		{"O_RDONLY|O_RAW|O_BINARY", false},
		{"O_RDONLY|O_RANDOM|O_SEQUENTIAL|O_TEXT", false},
		{"O_RDONLY|O_EXCL|O_NOFOLLOW", false},
		{"0", false},
		{"0x8000", false}, // _O_BINARY
		{"0x4000", false}, // _O_TEXT
		{"0x80", false},   // _O_NOINHERIT
		{"0x10", false},   // _O_RANDOM
		{"0x20", false},   // _O_SEQUENTIAL
	}
	for _, tc := range cases {
		var flags uint64
		for _, term := range strings.Split(tc.flags, "|") {
			value, known := number(term)
			if !known {
				t.Fatalf("%s: %s is not a Windows Perl flag", tc.flags, term)
			}
			flags |= value
		}
		if got := perlFlagsWrite(flags, perlWindowsWriteBits); got != tc.write {
			t.Errorf("sysopen flags %s (%#x): write %v, want %v", tc.flags, flags, got, tc.write)
		}
	}
	// A symbolic modifier stays clear of every write bit and access mode.
	for _, item := range perlWindowsFlags {
		if item.name == "O_TEMPORARY" {
			continue
		}
		if item.value&(3|perlWindowsWriteBits) != 0 {
			t.Errorf("%s = %#x overlaps a write bit", item.name, item.value)
		}
	}
}

// perlGoWindowsFlag is the Go syscall value on Windows of a common flag name:
// the value literal_write_perl_flags.go gives it in a Windows build.
func perlGoWindowsFlag(name string) int {
	switch name {
	case "O_WRONLY":
		return 0x1
	case "O_RDWR":
		return 0x2
	case "O_CREAT":
		return 0x40
	case "O_TRUNC":
		return 0x200
	case "O_APPEND":
		return 0x400
	}
	return 0
}
