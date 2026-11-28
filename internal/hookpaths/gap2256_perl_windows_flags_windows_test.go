// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"slices"
	"testing"
)

// On Windows the sysopen reader proves the write of every Windows Perl flag
// name and MSVC number that asks for one, and of none that reads
// (rel-1-0-10:GAP-2256).
func TestGAP2256WindowsPerlSysopenNative(t *testing.T) {
	for _, item := range perlCommonFlags {
		if item.value != uint64(perlGoWindowsFlag(item.name)) {
			t.Fatalf("%s = %#x, want the Go-Windows value %#x", item.name, item.value, perlGoWindowsFlag(item.name))
		}
	}
	if perlPlatformWriteBits != perlWindowsWriteBits ||
		perlGoWindowsWriteBits != uint64(os.O_CREATE|os.O_TRUNC|os.O_APPEND) {
		t.Fatalf("write bits %#x, Go-Windows %#x", perlPlatformWriteBits, perlGoWindowsWriteBits)
	}
	cases := []struct {
		code  string
		write bool
	}{
		{"use Fcntl; sysopen(F,'p',O_WRONLY|O_NOINHERIT);", true},
		{"use Fcntl; sysopen(F,'p',O_WRONLY|O_CREAT|O_RAW);", true},
		{"use Fcntl; sysopen(F,'p',O_RDONLY|O_TEMPORARY);", true},
		{"use Fcntl; sysopen(F,'p',O_WRONLY|O_RANDOM|O_SEQUENTIAL);", true},
		{"sysopen(F,'p',0x100);", true},
		{"sysopen(F,'p',0x8);", true},
		{"use Fcntl; sysopen(F,'p',O_RDONLY|O_NOINHERIT|O_RAW);", false},
		{"use Fcntl; sysopen(F,'p',O_RDONLY|O_RANDOM);", false},
		{"sysopen(F,'p',0x8000);", false},
	}
	for _, tc := range cases {
		paths := literalInterpreterWrites(tc.code, "perl", `C:\w`, `C:\w`)
		if slices.Contains(paths, "p") != tc.write {
			t.Errorf("%s: paths %v, want write %v", tc.code, paths, tc.write)
		}
	}
}
