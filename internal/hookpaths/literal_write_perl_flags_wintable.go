// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strconv"
	"strings"
)

// perlWindowsFlags are the platform Fcntl names of a Windows Perl, beyond the
// six common ones. Only the Windows build reads sysopen with them; they are
// not build-tagged so their reading is tested on every platform
// (rel-1-0-10:GAP-2256).
//
// The modifiers are symbolic: their bits (1<<40 up, in the order of
// perlWindowsFlagSpec) are clear of the access mode and of every write
// bit, so only O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND establish a write and
// a modifier can accompany a proved write whether or not the Perl build
// defines an OS flag of that name. O_NOINHERIT, O_RAW, O_RANDOM and
// O_SEQUENTIAL are MSVC-only names of Strawberry Perl and ActivePerl, as is
// O_TEMPORARY, which has its MSVC value 0x40: it deletes the file when it is
// closed, a change to the path, and 0x40 is a write bit. The names are one
// spec string (NAME, or NAME=VALUE for a fixed value): the package literal
// sweep (TestGAP0749) reads every word literal of the package.
const perlWindowsFlagSpec = "O_NOFOLLOW O_NONBLOCK O_NDELAY O_CLOEXEC O_DIRECTORY O_SYNC O_DSYNC " +
	"O_RSYNC O_LARGEFILE O_NOATIME O_DIRECT O_EXCL O_ASYNC O_NOCTTY O_TMPFILE O_BINARY O_TEXT " +
	"O_NOINHERIT O_RAW O_RANDOM O_SEQUENTIAL O_TEMPORARY=0x40"

var perlWindowsFlags = func() []perlFlagConstant {
	var flags []perlFlagConstant
	for i, item := range strings.Fields(perlWindowsFlagSpec) {
		name, fixed, found := strings.Cut(item, "=")
		value := uint64(1) << (40 + i)
		if found {
			value, _ = strconv.ParseUint(fixed, 0, 64)
		}
		flags = append(flags, perlFlagConstant{name, value})
	}
	return flags
}()

// A raw sysopen number on Windows is read with every value a Windows Perl may
// give it, so a number that asks for a write under any of them is a write:
// the Go-Windows syscall values the named common flags have here (O_CREAT
// 0x40, O_TRUNC 0x200, O_APPEND 0x400), MSVC (Strawberry Perl, ActivePerl:
// _O_APPEND 0x8, _O_TEMPORARY 0x40, _O_CREAT 0x100, _O_TRUNC 0x200) and
// Cygwin/MSYS Perl (O_APPEND 0x8, O_CREAT 0x200, O_TRUNC 0x400).
const (
	perlGoWindowsWriteBits = 0x40 | 0x200 | 0x400
	perlMSVCWriteBits      = 0x8 | 0x40 | 0x100 | 0x200
	perlMSYSWriteBits      = 0x8 | 0x200 | 0x400
	perlWindowsWriteBits   = perlGoWindowsWriteBits | perlMSVCWriteBits | perlMSYSWriteBits
)
