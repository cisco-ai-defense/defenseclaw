// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

// These named Perl modifiers are symbolic on Windows. Keep their bits clear of
// the Go write-mode flags: only O_WRONLY/O_RDWR/O_CREAT/O_TRUNC/O_APPEND
// establish a write. The modifiers can accompany a proved write without
// depending on whether the Windows Perl build exposes an OS flag of that name.
var perlPlatformFlags = [...]perlFlagConstant{
	{"O_NOFOLLOW", 1 << 40},
	{"O_NONBLOCK", 1 << 41},
	{"O_NDELAY", 1 << 42},
	{"O_CLOEXEC", 1 << 43},
	{"O_DIRECTORY", 1 << 44},
	{"O_SYNC", 1 << 45},
	{"O_DSYNC", 1 << 46},
	{"O_RSYNC", 1 << 47},
	{"O_LARGEFILE", 1 << 48},
	{"O_NOATIME", 1 << 49},
	{"O_DIRECT", 1 << 50},
	{"O_EXCL", 1 << 51},
	{"O_ASYNC", 1 << 52},
	{"O_NOCTTY", 1 << 53},
	{"O_TMPFILE", 1 << 54},
	{"O_BINARY", 1 << 55},
	{"O_TEXT", 1 << 56},
}
