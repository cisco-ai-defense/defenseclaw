// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookpaths

import "golang.org/x/sys/unix"

var perlPlatformFlags = [...]perlFlagConstant{
	{"O_NOFOLLOW", unix.O_NOFOLLOW},
	{"O_NONBLOCK", unix.O_NONBLOCK},
	{"O_NDELAY", unix.O_NDELAY},
	{"O_CLOEXEC", unix.O_CLOEXEC},
	{"O_DIRECTORY", unix.O_DIRECTORY},
	{"O_SYNC", unix.O_SYNC},
	{"O_DSYNC", unix.O_DSYNC},
	{"O_RSYNC", unix.O_RSYNC},
	{"O_LARGEFILE", unix.O_LARGEFILE},
	{"O_NOATIME", unix.O_NOATIME},
	{"O_DIRECT", unix.O_DIRECT},
	{"O_EXCL", unix.O_EXCL},
	{"O_ASYNC", unix.O_ASYNC},
	{"O_NOCTTY", unix.O_NOCTTY},
	{"O_TMPFILE", unix.O_TMPFILE},
	{"O_BINARY", 0},
	{"O_TEXT", 0},
}
