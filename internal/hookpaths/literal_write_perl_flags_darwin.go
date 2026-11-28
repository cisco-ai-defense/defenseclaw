// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookpaths

import (
	"os"

	"golang.org/x/sys/unix"
)

// perlPlatformWriteBits are the open flag bits beyond the access mode that
// change the path.
const perlPlatformWriteBits = uint64(os.O_CREATE | os.O_TRUNC | os.O_APPEND)

var perlPlatformFlags = [...]perlFlagConstant{
	{"O_NOFOLLOW", unix.O_NOFOLLOW},
	{"O_NONBLOCK", unix.O_NONBLOCK},
	{"O_CLOEXEC", unix.O_CLOEXEC},
	{"O_DIRECTORY", unix.O_DIRECTORY},
	{"O_SYNC", unix.O_SYNC},
	{"O_EXCL", unix.O_EXCL},
	{"O_NOCTTY", unix.O_NOCTTY},
	{"O_SHLOCK", unix.O_SHLOCK},
	{"O_EXLOCK", unix.O_EXLOCK},
	{"O_EVTONLY", unix.O_EVTONLY},
	{"O_BINARY", 0},
	{"O_TEXT", 0},
}
