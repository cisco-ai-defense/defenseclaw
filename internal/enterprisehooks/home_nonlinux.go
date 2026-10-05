//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"syscall"
)

// enokey has no equivalent on this platform.
const enokey = syscall.Errno(0)

// ecryptfsSupported: ecryptfs private homes exist only on Linux.
const ecryptfsSupported = false

// platformMountAt cannot read a mount table here; the lock check then
// never trusts markers and the user-mount check does not apply.
func platformMountAt(string) (unixMount, bool, error) {
	return unixMount{}, false, errors.New("no mount table reader on this platform")
}

func platformLiveSession(int) bool { return false }
