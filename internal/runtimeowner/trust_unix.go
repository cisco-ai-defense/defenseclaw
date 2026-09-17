//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package runtimeowner centralizes Unix ownership trust for private runtime state.
package runtimeowner

import (
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Trusted reports whether uid belongs to root, the active process identity, or
// an account-verified sudo invoker. Running as root alone never makes an
// arbitrary local UID trusted.
func Trusted(uid uint32) bool {
	return trusted(uid, os.Geteuid(), os.Getuid(), os.Getenv, user.Lookup)
}

func trusted(
	uid uint32,
	effectiveUID int,
	realUID int,
	getenv func(string) string,
	lookup func(string) (*user.User, error),
) bool {
	if uid == 0 || int(uid) == effectiveUID {
		return true
	}
	if effectiveUID != 0 {
		return false
	}
	if realUID > 0 && int(uid) == realUID {
		return true
	}
	sudoUID, ok := validatedSudoUID(getenv, lookup)
	return ok && uid == sudoUID
}

func validatedSudoUID(
	getenv func(string) string,
	lookup func(string) (*user.User, error),
) (uint32, bool) {
	rawUID := strings.TrimSpace(getenv("SUDO_UID"))
	rawGID := strings.TrimSpace(getenv("SUDO_GID"))
	name := strings.TrimSpace(getenv("SUDO_USER"))
	if rawUID == "" || rawGID == "" || name == "" {
		return 0, false
	}
	uid, err := strconv.ParseUint(rawUID, 10, 32)
	if err != nil || uid == 0 || strconv.FormatUint(uid, 10) != rawUID {
		return 0, false
	}
	gid, err := strconv.ParseUint(rawGID, 10, 32)
	if err != nil || strconv.FormatUint(gid, 10) != rawGID {
		return 0, false
	}
	account, err := lookup(name)
	if err != nil || account == nil || account.Uid != rawUID || account.Gid != rawGID {
		return 0, false
	}
	return uint32(uid), true
}
