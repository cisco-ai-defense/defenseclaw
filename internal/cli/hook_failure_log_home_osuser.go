// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !linux

package cli

import (
	"os/user"
	"strconv"
)

// hookAccountHome reads uid's home through os/user, which on macOS asks Open
// Directory through libSystem (getpwuid_r) and never reads HOME, so local,
// mobile and directory accounts resolve.
func hookAccountHome(uid int) (string, error) {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return account.HomeDir, nil
}
