//go:build !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os/user"
	"strconv"
)

func kernelBlockUIDName(uid int) string {
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return ""
	}
	return account.Username
}
