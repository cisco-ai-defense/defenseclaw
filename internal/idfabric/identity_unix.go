// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package idfabric

import (
	"os"
	"os/user"
	"strconv"
	"strings"
)

// osIdentity reports the effective UID, which is the join key that survives
// setuid hook impersonation, plus the OS account name when it resolves.
func osIdentity() User {
	out := User{UID: strconv.Itoa(os.Geteuid())}
	if current, err := user.Current(); err == nil && current != nil {
		// Prefer the effective UID already captured; only adopt the lookup's
		// UID when Geteuid produced nothing meaningful.
		if strings.TrimSpace(out.UID) == "" {
			out.UID = strings.TrimSpace(current.Uid)
		}
	}
	return out
}

// osUsername reports the OS account name for the device block.
func osUsername() string {
	if current, err := user.Current(); err == nil && current != nil {
		if name := strings.TrimSpace(current.Username); name != "" {
			return name
		}
	}
	return ""
}
