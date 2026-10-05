// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"strings"
	"syscall"
)

// isAPIPortHeldByAnotherAccount reports the bind failure Windows returns when
// another account holds the port on the wildcard address (0.0.0.0 or [::]):
// WSAEACCES (10013), "An attempt was made to access a socket in a way
// forbidden by its access permissions", rather than WSAEADDRINUSE. Windows
// lets only LocalSystem bind a specific address under another account's
// wildcard listener, and the gateway runs as its own service account.
func isAPIPortHeldByAnotherAccount(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.WSAEACCES) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "forbidden by its access permissions")
}
