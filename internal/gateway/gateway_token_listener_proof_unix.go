// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"os"
	"os/user"
	"strconv"
)

// gatewayTokenProofCallerIsSelf reports whether the account on the client
// end of the accepted loopback connection is this gateway's own.
func gatewayTokenProofCallerIsSelf(r *http.Request) bool {
	return userScopedProofCallerMatches(r, strconv.Itoa(os.Geteuid()))
}

// gatewayTokenProofCallerIsAccount reports whether the caller of r runs as
// the named local account (the OpenClaw account of the separate-user layout).
func gatewayTokenProofCallerIsAccount(r *http.Request, account string) bool {
	u, err := user.Lookup(account)
	if err != nil || u.Uid == "" || u.Uid == "0" {
		return false
	}
	return userScopedProofCallerMatches(r, u.Uid)
}
