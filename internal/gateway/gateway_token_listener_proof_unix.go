// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"os"
	"strconv"
)

// gatewayTokenProofCallerIsSelf reports whether the account on the client
// end of the accepted loopback connection is this gateway's own.
func gatewayTokenProofCallerIsSelf(r *http.Request) bool {
	return userScopedProofCallerMatches(r, strconv.Itoa(os.Geteuid()))
}
