// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"strconv"
)

// The proof route is reachable over TCP on Unix too. Bind its answer to the
// UID that opened the accepted connection, just as bearer authentication
// does; a second account must not relay a protected user's challenge.
var userScopedProofCallerIdentity = func(r *http.Request) (string, error) {
	uid, err := acpLoopbackPeerUID(r)
	if err != nil || uid < 0 {
		return "", err
	}
	return strconv.Itoa(uid), nil
}

func userScopedProofCallerMatches(r *http.Request, identity string) bool {
	if identity == "" {
		return false
	}
	got, err := userScopedProofCallerIdentity(r)
	return err == nil && got == identity
}
