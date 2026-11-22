// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"net/http"

	"golang.org/x/sys/windows"
)

// gatewayProcessSID is the SID of the account this gateway runs as (the
// token user of the process); tests replace it.
var gatewayProcessSID = func() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	if user == nil || user.User.Sid == nil {
		return "", errors.New("current token user is unavailable")
	}
	sid := user.User.Sid
	// A per-user OpenClaw runs as its user, never as a service account, so a
	// gateway running as one answers no OpenClaw proof (managed Windows is
	// refused for OpenClaw in this release).
	for _, wk := range []windows.WELL_KNOWN_SID_TYPE{windows.WinLocalSystemSid, windows.WinLocalServiceSid, windows.WinNetworkServiceSid} {
		if sid.IsWellKnown(wk) {
			return "", errors.New("gateway runs as a service account")
		}
	}
	return sid.String(), nil
}

// gatewayTokenProofCallerIsSelf reports whether the account on the client
// end of the accepted loopback connection is the account of this gateway:
// the SID of the process that owns the client socket (userScopedProofCallerSID,
// from the kernel TCP table) must be the token user of this process. The
// per-user OpenClaw plugin runs as the same account as the per-user gateway,
// so another account cannot relay a challenge to this gateway from a port it
// squats (DESIGN-REVIEW-1 P1-2).
func gatewayTokenProofCallerIsSelf(r *http.Request) bool {
	self, err := gatewayProcessSID()
	return err == nil && userScopedProofCallerMatches(r, self)
}

// gatewayTokenProofCallerIsAccount: the separate-user layout is Linux and
// macOS only in 1.0.10.
func gatewayTokenProofCallerIsAccount(*http.Request, string) bool { return false }
