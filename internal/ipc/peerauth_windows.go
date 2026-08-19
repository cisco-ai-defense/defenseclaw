// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ipc

import (
	"net"
)

// KindUnixPeer mirrors the unix constant so cross-platform code can
// reference the value unconditionally. On Windows nothing ever
// assigns this string because the initial-cut peer-auth stub
// (extractPeerIdentity below) always returns
// KindUnixPeerUnauthenticated instead.
const KindUnixPeer = "UnixPeer"

// KindUnixPeerUnauthenticated is the peerIdentity.Kind value the
// Windows accept path unconditionally reports for the initial-cut
// deferred-auth posture (spec 004, docs/specs/004-windows-ui-ipc/).
// The socket-file DACL is the only access boundary in this posture;
// full peer-auth (DACL pinning to a Cisco Secure Client GUI
// principal, or PID + WinVerifyTrust) lands in a follow-up spec per
// parity-plan §4.4. Kept in sync with the same constant in
// peerauth_unix.go (linux + darwin) so tests reading the value
// don't need build-tag gymnastics.
//
// The GA release-gate at internal/ipc/authposture_gagate.go refuses
// a release-candidate build in which this Kind is still reachable
// (spec 004 REQ-18 + REQ-19).
const KindUnixPeerUnauthenticated = "UnixPeerUnauthenticated"

// peerIdentity mirrors the unix shape so cross-platform callers can
// reference the type unconditionally. On Windows Kind reads
// KindUnixPeerUnauthenticated; the codesign-related fields stay
// zero because the initial-cut posture does no peer verification.
type peerIdentity struct {
	Kind      string
	PID       int32
	UID       uint32
	GID       uint32
	ExePath   string
	TeamID    string
	SigningID string
	BundleID  string
}

// extractPeerIdentity is the initial-cut Windows peer-auth stub —
// every accept succeeds unconditionally with Kind =
// KindUnixPeerUnauthenticated. Access to the UDS is bounded by the
// socket-file DACL applied at bind time (four ACEs; see
// internal/ipc/acl_windows.go), NOT by anything in this function.
//
// The full peer-auth follow-up (parity-plan §4.4) will replace this
// stub with either a DACL-pinned Cisco Secure Client GUI principal
// check or a PID-in-first-message + WinVerifyTrust flow, depending
// on which mechanism the packaging team selects. Until that lands,
// the GA release-gate build tag guards the shipping surface.
func extractPeerIdentity(c net.Conn) (peerIdentity, error) {
	_ = c // reserved for the auth follow-up
	return peerIdentity{Kind: KindUnixPeerUnauthenticated}, nil
}

// newCodesignValidatingListener is a stub on Windows — the initial-
// cut posture does no accept-time codesign validation. Returns the
// inner listener verbatim so the gRPC server accepts every peer that
// the socket-file DACL admits. The parameters are accepted (but
// ignored) to keep the cross-platform signature aligned with the
// darwin implementation at internal/ipc/peerauth_unix.go.
func newCodesignValidatingListener(
	inner net.Listener,
	teamIDs, signingIDs, bundleIDs []string,
	requireUnixPeer, requireSigningMetadata bool,
	logReject func(peerIdentity, string),
) net.Listener {
	return inner
}

