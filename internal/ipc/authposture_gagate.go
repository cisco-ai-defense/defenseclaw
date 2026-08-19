// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ga

package ipc

// authpostureGAGateOK is the compile-time gate spec 004 REQ-18 / REQ-19
// require. A release-candidate build compiles with `-tags ga`; every
// production build path (cmd/defenseclaw, cmd/defenseclaw-enterprise-setup,
// packaging artefacts) invokes `go build -tags ga` per the release
// runbook. The build MUST fail to link when the unauthenticated Windows
// peer-auth code path is still reachable — that's the GA guard-rail
// keeping the initial-cut deferred-auth posture from silently shipping.
//
// The gate is implemented as a compile-time reference to the symbol
// authpostureGAApproved, defined ONLY in the follow-up spec's file
// (authposture_gagate_approved.go) that lands the real peer-auth
// mechanism. Until that spec lands:
//
//   go build -tags ga        →  fails with:
//     undefined: authpostureGAApproved
//
//   go build (no tag)        →  succeeds normally (the file below is
//     excluded by //go:build ga).
//
// The pattern refuses the two obvious bypass attempts:
//
//   1. Rename the "UnixPeerUnauthenticated" const literal to look
//      benign. The gate does not compare strings — it looks for an
//      approval SYMBOL that only the auth follow-up defines. Renaming
//      a string does not create the symbol.
//   2. Drop this file. The release CI job runs `go build -tags ga`
//      and asserts a specific compile-error signature ("undefined:
//      authpostureGAApproved"). A missing gate file falls to a
//      DIFFERENT error signature ("no Go files"), which the job also
//      rejects. So the guard-rail catches both "posture snuck through"
//      and "guard was disabled".
//
// See parity-plan §4.4 for the follow-up spec that lands the real
// peer-auth mechanism and defines authpostureGAApproved.
var _ = authpostureGAApproved
