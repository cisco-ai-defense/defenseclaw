// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ga

package ipc

// authpostureGAGateOK is the GA compile-time release gate. A release-candidate build compiles with `-tags ga`; every
// production build path invokes `go build -tags ga` per the release
// runbook. The build MUST fail (non-zero exit from `go build`) when
// the unauthenticated Windows peer-auth code path is still reachable
// — that's the GA guard-rail keeping the initial-cut deferred-auth
// posture from silently shipping.
//
// The gate is implemented as a compile-time reference to the symbol
// authpostureGAApproved, defined ONLY in the follow-up change's file
// that lands the real peer-auth mechanism. Until that change lands,
// `go build -tags ga` fails with a compile error (typically
// "undefined: authpostureGAApproved"); `go build` (no tag) succeeds
// normally because this file is excluded by //go:build ga.
//
// The enterprise-setup-contracts job in .github/workflows/ci.yml (pull
// requests to main) and .github/workflows/windows-enterprise-setup.yml
// assert that `go build -tags ga` exits non-zero AND that the error
// names this file and authpostureGAApproved, so an unrelated compile
// or dependency failure cannot pass for the gate. This shape refuses
// three bypass attempts:
//
//  1. Rename the "UnixPeerUnauthenticated" const literal to look
//     benign. The gate does not compare strings — it looks for an
//     approval SYMBOL that only the auth follow-up defines.
//  2. Drop this file entirely. This does NOT keep the gate on:
//     the `ga` tag is ADDITIVE, so every other .go file in
//     internal/ipc (none of them //go:build-ga-constrained) still
//     compiles under `go build -tags ga`, and the build passes.
//     This is the same degenerate bypass as item 3 below — it
//     removes the gate WITHOUT removing the underlying
//     unauthenticated posture. The follow-up change's OWN
//     release-time assertion on the reported peer-auth kind is
//     the control that catches this case; this file's role is
//     item 1's rename-refusal only.
//  3. Delete only the `var _ = ...` line and keep this comment-
//     only file. `go build -tags ga` then succeeds for this
//     package in isolation, but the follow-up change's peer-auth
//     logic ALSO won't be present, so the eventual daemon behaves
//     identically to a build from before the deferred-auth cut — which is
//     caught by the follow-up change's OWN release-time assertion
//     that the daemon reports a legitimate peer-auth kind, not
//     by this file. This bypass is degenerate: it removes the
//     gate but does NOT remove the underlying unauthenticated
//     posture; the follow-up change's peer-auth landing IS the
//     point at which "UnixPeerUnauthenticated" stops being
//     reachable at runtime.
var _ = authpostureGAApproved
