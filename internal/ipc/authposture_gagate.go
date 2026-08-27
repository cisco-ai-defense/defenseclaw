// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ga

package ipc

// authpostureGAGateOK is the compile-time gate spec 004 REQ-18 / REQ-19
// require. A release-candidate build compiles with `-tags ga`; every
// production build path invokes `go build -tags ga` per the release
// runbook. The build MUST fail (non-zero exit from `go build`) when
// the unauthenticated Windows peer-auth code path is still reachable
// — that's the GA guard-rail keeping the initial-cut deferred-auth
// posture from silently shipping.
//
// The gate is implemented as a compile-time reference to the symbol
// authpostureGAApproved, defined ONLY in the follow-up spec's file
// that lands the real peer-auth mechanism. Until that spec lands,
// `go build -tags ga` fails with a compile error (typically
// "undefined: authpostureGAApproved"); `go build` (no tag) succeeds
// normally because this file is excluded by //go:build ga.
//
// The CI job in .github/workflows/windows-enterprise-setup.yml
// asserts the PRIMARY invariant — `go build -tags ga` exits non-
// zero — and emits the "authpostureGAApproved"-in-stderr check as
// a diagnostic hint only. This shape refuses three bypass attempts:
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
//     unauthenticated posture. See CR
//     spec-004:PRRT_kwDORuAK-s6aoCwI. The follow-up spec's OWN
//     release-time assertion on the reported peer-auth kind is
//     the control that catches this case; this file's role is
//     item 1's rename-refusal only.
//  3. Delete only the `var _ = ...` line and keep this comment-
//     only file. `go build -tags ga` then succeeds for this
//     package in isolation, but the follow-up spec's peer-auth
//     logic ALSO won't be present, so the eventual daemon behaves
//     identically to a pre-spec-004 pre-cut build — which is
//     caught by the follow-up spec's OWN release-time assertion
//     that the daemon reports a legitimate peer-auth kind, not
//     by this file. This bypass is degenerate: it removes the
//     gate but does NOT remove the underlying unauthenticated
//     posture; the follow-up spec's peer-auth landing IS the
//     point at which "UnixPeerUnauthenticated" stops being
//     reachable at runtime.
//
// See parity-plan §4.4 for the follow-up spec that defines
// authpostureGAApproved and lands the real peer-auth mechanism.
// See CR spec-004:PRRT_kwDORuAK-s6ankzo for the primary/diagnostic
// split.
var _ = authpostureGAApproved
