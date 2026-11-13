// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package gateway

// FlowHitsSince reports the secret-flow shadow hits a session gained since the last call, as short "kind:action" labels. This build has
// no secret-flow step (it is not in rel/1.0.10), so there is never a hit; the chainbench flow build replaces this file with a reader of
// the session's explain view.
func (e *S7Engine) FlowHitsSince(sessionID string) []string { return nil }
