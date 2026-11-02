// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

// PerUserGatewayStartInProgress is false on Windows: its per-user hooks are
// the native runner, which does not run hook-post.
func PerUserGatewayStartInProgress(string) bool { return false }

// PerUserGatewayRestartProven is false on Windows.
func PerUserGatewayRestartProven(string, *PerUserPeerRecord) bool { return false }

// PerUserGatewayRestartProvenDuringCall is unused by Windows hooks.
func PerUserGatewayRestartProvenDuringCall(string, *PerUserPeerRecord, bool) bool { return false }
