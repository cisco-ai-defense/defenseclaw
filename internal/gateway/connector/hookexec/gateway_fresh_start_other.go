// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hookexec

// PerUserGatewayFreshStartNoAnswer is limited to the Linux per-user hook.
func PerUserGatewayFreshStartNoAnswer(string, *PerUserPeerRecord) (bool, string) {
	return false, "not_fresh"
}

// PerUserGatewayRecordLocalAnswer has no fresh-start window on other platforms.
func PerUserGatewayRecordLocalAnswer(string) error { return nil }

// PerUserGatewayRecordObservedAnswer has no fresh-start window on other platforms.
func PerUserGatewayRecordObservedAnswer(string, *PerUserPeerRecord) {}

// perUserGatewayRecentlyStarted has no fresh-start window on other platforms.
func perUserGatewayRecentlyStarted(string) bool { return false }

func perUserFreshGatewayProof(string, *perUserPeerCheck) restartProofResult {
	return restartProofResult{reason: "not_fresh"}
}

func perUserCaptureFreshGatewayOwner(string, *perUserPeerCheck) {}
