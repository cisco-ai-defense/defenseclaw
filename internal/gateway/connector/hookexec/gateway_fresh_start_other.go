// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package hookexec

// PerUserGatewayFreshStartNoAnswer is limited to the Linux per-user hook.
func PerUserGatewayFreshStartNoAnswer(string, *PerUserPeerRecord) bool { return false }
