// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package gateway

import "github.com/defenseclaw/defenseclaw/internal/useridentity"

// verifyPeerSession has no verified source outside Linux: macOS and Windows
// sessions stay claimed.
func verifyPeerSession(int, string, useridentity.SessionFacts) (useridentity.SessionFacts, bool) {
	return useridentity.SessionFacts{}, false
}
