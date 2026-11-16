// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "context"

// OwnStatusPath is the hook-socket route on which a standard user of a
// managed computer reads their own protection state: whether the
// organization's Claude Code policy covers their Claude Code and Claude
// Cowork sessions, and their own last Cowork event (cowork-1-0-8 GAP-0053).
// The gateway answers for the socket's kernel-verified peer and nobody else:
// users see only their own state, never other accounts' or the
// administrator's configuration.
const OwnStatusPath = "/api/v1/managed/own-status"

// OwnStatus asks the gateway on the hook socket for the calling account's
// own protection state. It returns the HTTP status and the JSON answer.
func OwnStatus(ctx context.Context, socket string) (int, []byte, error) {
	return getOwnHookRoute(ctx, socket, "http://defenseclaw-hook"+OwnStatusPath)
}
