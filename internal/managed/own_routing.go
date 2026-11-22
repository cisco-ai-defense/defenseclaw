// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "context"

// OwnRouting reads the calling account's own routing decisions or budgets
// (path: /api/v1/routing/effective, budgets or explain/<id>) on the hook
// socket, which the gateway answers for the socket's kernel-verified peer.
// It returns the HTTP status and the JSON answer.
func OwnRouting(ctx context.Context, socket, path string) (int, []byte, error) {
	return getOwnHookRoute(ctx, socket, "http://defenseclaw-hook"+path)
}
