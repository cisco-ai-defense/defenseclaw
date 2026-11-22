// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ownRoutingFetch reads on the hook socket; a seam for tests.
var ownRoutingFetch = managed.OwnRouting

func readOwnRouting(ctx context.Context, path string) (int, []byte, error) {
	socket := ownProfileExplainSocket()
	if socket == "" {
		return 0, nil, errors.New("this computer is not managed, or the managed gateway's hook socket is not available")
	}
	return ownRoutingFetch(ctx, socket, path)
}
