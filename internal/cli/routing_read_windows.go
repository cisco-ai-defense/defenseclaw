// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// ownRoutingFetch reads on the own-status pipe; a seam for tests.
var ownRoutingFetch = refusalpipe.OwnRouting

func readOwnRouting(ctx context.Context, path string) (int, []byte, error) {
	return ownRoutingFetch(ctx, path)
}
