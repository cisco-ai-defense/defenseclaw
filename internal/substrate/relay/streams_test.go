// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// TestStreamRoutesAreAttachRoutes (S2b): the gateway passes port and mcp
// through, a route name is its kit stream name, and there is no editor
// route.
func TestStreamRoutesAreAttachRoutes(t *testing.T) {
	if !slices.Contains(AttachRoutes, RoutePort) || !slices.Contains(AttachRoutes, RouteMCP) {
		t.Fatalf("AttachRoutes %v", AttachRoutes)
	}
	if RoutePort != kit.StreamPort || RouteMCP != kit.StreamMCP {
		t.Fatal("a stream route must be named as its kit stream")
	}
	if slices.Contains(AttachRoutes, "code") {
		t.Fatal("no editor route")
	}
}
