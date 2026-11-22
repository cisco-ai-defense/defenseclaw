// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package toolshape

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The caps of this reader package, one line each (DET111 step 2, the cap
// registry: bounded.Register, checked by bounded.TestCapRegistry). A new
// max* cap this package compares a count against is added here.
var (
	_ = bounded.Register("toolshape.maxContent", bounded.Items, int(maxContent))
	_ = bounded.Register("toolshape.maxDepth", bounded.Depth, int(maxDepth))
	_ = bounded.Register("toolshape.maxItems", bounded.Items, int(maxItems))
	_ = bounded.Register("toolshape.maxNested", bounded.Depth, int(maxNested))
	_ = bounded.Register("toolshape.maxNodes", bounded.Nodes, int(maxNodes))
	_ = bounded.Register("toolshape.maxPageDefs", bounded.Items, int(maxPageDefs))
	_ = bounded.Register("toolshape.maxPageScript", bounded.Items, int(maxPageScript))
	_ = bounded.Register("toolshape.maxPageSends", bounded.Items, int(maxPageSends))
	_ = bounded.Register("toolshape.maxPageTokens", bounded.Items, int(maxPageTokens))
	_ = bounded.Register("toolshape.maxPath", bounded.Paths, int(maxPath))
	_ = bounded.Register("toolshape.maxString", bounded.Items, int(maxString))
)
