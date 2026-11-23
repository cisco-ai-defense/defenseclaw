// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The caps of this reader package, one line each (DET111 step 2, the cap
// registry: bounded.Register, checked by bounded.TestCapRegistry). A new
// max* cap this package compares a count against is added here.
var (
	_ = bounded.Register("psparse.maxDepth", bounded.Depth, int(maxDepth))
	_ = bounded.Register("psparse.maxInput", bounded.Items, int(maxInput))
	_ = bounded.Register("psparse.maxPortNesting", bounded.Depth, maxPortNesting)
)
