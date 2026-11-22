// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effectrules

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The caps of this reader package, one line each (DET111 step 2, the cap
// registry: bounded.Register, checked by bounded.TestCapRegistry). A new
// max* cap this package compares a count against is added here.
var (
	_ = bounded.Register("effectrules.maxIdentityStats", bounded.Paths, maxIdentityStats)
)
