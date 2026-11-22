// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The caps of this reader package, one line each (DET111 step 2, the cap
// registry: bounded.Register, checked by bounded.TestCapRegistry). A new
// max* cap this package compares a count against is added here.
var (
	_ = bounded.Register("effects.maxBraceWords", bounded.Items, int(maxBraceWords))
	_ = bounded.Register("effects.maxCodeLiterals", bounded.Items, int(maxCodeLiterals))
	_ = bounded.Register("effects.maxCWDBytes", bounded.Bytes, int(maxCWDBytes))
	_ = bounded.Register("effects.maxCWDCandidates", bounded.Items, int(maxCWDCandidates))
	_ = bounded.Register("effects.maxDataText", bounded.Bytes, int(maxDataText))
	_ = bounded.Register("effects.maxFileBodies", bounded.Items, int(maxFileBodies))
	_ = bounded.Register("effects.maxGrammarSource", bounded.Items, int(maxGrammarSource))
	_ = bounded.Register("effects.maxMCPDepth", bounded.Depth, int(maxMCPDepth))
	_ = bounded.Register("effects.maxMCPNodes", bounded.Nodes, int(maxMCPNodes))
	_ = bounded.Register("effects.maxNestedDepth", bounded.Depth, int(maxNestedDepth))
	_ = bounded.Register("effects.maxSpellingBytes", bounded.Bytes, int(maxSpellingBytes))
	_ = bounded.Register("effects.maxStageSources", bounded.Items, int(maxStageSources))
)
