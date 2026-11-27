// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package semantic

import "github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"

// The caps the projection cuts the fact-only sections at (sql_facts, kube),
// reported through FactOnlyCuts (DET111 T20 review P1-1, P3-2). The other
// projection limits fail the projection and are not cuts.
var (
	_ = bounded.Register("semantic.maxSQLFacts", bounded.Items, maxSQLFacts)
	_ = bounded.Register("semantic.maxSQLFactValues", bounded.Items, maxSQLFactValues)
	_ = bounded.Register("semantic.maxSQLFactStatements", bounded.Items, maxSQLFactStatements)
	_ = bounded.Register("semantic.maxKube", bounded.Items, maxKube)
	_ = bounded.Register("semantic.maxScalarBytes", bounded.Bytes, maxScalarBytes)
)
