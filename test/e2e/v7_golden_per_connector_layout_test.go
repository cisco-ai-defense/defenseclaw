// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"encoding/json"
	"os"
	"testing"
)

// TestGoldenPerConnectorLayout — Plan E3.4 / item 1.
//
// Locks in the per-connector golden directory contract:
//
//  1. testdata/v7/golden/<connector>/ exists for every built-in
//     connector returned by connectorMatrix().
//  2. Each subdir holds at least one well-formed JSON envelope
//     (verdict-blocked.golden.json — chosen as the canonical
//     "always-emitted" event so the matrix is never empty).
//  3. The connector subdirectory layout under
//     `goldenPathForConnector` resolves to a real file (vs.
//     silently falling through to the connector-agnostic
//     baseline).
//
// This is a *layout* test — it does not exercise the contents
// against any production code path. The goal is to fail loudly if
// a future cleanup deletes the subdirectories or renames the
// canonical file, rather than silently regress the connector
// matrix scaffolding.
func TestGoldenPerConnectorLayout(t *testing.T) {
	const canonical = "verdict-blocked.golden.json"

	for _, fx := range connectorMatrix(t) {
		t.Run(fx.Name, func(t *testing.T) {
			p := goldenPathForConnector(t, fx.Name, canonical)
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatalf("missing per-connector golden %s: %v\n"+
					"hint: testdata/v7/golden/%s/ should hold a copy of the canonical "+
					"verdict-blocked envelope so future per-connector matrix tests have "+
					"a non-empty starting point.",
					p, err, fx.Name)
			}
			var probe map[string]any
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("connector=%s: golden %s is not valid JSON: %v",
					fx.Name, canonical, err)
			}
			if et, _ := probe["event_type"].(string); et != "verdict" {
				t.Errorf("connector=%s: golden %s expected event_type=verdict, got %q",
					fx.Name, canonical, et)
			}
		})
	}
}
