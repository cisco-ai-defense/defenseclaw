// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package semantic

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestT20FactOnlySectionsNeverFailTheProjection (DET111 T20 review P1-1,
// P3-2): an SQL fact or a Kubernetes request past a projection bound is cut
// from the fact-only section and reported by FactOnlyCuts; the projection of
// the rest of the call succeeds. Red at 23ee0d55e2 (ProjectionScalarLimit /
// ProjectionCountLimit for the whole call).
func TestT20FactOnlySectionsNeverFailTheProjection(t *testing.T) {
	long := strings.Repeat("a", maxScalarBytes+1)
	for _, c := range []struct{ name, connection, query string }{
		{"postgresql quoted", "postgresql://db.invalid:5432/production", `COPY "` + long + `" (c) TO PROGRAM 'id'`},
		{"mysql backtick", "mysql://db.invalid:3306/production", "SELECT `" + long + "`(1)"},
		{"sqlserver bracket", "sqlserver://db.invalid:1433?database=production", "SELECT [" + long + "](1)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]string{"connection": c.connection, "database": "production", "query": c.query})
			if err != nil {
				t.Fatal(err)
			}
			facts := actionfacts.Analyze(actionfacts.Input{Tool: "sql_query", Args: raw, CWD: "/repo"})
			projected, code := Project(facts)
			if code != ProjectionOK || projected == nil {
				t.Fatalf("Project = %s, want ok", code)
			}
			if len(facts.SQLFacts) > 0 && !FactOnlyCuts(facts).Has(bounded.Bytes) {
				t.Fatalf("FactOnlyCuts = %v, want the scalar cut", FactOnlyCuts(facts))
			}
		})
	}
	t.Run("counts and kube", func(t *testing.T) {
		facts := actionfacts.Facts{Parse: actionfacts.ParseResult{Status: actionfacts.StatusComplete, Dialect: actionfacts.DialectNone}}
		for range maxSQLFacts + 1 {
			facts.SQLFacts = append(facts.SQLFacts, actionfacts.SQLFact{Functions: []string{long, "ok"}, StatementCount: 1})
		}
		facts.KubeRequests = []actionfacts.KubeRequestFact{{Verb: "get", Resource: "secrets", Name: long}}
		projected, code := Project(facts)
		if code != ProjectionOK {
			t.Fatalf("Project = %s, want ok", code)
		}
		if len(projected.SqlFacts) != maxSQLFacts || len(projected.SqlFacts[0].Functions) != 1 || len(projected.Kube) != 0 {
			t.Fatalf("projection kept %d sql facts, %v functions, %d kube", len(projected.SqlFacts), projected.SqlFacts[0].Functions, len(projected.Kube))
		}
		if cuts := FactOnlyCuts(facts); !cuts.Has(bounded.Items) || !cuts.Has(bounded.Bytes) {
			t.Fatalf("FactOnlyCuts = %v, want items and bytes", cuts)
		}
	})
}
