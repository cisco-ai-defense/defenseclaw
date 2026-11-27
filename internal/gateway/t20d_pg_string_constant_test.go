// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestT20DPsqlCopyProgramDollarQuote (GAP-1950): psql -c with COPY ...
// TO PROGRAM whose program is a dollar-quoted or escape string raises the
// COPY PROGRAM rule as the plain quoted form does. Red at 279da61428.
func TestT20DPsqlCopyProgramDollarQuote(t *testing.T) {
	for _, command := range []string{
		`psql -d production -c 'COPY t (c) TO PROGRAM $$id$$'`,
		`psql -d production -c 'COPY t (c) TO PROGRAM $run$id$run$'`,
		`psql -d production -c "COPY t (c) TO PROGRAM E'id'"`,
	} {
		for _, pack := range []string{"default", "strict"} {
			r := t20cCodexBash(t, pack, command)
			if r.Action == "allow" || !findingStringHasRuleID(r.Findings, postgreSQLCopyProgramRuleID) {
				t.Errorf("%s %q: action=%s findings=%v, want %s", pack, command, r.Action, r.Findings, postgreSQLCopyProgramRuleID)
			}
		}
	}
}
