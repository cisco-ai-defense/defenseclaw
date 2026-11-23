// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"
)

// TestT20BPackColumnKeepsBuiltinInvariants (DET111 T19 review P3-1, P3-2;
// T20 P3-5, P3-6): a pack tiers.yaml could set a shadow-only effect row
// (effect-read) to alert, which Decide would enforce while ShadowOnly kept
// the finding out of the call; change a row severity the verdict severity
// does not read; or record and allow a hard floor (evaluation-fault,
// truncated). Such a column is now refused at load with a clear error, so
// ShadowOnly and the verdict severity (the built-in table) and Decide (the
// pack table) give one answer. A raise of a hard floor still loads. Red at
// 06f1da5b94.
func TestT20BPackColumnKeepsBuiltinInvariants(t *testing.T) {
	refused := map[string]string{
		"shadow-row-on":        "version: 1\ntier: default\nrows:\n  - id: effect-read\n    per_user: {floor: alert}\n    managed: {floor: alert}\n",
		"fault-recorded":       "version: 1\ntier: default\nrows:\n  - id: evaluation-fault\n    per_user: {floor: allow, ceiling: record}\n    managed: {floor: allow, ceiling: record}\n",
		"truncated-strict-low": "version: 1\ntier: strict\nrows:\n  - id: truncated\n    per_user: {floor: allow, severity: MEDIUM}\n    managed: {floor: allow, severity: MEDIUM}\n",
		"severity-change":      "version: 1\ntier: default\nrows:\n  - id: truncated\n    per_user: {floor: alert, levels: false, severity: HIGH}\n    managed: {floor: alert, levels: false, severity: HIGH}\n",
	}
	for name, column := range refused {
		if _, err := ParseColumn([]byte(column)); err == nil || !strings.Contains(err.Error(), "tiers.yaml: row") {
			t.Errorf("%s: ParseColumn err = %v, want a refusal naming the row", name, err)
		}
	}
	for _, tier := range []Tier{TierDefault, TierPermissive, TierStrict} {
		raw, err := MarshalColumn(Builtin().ColumnOf(tier))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseColumn(raw); err != nil {
			t.Errorf("built-in %v column refused: %v", tier, err)
		}
	}
	raise := "version: 1\ntier: default\nrows:\n  - id: state-write\n    per_user: {floor: block}\n    managed: {floor: block}\n"
	if _, err := ParseColumn([]byte(raise)); err != nil && !strings.Contains(err.Error(), "severity") {
		t.Errorf("raise of state-write refused: %v", err)
	}
}
