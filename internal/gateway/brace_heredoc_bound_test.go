// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"
	"testing"
)

// ONE BOUND RULE for the brace budget (rel-1-0-10:GAP-0706): an over-limit
// brace expansion reads as the unknown tier whatever sits before it, a
// here-document handed to a shell or a comment line that spells a here-document
// operator included; only the body of a quoted here-document whose command is
// data-only stays uncounted. Rows are the review probe ids.
func TestBraceBudgetOneBoundAfterHeredocOrComment(t *testing.T) {
	home, cwd := shellProtectedFileHome(t)
	bomb := strings.Repeat("{a,b}", 40)
	tiers := []struct {
		name, posture string
		managed       bool
		strict        bool
	}{
		{"default", "default", false, false},
		{"permissive", "permissive", false, false},
		{"strict", "strict", false, true},
		{"managed", "default", true, false},
		{"managed-strict", "strict", true, true},
	}
	overLimit := []struct{ id, command string }{
		{"J02", "bash <<'EOF'\necho " + bomb + "\nEOF"},
		{"J07", "sh <<'EOF'\n" + bomb + "\nEOF"},
		{"J03", "echo hi # <<'X'\necho " + bomb},
		{"Q10", "# <<'X'\necho " + bomb},
		{"Q02", "echo hi # <<'X'\necho evil >> ~/.ssh/auth{orized_,x}keys " + bomb},
		{"Q06", "bash <<'EOF'\necho evil >> ~/.ssh/auth{orized_,x}keys " + bomb + "\nEOF"},
		{"Q07", "cat <<'EOF' | sh\n" + bomb + "\nEOF"},
	}
	for _, row := range overLimit {
		for _, tier := range tiers {
			t.Run(row.id+"/"+tier.name, func(t *testing.T) {
				action, rules := shellProtectedFileRoute(t, home, cwd, "claudecode", tier.posture, tier.managed, row.command)
				want := "alert"
				if tier.strict {
					want = "block"
				}
				if action != want || !slices.Contains(rules, "ACTION-COMPOUND-LIMIT") {
					t.Fatalf("%s %s = %s %v, want %s with ACTION-COMPOUND-LIMIT", row.id, tier.name, action, rules, want)
				}
			})
		}
	}
	// The benign twin a careful developer runs: a script of data sent to
	// python3 stays outside the brace budget in every tier.
	for _, tier := range tiers {
		t.Run("J01/"+tier.name, func(t *testing.T) {
			_, rules := shellProtectedFileRoute(t, home, cwd, "claudecode", tier.posture, tier.managed,
				"python3 - <<'PY'\nx = 1 # "+bomb+"\nPY")
			if slices.Contains(rules, "ACTION-COMPOUND-LIMIT") {
				t.Fatalf("J01 %s raised ACTION-COMPOUND-LIMIT: %v", tier.name, rules)
			}
		})
	}
}
