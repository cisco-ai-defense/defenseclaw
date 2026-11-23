// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"slices"
	"testing"
)

func TestDisabledByBundleRoutingAdmin(t *testing.T) {
	current := []byte(`routing:
  enabled: true
  admin:
    rules:
      - {id: ctr, match: {groups: [c]}, action: deny}
      - {id: local, match: {severity_at_least: HIGH}, allow: [l]}
    budgets:
      - {id: daily, scope: user, subject: "*", period: day, limit_usd: 5, on_exceed: deny}
      - {id: wk, scope: user, subject: "*", period: week, limit_usd: 5, on_exceed: "downgrade:l"}
`)
	cases := []struct {
		name     string
		rendered string
		want     []string
	}{
		{"same policy, higher limit", `routing:
  enabled: true
  admin:
    rules:
      - {id: ctr, match: {groups: [c]}, action: deny}
      - {id: local, match: {severity_at_least: HIGH}, allow: [l]}
    budgets:
      - {id: daily, scope: user, subject: "*", period: day, limit_usd: 50, on_exceed: deny}
      - {id: wk, scope: user, subject: "*", period: week, limit_usd: 5, on_exceed: "downgrade:l"}
`, nil},
		{"weakened under the same ids", `routing:
  enabled: true
  admin:
    rules:
      - {id: ctr, match: {groups: [c]}, allow: [l]}
      - {id: local, match: {severity_at_least: HIGH}, allow: [l]}
    budgets:
      - {id: daily, scope: user, subject: "*", period: day, limit_usd: 5, on_exceed: "downgrade:l"}
      - {id: wk, scope: user, subject: "*", period: week, limit_usd: 5, on_exceed: warn}
`, []string{"routing.admin.budget.daily.deny", "routing.admin.budget.wk.downgrade", "routing.admin.rule.ctr.deny"}},
		{"routing off", "routing:\n  enabled: false\n", []string{
			"routing.admin.budget.daily", "routing.admin.budget.daily.deny", "routing.admin.budget.daily.downgrade",
			"routing.admin.budget.wk", "routing.admin.budget.wk.downgrade",
			"routing.admin.rule.ctr", "routing.admin.rule.ctr.deny", "routing.admin.rule.local"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DisabledByBundle(current, []byte(tc.rendered))
			if err != nil {
				t.Fatal(err)
			}
			var routing []string
			for _, id := range got {
				if len(id) > 14 && id[:14] == "routing.admin." {
					routing = append(routing, id)
				}
			}
			if !slices.Equal(routing, tc.want) {
				t.Fatalf("got %v, want %v", routing, tc.want)
			}
		})
	}
}
