// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

func TestDoctorBudgetsRow(t *testing.T) {
	spent := 3.0
	cases := []struct {
		name   string
		u      api.UsageAnswer
		err    error
		status string
		ok     bool
	}{
		{"all priced", api.UsageAnswer{Rows: []api.UsageRow{{UsageCalls: 4, CostCalls: 4}}, Budgets: []api.UsageBudget{{ID: "a", SpentUSD: &spent}}}, nil, doctorOK, true},
		{"unpriced calls", api.UsageAnswer{Rows: []api.UsageRow{{UsageCalls: 4, CostCalls: 1}}}, nil, doctorWarn, true},
		{"spend unknown", api.UsageAnswer{Budgets: []api.UsageBudget{{ID: "a"}}}, nil, doctorWarn, true},
		{"leader down", api.UsageAnswer{}, &api.Error{Status: http.StatusServiceUnavailable, Reason: "usage_unavailable"}, doctorWarn, true},
		{"usage off", api.UsageAnswer{}, &api.Error{Status: http.StatusNotImplemented, Reason: "usage_disabled"}, doctorSkip, true},
		{"network error", api.UsageAnswer{}, errors.New("dial"), "", false},
	}
	for _, c := range cases {
		got, ok := doctorBudgetsRow(c.u, c.err)
		if ok != c.ok || got.Status != c.status {
			t.Errorf("%s: status %q ok %v, want %q %v (%s)", c.name, got.Status, ok, c.status, c.ok, got.Summary)
		}
	}
}
