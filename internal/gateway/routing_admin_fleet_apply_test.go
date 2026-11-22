// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// apply with no store, with a nil config and again must never panic (it
// once wiped its own held mutex) and leaves no client.
func TestFleetApplyWithoutAStore(t *testing.T) {
	f := &fleetState{}
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{}
	for _, c := range []*config.Config{nil, cfg, cfg, nil} {
		f.apply(c)
		if f.counter() != nil || f.mapper() != nil || f.status() != "" {
			t.Fatal("no store: no client")
		}
	}
	cfg.Routing.Admin.BudgetStore = &config.RoutingBudgetStoreConfig{URL: "https://store.example:8443"}
	f.apply(cfg) // managed only: an OSS config keeps budgets on the device
	if f.counter() != nil {
		t.Fatal("the store is standalone managed only")
	}
	f.apply(nil)
}
