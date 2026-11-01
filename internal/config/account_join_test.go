// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

func TestValidateAccountJoin(t *testing.T) {
	soon := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC).Format(time.RFC3339)
	for _, tc := range []struct {
		name string
		c    EnterpriseAccountJoinConfig
		ok   bool
	}{
		{"absent", EnterpriseAccountJoinConfig{}, true},
		{"off", EnterpriseAccountJoinConfig{Mode: "off"}, true},
		{"on", EnterpriseAccountJoinConfig{Mode: "on", Generation: 1}, true},
		{"overlap", EnterpriseAccountJoinConfig{Mode: "on", Generation: 1, NextGeneration: 2, NextNotAfter: soon}, true},
		{"unknown mode", EnterpriseAccountJoinConfig{Mode: "yes", Generation: 1}, false},
		{"on without a generation", EnterpriseAccountJoinConfig{Mode: "on"}, false},
		{"negative generation", EnterpriseAccountJoinConfig{Mode: "on", Generation: -1}, false},
		{"next not above", EnterpriseAccountJoinConfig{Mode: "on", Generation: 2, NextGeneration: 2, NextNotAfter: soon}, false},
		{"next without not_after", EnterpriseAccountJoinConfig{Mode: "on", Generation: 1, NextGeneration: 2}, false},
		{"not_after without next", EnterpriseAccountJoinConfig{Mode: "on", Generation: 1, NextNotAfter: soon}, false},
		{"bad not_after", EnterpriseAccountJoinConfig{Mode: "on", Generation: 1, NextGeneration: 2, NextNotAfter: "next week"}, false},
	} {
		if err := validateAccountJoin(tc.c); (err == nil) != tc.ok {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	if !(EnterpriseAccountJoinConfig{Mode: " on "}).On() || (EnterpriseAccountJoinConfig{}).On() {
		t.Fatal("On")
	}
}

func TestAccountJoinNeedsTheStandaloneProfileAndA107Floor(t *testing.T) {
	cfg := &Config{}
	if keys := cfg.UsesMinProductVersion107Keys(); len(keys) != 0 {
		t.Fatalf("absent: %v", keys)
	}
	cfg.Enterprise.AccountJoin = EnterpriseAccountJoinConfig{Mode: "on", Generation: 1}
	if keys := cfg.UsesMinProductVersion107Keys(); strings.Join(keys, ",") != "enterprise.account_join" {
		t.Fatalf("set: %v", keys)
	}
	if enterpriseBlockEmpty(cfg.Enterprise) {
		t.Fatal("an account_join block is not empty: a Secure Client config that sets it is refused")
	}
}
