// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/budgetstore"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestFleetKeysCarryNoNames(t *testing.T) {
	keys, err := budgetstore.DeriveKeys(bytes.Repeat([]byte{7}, budgetstore.SecretBytes))
	if err != nil {
		t.Fatal(err)
	}
	f := &fleetState{keys: &keys, users: map[string]string{}, byFleet: map[string]string{}, client: &budgetstore.Client{},
		budgets: []config.RoutingBudget{
			{ID: "daily", Scope: "user", Subject: "*"},
			{ID: "named", Scope: "user", Subject: "alice@dclab.test"},
			{ID: "eng", Scope: "group", Subject: `DCLAB\eng`},
			{ID: "codex", Scope: "connector", Subject: "codex"},
		}}
	f.noteUser("S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001", "alice@dclab.test")
	f.noteUser("2001", "", "") // no directory id: stays on this device
	fleetKey, ok := f.ToFleet("user:daily:*:S-1-5-21-1-2-3-1001")
	if !ok || !budgetstore.ValidKey(fleetKey) {
		t.Fatalf("fleet key %q %v", fleetKey, ok)
	}
	if back, ok := f.FromFleet(fleetKey); !ok || back != "user:daily:*:S-1-5-21-1-2-3-1001" {
		t.Fatalf("round trip %q", back)
	}
	if _, ok := f.ToFleet("user:daily:*:2001"); ok {
		t.Fatal("a user without a directory id must not be sent")
	}
	if _, ok := f.FromFleet("user:daily:*:usomeoneelse"); ok {
		t.Fatal("another device's user has no local form")
	}
	if k, ok := f.ToFleet("connector:codex:codex"); !ok || k != "connector:codex:codex" {
		t.Fatal("connector keys are shared as they are")
	}
	wanted := strings.Join(append(f.Wanted(), fleetKey), " ")
	for _, name := range []string{"alice", "dclab", "eng", "S-1-5", "1001"} {
		if strings.Contains(strings.ToLower(wanted), strings.ToLower(name)) && name != "eng" {
			t.Fatalf("fleet keys %q name %q", wanted, name)
		}
	}
	if strings.Contains(wanted, `DCLAB\eng`) || strings.Contains(wanted, ":eng:"+"DCLAB") {
		t.Fatal("group names never leave the device")
	}
	for _, k := range f.Wanted() {
		if !budgetstore.ValidKey(k) {
			t.Fatalf("wanted key %q is not a store key", k)
		}
	}
}
