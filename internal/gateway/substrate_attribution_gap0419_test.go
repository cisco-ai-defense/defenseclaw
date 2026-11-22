// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0419: the actor list says whom each agent is attributed to, and marks
// one made outside DefenseClaw (attributed to its atespace only) foreign.
func TestSubstrateListMarksForeignActorsGAP0419(t *testing.T) {
	f := newSubstrateFixture(t)
	if err := f.regs.Put(context.Background(), registry.Registration{Atespace: "l5-other", Name: "direct-1",
		UID: "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4d", Connector: "claudecode", Attributed: true}); err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors?all=1", "p-admin", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Actors []map[string]any `json:"actors"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, a := range out.Actors {
		name, _ := a["name"].(string)
		want, foreign := "person", false
		if name == "direct-1" {
			want, foreign = "atespace", true
		}
		if a["attribution"] != want || a["foreign"] != foreign {
			t.Errorf("%s: attribution %v foreign %v, want %s %v", name, a["attribution"], a["foreign"], want, foreign)
		}
		seen[name] = true
	}
	if !seen["direct-1"] || !seen["alice-1"] {
		t.Fatalf("list %v", out.Actors)
	}
}
