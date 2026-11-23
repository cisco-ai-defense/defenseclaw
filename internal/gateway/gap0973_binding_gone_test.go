// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"net/http"
	"testing"
)

// GAP-0973: an approval of a binding ask whose binding is gone (rm won the
// race) is a 200 that moved nothing; the body says so with binding_gone and
// a message, so the administrator does not read it as a secret gone live.
// An approval that moved a binding carries neither field.
func TestGAP0973ApproveOfAGoneBindingSaysSo(t *testing.T) {
	race := &rmRaceAsks{}
	bf := newBindingFixture(t, func(c *SubstrateConfig) { race.SubstrateAskStore = c.Asks; c.Asks = race })

	code, out := bf.add(t, "p-alice", hardOutsideAdd)
	id, _ := out["ask_id"].(string)
	if code != http.StatusAccepted || id == "" {
		t.Fatalf("add: %d %v", code, out)
	}
	race.after = func() {
		bf.do(t, bf.admin, http.MethodDelete, "/api/v1/substrate/secrets/gl-lab", "p-alice", "")
	}
	decideCode, dout := bf.decide(t, "p-admin", id, "approve")
	if decideCode != http.StatusOK {
		t.Fatalf("approve that won the race with rm: %d %v, want 200", decideCode, dout)
	}
	if dout["binding_gone"] != true {
		t.Errorf("approve of a gone binding: %v, want binding_gone true", dout)
	}
	if m, _ := dout["message"].(string); m == "" {
		t.Errorf("approve of a gone binding: %v, want a message", dout)
	}

	// The same answer again is a replay of an answered ask; it says the same.
	againCode, again := bf.decide(t, "p-admin", id, "approve")
	if againCode != http.StatusOK || again["binding_gone"] != true {
		t.Errorf("replayed approve of a gone binding: %d %v, want 200 and binding_gone", againCode, again)
	}
}

func TestGAP0973ApproveThatMovedTheBindingStaysPlain(t *testing.T) {
	bf := newBindingFixture(t, nil)
	code, out := bf.add(t, "p-alice", hardOutsideAdd)
	id, _ := out["ask_id"].(string)
	if code != http.StatusAccepted || id == "" {
		t.Fatalf("add: %d %v", code, out)
	}
	decideCode, dout := bf.decide(t, "p-admin", id, "approve")
	if decideCode != http.StatusOK {
		t.Fatalf("approve: %d %v", decideCode, dout)
	}
	if _, ok := dout["binding_gone"]; ok {
		t.Errorf("approve that moved the binding says binding_gone: %v", dout)
	}
	if _, ok := dout["message"]; ok {
		t.Errorf("approve that moved the binding carries a message: %v", dout)
	}
}
