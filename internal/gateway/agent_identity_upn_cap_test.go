// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
)

// W19 review (loop round 2): the recorder orders UPN sightings past the
// agentIdentityRecorderMaxPending identities it tracks. A new identity past
// the cap keeps its newest sighting, and an identity whose newest sighting
// was dropped never takes a sighting that may be older than it: the row
// lists no UPN until a newer read.
func TestAgentIdentityUPNOrderHoldsPastTheTrackedCap(t *testing.T) {
	const oldUPN, newUPN, newerUPN = "dcad-old@dclab.test", "dcad-new@dclab.test", "dcad-newer@dclab.test"
	const id = "aid-past-the-cap"
	setup := func(t *testing.T) *agentIdentityRecorder {
		t.Helper()
		return &agentIdentityRecorder{pending: map[string]*inventory.AgentIdentityRecord{}, hints: map[string]string{}}
	}
	// fill tracks other identities up to the cap, read from..from+n-1.
	fill := func(r *agentIdentityRecorder, from uint64) {
		if r.upns == nil {
			r.upns = map[string]agentIdentityUPN{}
		}
		for i := uint64(0); len(r.upns) < agentIdentityRecorderMaxPending; i++ {
			r.upns[fmt.Sprintf("aid-other-%d", from+i)] = agentIdentityUPN{read: from + i, upn: "other@dclab.test"}
		}
	}
	sight := func(r *agentIdentityRecorder, agentID string, read uint64, upn string) {
		r.observe(agentIdentityFacts{ID: agentID, UserID: "1001", Connector: "codex", MachineHash: "machine",
			UserUPN: upn, UPNRead: read}, "", false)
	}
	check := func(t *testing.T, r *agentIdentityRecorder, step, want string) {
		t.Helper()
		rec := r.pending[id]
		if rec == nil {
			t.Fatalf("%s: no buffered row", step)
		}
		if rec.UPN != want || rec.UPNUnavailable != (want == "") {
			t.Fatalf("%s: row UPN %q (unavailable %t); want %q", step, rec.UPN, rec.UPNUnavailable, want)
		}
		if len(r.upns) > agentIdentityRecorderMaxPending {
			t.Fatalf("%s: %d sightings tracked, past the cap", step, len(r.upns))
		}
	}

	t.Run("an older read of a new identity arrives after a newer one", func(t *testing.T) {
		r := setup(t)
		fill(r, 1000)
		sight(r, id, 9001, newUPN)
		sight(r, id, 9000, oldUPN)
		check(t, r, "older read applied last", newUPN)
	})
	t.Run("an older read of an identity whose sighting was dropped", func(t *testing.T) {
		r := setup(t)
		sight(r, id, 100, newUPN)
		fill(r, 200)
		sight(r, "aid-new-identity", 9000, newUPN)
		if _, tracked := r.upns[id]; tracked {
			t.Fatal("the oldest sighting was not dropped at the cap")
		}
		sight(r, id, 99, oldUPN)
		check(t, r, "older read after the drop", "")
		sight(r, id, 9001, newerUPN)
		check(t, r, "newer read after the drop", newerUPN)
		sight(r, id, 150, oldUPN)
		check(t, r, "older read after the newer one", newerUPN)
	})
	t.Run("a read newer than every dropped sighting", func(t *testing.T) {
		r := setup(t)
		fill(r, 200)
		sight(r, "aid-new-identity", 9000, newUPN)
		sight(r, id, 201, newUPN)
		check(t, r, "read after the drop", newUPN)
	})
}
