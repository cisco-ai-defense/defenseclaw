// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"testing"
)

// GAP-0581: the telemetry relay keeps an egress record without a UID by the
// atespace and actor name it carries. This is what the callout writes for
// the refusals that have no UID: a deleted actor (refused before the UID is
// set), a registration lookup outage with nothing cached, and an actor
// DefenseClaw never registered. The atespace and name are the request's
// actor, which comes from the egress gateway's verified SPIFFE ID
// (actorFromAttributes), never from the actor's own headers.
func TestGAP0581CalloutRefusalsWithoutUIDNameTheActor(t *testing.T) {
	ctx := context.Background()
	check := func(t *testing.T, h *harness, r *Request, category string) {
		t.Helper()
		v := h.eng.DecideHeaders(ctx, r)
		if v.Allow || v.Category != category {
			t.Fatalf("got %+v, want a %s refusal", v, category)
		}
		h.eng.Finish(r, v)
		h.events.mu.Lock()
		defer h.events.mu.Unlock()
		if len(h.events.events) == 0 {
			t.Fatal("no event")
		}
		ev := h.events.events[len(h.events.events)-1]
		if ev.Decision != "block" || ev.Actor == "" || ev.Atespace != r.Actor.Atespace || ev.Actor != r.Actor.Name || ev.ActorUID != "" {
			t.Fatalf("event %+v: want a block naming %s/%s with no UID", ev, r.Actor.Atespace, r.Actor.Name)
		}
	}
	t.Run("deleted actor", func(t *testing.T) {
		h := newHarness(t, nil)
		h.uids.live = false
		check(t, h, req("eng-web", "GET", "example.com", "/"), CategoryActorNotLive)
	})
	t.Run("lookup outage", func(t *testing.T) {
		h, _ := outageHarness(t, false)
		leaderDown(h)
		check(t, h, req("eng-web", "GET", "example.com", "/"), CategoryChainUnchecked)
	})
	t.Run("unregistered actor", func(t *testing.T) {
		h := newHarness(t, nil)
		h.uids.uid = ""
		check(t, h, req("other", "GET", "pastebin.com", "/"), "paste_site")
	})
}
