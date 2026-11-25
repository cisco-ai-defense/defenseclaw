// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"errors"
	"testing"
	"time"
)

// GAP-0642: right after a rollout restart of the gateway, leader, callout
// and controller, `run --clone` failed in 5 of 6 cycles with the network
// guard's 503. The new leader answered every clear egress check
// unavailable for its start grace (GAP-0601), and the callout refuses an
// unchecked check under a fail-closed chain mode. The grace waits for a
// gateway's note of a tool step it could not record while no leader
// answered. An actor registered in this leader term, not a fork, did not
// exist then, so its first clone is answered at once. An older actor, a fork
// and an actor with no registration still wait.
func TestGAP0642ActorBornInTheTermSkipsTheStartGrace(t *testing.T) {
	ctx := context.Background()
	get := EgressRequest{Actor: actorB, Name: "b", Host: "github.com", Method: "GET"}
	for _, tc := range []struct {
		name    string
		born    func(h *harness) func(context.Context, string, string) (time.Time, string, error)
		answers bool
	}{
		{"registered after the term began", func(h *harness) func(context.Context, string, string) (time.Time, string, error) {
			at := h.now.Add(time.Second)
			return func(context.Context, string, string) (time.Time, string, error) { return at, "", nil }
		}, true},
		{"registered before the term began", func(h *harness) func(context.Context, string, string) (time.Time, string, error) {
			at := h.now.Add(-time.Minute)
			return func(context.Context, string, string) (time.Time, string, error) { return at, "", nil }
		}, false},
		{"a fork registered in the term", func(h *harness) func(context.Context, string, string) (time.Time, string, error) {
			at := h.now.Add(time.Second)
			return func(context.Context, string, string) (time.Time, string, error) { return at, "parent-uid", nil }
		}, false},
		{"no registration", func(h *harness) func(context.Context, string, string) (time.Time, string, error) {
			return func(context.Context, string, string) (time.Time, string, error) { return time.Time{}, "", nil }
		}, false},
		{"the registration read fails", func(h *harness) func(context.Context, string, string) (time.Time, string, error) {
			return func(context.Context, string, string) (time.Time, string, error) {
				return time.Now(), "", errors.New("store down")
			}
		}, false},
		{"no Born (rel behaviour)", nil, false},
	} {
		h := coldLeader(t)
		h.svc.Leading()
		if tc.born != nil {
			h.svc.opts.Born = tc.born(h)
		}
		h.advance(2 * time.Second)
		for _, m := range []string{"GET", "POST"} {
			req := get
			req.Method = m
			v, err := h.svc.Egress(ctx, req)
			switch {
			case tc.answers && (err != nil || v.Deny):
				t.Errorf("%s %s: want a clear answer inside the grace, got %+v %v", tc.name, m, v, err)
			case !tc.answers && !errors.Is(err, errStarting):
				t.Errorf("%s %s: want errStarting inside the grace, got %+v %v", tc.name, m, v, err)
			}
		}
	}
}
