// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// GAP-0526 (J20, E16): the leader closed a crashed actor's open ask, but
// nothing recorded why: no log line named the crash or the closure, and the
// decision had no reason code. Each closing event (crashed, reverted,
// deleted) now logs the event and every ask it closed with its reason code,
// and the closed ask's decision (the record an answer leaves) carries the
// code. A suspend closes nothing and logs nothing.
func TestLifecycleRecordsTheAsksItClosesGAP0526(t *testing.T) {
	for _, c := range []struct{ event, code string }{
		{chainstate.LifecycleCrashed, "actor_crashed"},
		{chainstate.LifecycleReverted, "actor_reverted"},
		{chainstate.LifecycleDeleted, "actor_deleted"},
	} {
		t.Run(c.event, func(t *testing.T) {
			store := asks.NewMemory()
			ctx := context.Background()
			open, err := store.OpenAsk(ctx, asks.Ask{Atespace: "dc-ops", Actor: "gv-1", UID: wireUID1, OwnerID: "ctr1", Host: "example.com"})
			if err != nil {
				t.Fatal(err)
			}
			var log strings.Builder
			h := substrateLifecycleClosesAsks(func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
				return chainstate.LifecycleResult{}, nil
			}, store, &log, nil)
			ev := func(kind string) chainstate.LifecycleEvent {
				return chainstate.LifecycleEvent{Actor: chainstate.Actor{Atespace: "dc-ops", UID: wireUID1}, Event: kind}
			}
			if _, err := h(ctx, ev(chainstate.LifecycleSuspended)); err != nil || log.Len() != 0 || len(store.Pending()) != 1 {
				t.Fatalf("suspend: err %v, log %q, pending %v", err, log.String(), store.Pending())
			}
			if _, err := h(ctx, ev(c.event)); err != nil {
				t.Fatal(err)
			}
			if p := store.Pending(); len(p) != 0 {
				t.Fatalf("the ask stays pending: %v", p)
			}
			for _, want := range []string{"lifecycle " + c.event, "closed 1 open ask(s) (" + c.code + ")", "ask " + open.ID + " of dc-ops/gv-1 (example.com) closed", "reason " + c.code} {
				if !strings.Contains(log.String(), want) {
					t.Errorf("log %q lacks %q", log.String(), want)
				}
			}
			ds, err := store.Decisions(ctx, asks.ListRequest{OwnerID: "ctr1"})
			if err != nil || len(ds) != 1 {
				t.Fatalf("decisions %+v, %v; want one", ds, err)
			}
			if d := ds[0]; d.Verdict != asks.StateExpired || d.Event != c.code || d.Tool != "example.com" || d.Reason == "" {
				t.Fatalf("decision %+v, want expired with event %s", d, c.code)
			}
		})
	}
}
