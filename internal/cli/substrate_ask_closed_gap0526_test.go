// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/asks"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

// substrate-1 GAP-0526: a crash closed the actor's pending ask with no
// record of the closure. The leader now relays one ask_closed record per
// closed ask with the reason code (a gateway replica audits and posts it),
// and the ask's note names the code.
func TestGAP0526CrashClosedAskIsRelayedWithItsReason(t *testing.T) {
	store := asks.NewMemory()
	ctx := context.Background()
	opened, _ := store.OpenAsk(ctx, asks.Ask{Atespace: "eng-web", Actor: "a1", UID: wireUID1, OwnerID: "o", Host: "x.example.org", Unattended: true})
	relay := &telemetryrelay.Store{}
	h := substrateLifecycleClosesAsks(func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
		return chainstate.LifecycleResult{}, nil
	}, store, nil, relay)
	if _, err := h(ctx, chainstate.LifecycleEvent{Actor: chainstate.Actor{Atespace: "eng-web", UID: wireUID1}, Event: chainstate.LifecycleCrashed}); err != nil {
		t.Fatal(err)
	}
	got, err := relay.Take(ctx, telemetryrelay.TakeRequest{Max: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Records) != 1 {
		t.Fatalf("relayed %d records, want one ask_closed: %+v", len(got.Records), got.Records)
	}
	r := got.Records[0]
	if r.Kind != telemetryrelay.KindAskClosed || r.AskID != opened.ID || r.Reason != telemetryrelay.AskClosedActorCrashed ||
		r.Host != "x.example.org" || !r.Unattended || r.Actor != "a1" {
		t.Fatalf("relayed %+v", r)
	}
	list, _ := store.List(ctx, asks.ListRequest{All: true})
	if len(list) != 1 || list[0].State != asks.StateExpired || !strings.Contains(list[0].Note, "actor_crashed") {
		t.Fatalf("closed ask %+v", list)
	}
}
