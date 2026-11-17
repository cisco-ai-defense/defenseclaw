// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/extproc"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/telemetryrelay"
)

const relayTestUID = "00000000-0000-4000-8000-0000000000a1"

// GAP-0453: the leader relays each lifecycle event the controller reports,
// with the actor's registration, and nothing for an event the chain state
// ignored.
func TestGAP0453LeaderRelaysLifecycleEventsWithTheRegistration(t *testing.T) {
	regs, err := registry.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := regs.Put(ctx, registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: relayTestUID, Connector: "claudecode",
		Profile: "eng", Template: "eng-web/claude", Unattended: true, BatchID: "b1",
		Person: registry.Person{Kind: "human", Issuer: "https://idp.example", Subject: "alice", Principal: "alice@example.com"}}); err != nil {
		t.Fatal(err)
	}
	relay := &telemetryrelay.Store{}
	ignored := false
	h := substrateLifecycleRelays(func(context.Context, chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
		return chainstate.LifecycleResult{Ignored: ignored}, nil
	}, regs, relay)
	at := time.Date(2026, 11, 17, 18, 0, 0, 0, time.UTC)
	ev := chainstate.LifecycleEvent{Actor: chainstate.Actor{Atespace: "eng-web", UID: relayTestUID}, Event: chainstate.LifecycleSuspended, AtUnixNano: at.UnixNano()}
	if _, err := h(ctx, ev); err != nil {
		t.Fatal(err)
	}
	ignored = true
	if _, err := h(ctx, ev); err != nil {
		t.Fatal(err)
	}
	out, _ := relay.Take(ctx, telemetryrelay.TakeRequest{})
	if len(out.Records) != 1 {
		t.Fatalf("relayed %d records, want 1 (the ignored event is not a transition): %+v", len(out.Records), out.Records)
	}
	r := out.Records[0]
	if r.Kind != telemetryrelay.KindLifecycle || r.Lifecycle != chainstate.LifecycleSuspended || r.Actor != "alice-1" || r.Profile != "eng" ||
		r.Template != "eng-web/claude" || r.Connector != "claudecode" || r.RunMode != "unattended" || r.BatchID != "b1" ||
		r.UserName != "alice@example.com" || r.UserID != "https://idp.example#alice" || !r.At.Equal(at) {
		t.Fatalf("lifecycle record %+v", r)
	}
}

// GAP-0450: the controller's idle suspends and policy conflicts are counted
// for the relay; other events are only logged.
func TestGAP0450ControllerEventsCountForTheRelay(t *testing.T) {
	var logged []string
	poster := &telemetryrelay.Poster{}
	sink := substrateRelayCounts{next: sinkFunc(func(e controller.Event) { logged = append(logged, e.Type) }), relay: poster}
	for _, typ := range []string{controller.EventIdleSuspend, controller.EventInventory, controller.EventPolicyConflict, controller.EventPolicyWritten} {
		sink.Emit(controller.Event{Type: typ})
	}
	if len(logged) != 4 {
		t.Fatalf("logged %v", logged)
	}
	ctx := context.Background()
	store := &telemetryrelay.Store{}
	// What the poster holds is what the leader would get.
	srvRecs := posterPending(t, poster)
	store.Add(srvRecs...)
	out, _ := store.Take(ctx, telemetryrelay.TakeRequest{})
	var metrics []string
	for _, r := range out.Records {
		metrics = append(metrics, r.Metric)
	}
	if !slices.Equal(metrics, []string{telemetryrelay.MetricIdleSuspends, telemetryrelay.MetricPolicyConflicts}) {
		t.Fatalf("counted %v", metrics)
	}
}

// GAP-0453: the callout relays each egress decision of an actor.
func TestGAP0453CalloutRelaysEgressDecisions(t *testing.T) {
	var n int
	poster := &telemetryrelay.Poster{}
	sink := substrateRelayEgress{next: egressFunc(func(extproc.Event) { n++ }), relay: poster}
	sink.EgressEvent(extproc.Event{Event: extproc.EventEgressBlocked, Decision: "block", Atespace: "eng-web", Actor: "alice-1",
		ActorUID: relayTestUID, Host: "evil.example.com", Category: "chain_egress", Headers: map[string]string{"authorization": "x"}})
	sink.EgressEvent(extproc.Event{Event: extproc.EventEgressAllowed, Decision: "allow", Host: "own.example"}) // no actor
	recs := posterPending(t, poster)
	if n != 2 || len(recs) != 1 || recs[0].Host != "evil.example.com" || recs[0].Decision != "block" || recs[0].Category != "chain_egress" {
		t.Fatalf("logged %d, relayed %+v", n, recs)
	}
}

// The controller posts counts and the callout egress decisions, each only
// through its own method; only gateway replicas take from the relay.
func TestGAP0450RelayPermissions(t *testing.T) {
	p := substrateLeaderPermissions([]string{"gw"}, []string{"callout"}, []string{"ctl"})
	for id, own := range map[string]string{"callout": telemetryrelay.MethodPostEgress, "ctl": telemetryrelay.MethodPostCounts} {
		other := telemetryrelay.MethodPostCounts
		if own == other {
			other = telemetryrelay.MethodPostEgress
		}
		if !slices.Contains(p[id], own) || slices.Contains(p[id], other) || slices.Contains(p[id], telemetryrelay.MethodTake) {
			t.Fatalf("%s may call %v", id, p[id])
		}
	}
	if !slices.Contains(p["gw"], "*") {
		t.Fatalf("gateway %v", p["gw"])
	}
}

type sinkFunc func(controller.Event)

func (f sinkFunc) Emit(e controller.Event) { f(e) }

type egressFunc func(extproc.Event)

func (f egressFunc) EgressEvent(e extproc.Event) { f(e) }

// posterPending flushes the poster into a leader-less store and returns what
// it held.
func posterPending(t *testing.T, p *telemetryrelay.Poster) []telemetryrelay.Record {
	t.Helper()
	return p.Pending()
}
