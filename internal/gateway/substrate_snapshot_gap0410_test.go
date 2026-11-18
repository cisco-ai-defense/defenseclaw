// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// gap0410Fixture is a gateway with alice's actor alice-1 in state, holding
// only its template's golden snapshot (generation 1, owned by a tag), as a
// launcher actor has until it is first suspended (E4 stk, FIX-0410 probe).
func gap0410Fixture(t *testing.T, state ateapi.ActorState) (*substrateFixture, *ateapifake.Fake, *int) {
	t.Helper()
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}, ActorTemplate: ateapi.Ref("eng-web", "cc"),
		Status: &ateapi.ActorStatus{State: state, LastAssignedGeneration: 1, Snapshots: []*ateapi.Snapshot{{
			Uuid: "golden", Generation: 1, Owner: 2 /* SNAPSHOT_OWNER_TAG */, Fidelity: ateapi.SnapshotFidelityMemory,
			DurableSnapshot: &ateapi.SnapshotStorage{State: ateapi.SnapshotStorageCompleted}}}}})
	f := newSubstrateFixture(t)
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: identity.ActorState(strings.TrimPrefix(state.String(), "ACTOR_STATE_"))}
	ensured := 0
	f.api.substrateState().cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { ensured++; return nil }}
	return f, fake, &ensured
}

func gap0410Body(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("body %s: %v", b, err)
	}
	return v
}

// GAP-0410: the checkpoint's snapshot route has the cluster store the
// running actor durably and starts it again, so a crash recovery returns to
// that snapshot (the folder and its restore points) and not to the
// template's golden one, which lost /work/proj-a at IB5 (exit 91).
func TestGAP0410CheckpointSnapshotSurvivesACrash(t *testing.T) {
	f, fake, ensured := gap0410Fixture(t, ateapi.ActorStateRunning)
	ref := ateapi.Ref("eng-web", "alice-1")
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/snapshot", "p-bob", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("someone else's snapshot %d %s", rec.Code, rec.Body)
	}
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/snapshot", "p-alice", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("snapshot %d %s: the launcher cannot keep the person's work past a crash", rec.Code, rec.Body)
	}
	v := gap0410Body(t, rec.Body.Bytes())
	if v["state"] != "running" || v["snapshot_generation"] != float64(2) {
		t.Fatalf("snapshot answer %v", v)
	}
	if fake.Calls("SuspendActorDurable") != 1 || fake.Calls("SuspendActor") != 0 {
		t.Fatalf("suspends: durable %d, async %d (an async one is not stored before a crash)", fake.Calls("SuspendActorDurable"), fake.Calls("SuspendActor"))
	}
	a, _ := fake.GetActor(context.Background(), ref)
	if a.GetStatus().GetState() != ateapi.ActorStateRunning || *ensured != 1 {
		t.Fatalf("after the snapshot: %v, policy ensured %d", a.GetStatus().GetState(), *ensured)
	}

	// The worker goes away; recover returns to generation 2, the actor's own.
	if err := fake.SetState(ref, ateapi.ActorStateCrashed); err != nil {
		t.Fatal(err)
	}
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: "CRASHED"}
	rec = f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/recover", "p-alice", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("recover %d %s", rec.Code, rec.Body)
	}
	if v := gap0410Body(t, rec.Body.Bytes()); v["recovered_from"] != "snapshot" {
		t.Fatalf("recover answer %v: want recovered_from snapshot", v)
	}
	a, _ = fake.GetActor(context.Background(), ref)
	h := gap0410Newest(a.GetStatus())
	if a.GetStatus().GetState() != ateapi.ActorStateRunning || h.GetGeneration() != 2 || h.GetOwner() != ateapi.SnapshotOwnerActor {
		t.Fatalf("after recover: %v at generation %d owner %v", a.GetStatus().GetState(), h.GetGeneration(), h.GetOwner())
	}
}

// GAP-0410: a crashed actor that never had a snapshot of its own stored
// (none, or only an async one still being uploaded) comes back at its
// template's start, and recover says so, so the launcher can tell the
// person the folder is lost instead of failing undo with exit 91.
func TestGAP0410RecoverSaysWhenOnlyTheTemplateIsLeft(t *testing.T) {
	for name, async := range map[string]bool{"never suspended": false, "async snapshot not uploaded": true} {
		t.Run(name, func(t *testing.T) {
			f, fake, _ := gap0410Fixture(t, ateapi.ActorStateRunning)
			ref := ateapi.Ref("eng-web", "alice-1")
			if async {
				for _, st := range []ateapi.ActorState{ateapi.ActorStateSuspended, ateapi.ActorStateRunning} {
					if err := fake.SetState(ref, st); err != nil {
						t.Fatal(err)
					}
				}
			}
			if err := fake.SetState(ref, ateapi.ActorStateCrashed); err != nil {
				t.Fatal(err)
			}
			f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: "CRASHED"}
			rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/recover", "p-alice", "{}")
			if rec.Code != http.StatusOK {
				t.Fatalf("recover %d %s", rec.Code, rec.Body)
			}
			if v := gap0410Body(t, rec.Body.Bytes()); v["recovered_from"] != "template" {
				t.Fatalf("recover answer %v: want recovered_from template", v)
			}
		})
	}
}

// GAP-0410: a snapshot of an actor that is not running is refused (409), and
// a control API client that cannot suspend durably leaves the route 501.
func TestGAP0410SnapshotRefusals(t *testing.T) {
	f, fake, _ := gap0410Fixture(t, ateapi.ActorStateSuspended)
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/snapshot", "p-alice", "{}")
	var e struct{ Reason string }
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if rec.Code != http.StatusConflict || e.Reason != "not_running" || fake.Calls("SuspendActorDurable") != 0 {
		t.Fatalf("snapshot of a suspended actor %d %s", rec.Code, rec.Body)
	}
	f.api.substrateState().cfg.Actions = &SubstrateATEActions{Client: asyncOnly{fake}}
	rec = f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/snapshot", "p-alice", "{}")
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("snapshot without a durable suspend %d %s", rec.Code, rec.Body)
	}
}

// asyncOnly is a control API client without SuspendActorDurable.
type asyncOnly struct{ ateapi.Client }

// gap0410Newest is the highest snapshot generation of s.
func gap0410Newest(s *ateapi.ActorStatus) *ateapi.Snapshot {
	var h *ateapi.Snapshot
	for _, sn := range s.GetSnapshots() {
		if h == nil || sn.GetGeneration() > h.GetGeneration() {
			h = sn
		}
	}
	return h
}
