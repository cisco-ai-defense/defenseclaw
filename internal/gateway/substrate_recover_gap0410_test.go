//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0410: a crashed actor shows as crashed, and its owner brings it back
// through the gateway (revert to the last snapshot, then resume) instead of
// needing kubectl ate revert; a second recover, or someone else's, is
// refused.
func TestGAP0410CrashedActorIsShownAndRecovered(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-1"}, ActorTemplate: ateapi.Ref("eng-web", "cc"),
		Status: &ateapi.ActorStatus{State: ateapi.ActorStateCrashed}})
	f := newSubstrateFixture(t)
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: "CRASHED"}
	st := f.api.substrateState()
	ensured := 0
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { ensured++; return nil }}

	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-1", "p-alice", "")
	var v map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if rec.Code != http.StatusOK || v["state"] != "crashed" {
		t.Fatalf("get %d %s: status cannot show the crash", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/recover", "p-bob", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("someone else's recover %d %s", rec.Code, rec.Body)
	}
	rec = f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/recover", "p-alice", "{}")
	if rec.Code != http.StatusOK {
		t.Fatalf("recover %d %s: the launcher has no way back from a crash", rec.Code, rec.Body)
	}
	a, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-1"))
	if err != nil || a.GetStatus().GetState() != ateapi.ActorStateRunning || ensured != 1 {
		t.Fatalf("after recover: %v %v, policy ensured %d", a.GetStatus().GetState(), err, ensured)
	}
	if fake.Calls("RevertActor") != 1 {
		t.Fatalf("RevertActor calls %d", fake.Calls("RevertActor"))
	}
	rec = f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors/eng-web/alice-1/recover", "p-alice", "{}")
	var e struct{ Reason string }
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if rec.Code != http.StatusConflict || e.Reason != "not_crashed" {
		t.Fatalf("recover of a running actor %d %s", rec.Code, rec.Body)
	}
}
