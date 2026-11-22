//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// noRoom is a control API whose pool has no free worker.
type noRoom struct{ *ateapifake.Fake }

func (noRoom) ResumeActor(context.Context, *ateapi.ObjectRef) (*ateapi.Actor, bool, error) {
	return nil, false, status.Error(codes.ResourceExhausted, "no worker has room for the actor")
}

// GAP-0167: a create the pool has no room for says so (503 no_free_worker)
// and leaves no SUSPENDED actor behind; list shows each agent state.
func TestSubstrateCreateWithNoFreeWorker(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: noRoom{fake}, Ensure: func(context.Context, string, string) error { return nil }}
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-full"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	var e struct{ Reason string }
	_ = json.Unmarshal(rec.Body.Bytes(), &e)
	if e.Reason != "no_free_worker" {
		t.Errorf("reason %q", e.Reason)
	}
	if _, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-full")); !ateapi.IsNotFound(err) {
		t.Errorf("the half-made actor stayed: %v", err)
	}
	// list: the fixture actors are running, with their state.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "")
	var l struct {
		Actors []map[string]any `json:"actors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &l)
	found := false
	for _, a := range l.Actors {
		if a["name"] == "alice-1" {
			found = true
			if a["state"] != "running" {
				t.Errorf("alice-1 state %v", a["state"])
			}
		}
		if a["name"] == "alice-full" && a["deleted"] != true {
			t.Errorf("the failed create is listed as an agent: %v", a)
		}
	}
	if !found {
		t.Errorf("list %s", rec.Body)
	}
}
