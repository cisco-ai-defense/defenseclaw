// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

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

// GAP-0474: a delete says how many snapshots went with the actor, status
// shows the count first, and the audit store gets a person-level delete row
// (person, UID, count), not only the controller's sandbox event.
func TestGAP0474DeleteNamesThePurgedSnapshotsAndAuditsThePerson(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	st.cfg.Actions = &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { return nil }}
	st.cfg.Lookup = identity.ActorLookupFunc(func(ctx context.Context, atespace, name string) (identity.LiveActor, error) {
		a, err := fake.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			return identity.LiveActor{}, identity.ErrActorNotFound
		}
		return identity.LiveActor{UID: a.GetMetadata().GetUid(), State: identity.ActorState(strings.TrimPrefix(a.GetStatus().GetState().String(), "ACTOR_STATE_"))}, nil
	})
	type row struct {
		severity, summary string
		details           map[string]any
	}
	var rows []row
	st.audit = func(_ context.Context, severity, summary string, details map[string]any) {
		rows = append(rows, row{severity, summary, details})
	}
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-9"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	ctx := context.Background()
	ref := ateapi.Ref("eng-web", "alice-9")
	a, err := fake.GetActor(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	uid := a.GetMetadata().GetUid()
	// Three sync suspends, as the cert cell did.
	for i := 0; i < 3; i++ {
		if _, err := fake.SuspendActor(ctx, ref); err != nil {
			t.Fatalf("suspend %d: %v", i, err)
		}
		if i < 2 {
			if _, _, err := fake.ResumeActor(ctx, ref); err != nil {
				t.Fatalf("resume %d: %v", i, err)
			}
		}
	}
	a, _ = fake.GetActor(ctx, ref)
	want := len(a.GetStatus().GetSnapshots())
	if want == 0 {
		t.Fatal("the fake holds no snapshots after three suspends")
	}

	var view map[string]any
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/alice-9", "p-alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d %s", rec.Code, rec.Body)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if n, ok := view["snapshots"].(float64); !ok || int(n) != want {
		t.Fatalf("status snapshots = %v, want %d", view["snapshots"], want)
	}

	rows = nil
	rec = f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/actors/eng-web/alice-9", "p-alice", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("delete %d %s", rec.Code, rec.Body)
	}
	view = nil
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if n, ok := view["snapshots"].(float64); !ok || int(n) != want || view["deleted"] != true {
		t.Fatalf("delete answer %v, want deleted with %d snapshots", view, want)
	}
	var del *row
	for i := range rows {
		if rows[i].details["event"] == "actor_deleted" {
			del = &rows[i]
		}
	}
	if del == nil {
		t.Fatalf("no actor_deleted audit row: %+v", rows)
	}
	d := del.details
	if d["actor_uid"] != uid || d["actor"] != "eng-web/alice-9" || d["snapshots"] != want || d["person_id"] == "" || d["person_id"] == nil {
		t.Fatalf("delete row %+v", d)
	}
	if !strings.Contains(del.summary, uid) || !strings.Contains(del.summary, "snapshot") {
		t.Fatalf("delete summary %q", del.summary)
	}
}
