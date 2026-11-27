// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// uncountedActions hides the optional Snapshots method of the real actions,
// as a cluster that cannot count snapshots does.
type uncountedActions struct{ SubstrateActorActions }

// failingPutStore refuses the registration write a delete ends with.
type failingPutStore struct{ registry.Store }

func (failingPutStore) Put(context.Context, registry.Registration) error {
	return errors.New("registration store unavailable")
}

// substrate-1:GAP-0667 (P34-E review): the actor_deleted audit row is written
// right after the cluster delete, so it exists even when the registration
// write that follows fails; a cluster that cannot count snapshots writes -1;
// and the administrator flag is a bool named by_admin, not admin, which admin_read
// rows use for the administrator's name.
func TestGAP0667DeleteAuditRowIsWrittenAfterTheDeleteAndNamesByAdmin(t *testing.T) {
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	})
	st := f.api.substrateState()
	actions := &SubstrateATEActions{Client: fake, Ensure: func(context.Context, string, string) error { return nil }}
	st.cfg.Actions = uncountedActions{actions}
	st.cfg.Lookup = identity.ActorLookupFunc(func(ctx context.Context, atespace, name string) (identity.LiveActor, error) {
		a, err := fake.GetActor(ctx, ateapi.Ref(atespace, name))
		if err != nil {
			return identity.LiveActor{}, identity.ErrActorNotFound
		}
		return identity.LiveActor{UID: a.GetMetadata().GetUid()}, nil
	})
	var details []map[string]any
	st.audit = func(_ context.Context, _, _ string, d map[string]any) { details = append(details, d) }

	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"template":"cc","connector":"claudecode","name":"alice-67"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	st.cfg.Registrations = failingPutStore{st.cfg.Registrations}

	rec := f.do(t, f.admin, http.MethodDelete, "/api/v1/substrate/actors/eng-web/alice-67", "p-alice", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("delete with a failing registration write: %d %s, want 503", rec.Code, rec.Body)
	}
	var row map[string]any
	for _, d := range details {
		if d["event"] == "actor_deleted" {
			row = d
		}
	}
	if row == nil {
		t.Fatalf("no actor_deleted row although the cluster deleted the actor: %+v", details)
	}
	if row["snapshots"] != -1 {
		t.Errorf("snapshots = %v for an uncounted delete, want -1", row["snapshots"])
	}
	// The agent's own owner deletes it here, so the flag is present and false.
	if by, ok := row["by_admin"].(bool); !ok || by {
		t.Errorf("by_admin = %v, want false (a bool) for the owner deleting their own agent", row["by_admin"])
	}
	if _, clash := row["admin"]; clash {
		t.Error("the actor_deleted row still carries an admin field that clashes with admin_read's")
	}
}
