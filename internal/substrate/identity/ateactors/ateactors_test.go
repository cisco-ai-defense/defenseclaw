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

package ateactors

import (
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

func TestATEAPILookup(t *testing.T) {
	fake := ateapifake.New()
	ref := ateapi.Ref("team-a", "agent-1")
	a := fake.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "team-a", Name: "agent-1"}})
	if err := fake.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	lookup := ATEAPILookup(fake)
	got, err := lookup.LookupActor(context.Background(), "team-a", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if got.UID != a.GetMetadata().GetUid() || got.State != identity.ActorRunning {
		t.Fatalf("live actor %+v", got)
	}
	again, err := fake.Recreate(ref)
	if err != nil {
		t.Fatal(err)
	}
	got, _ = lookup.LookupActor(context.Background(), "team-a", "agent-1")
	if got.UID != again.GetMetadata().GetUid() || got.UID == a.GetMetadata().GetUid() || got.State != "SUSPENDED" {
		t.Fatalf("recreated actor %+v", got)
	}
	fake.RemoveActor(ref)
	if _, err := lookup.LookupActor(context.Background(), "team-a", "agent-1"); !errors.Is(err, identity.ErrActorNotFound) {
		t.Fatalf("missing actor: %v", err)
	}
}
