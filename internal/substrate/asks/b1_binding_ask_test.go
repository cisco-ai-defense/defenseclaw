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

package asks

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestB1SecretBindingAsk: a binding ask has no actor, is keyed by its
// binding, may wait up to 168h, and only an administrator answers it
// (the leader's registration hook never runs for it).
func TestB1SecretBindingAsk(t *testing.T) {
	ctx := context.Background()
	s := NewMemory()
	s.OnApprove = func(context.Context, Ask) error { return errors.New("registration hook ran for a binding ask") }
	if _, err := s.OpenAsk(ctx, Ask{Kind: KindSecretBinding, Host: "git.lab.example", Tool: "gl-lab", Rule: BindingRule("b-1")}); err == nil {
		t.Fatal("binding ask without an owner opened")
	}
	if _, err := s.OpenAsk(ctx, Ask{Kind: KindSecretBinding, OwnerID: "alice", Host: "git.lab.example", Tool: "gl-lab"}); err == nil {
		t.Fatal("binding ask without a binding opened")
	}
	a, err := s.OpenAsk(ctx, Ask{Kind: KindSecretBinding, OwnerID: "alice", Host: "git.lab.example", Tool: "gl-lab",
		Rule: BindingRule("b-1"), TimeoutSeconds: int64((100 * time.Hour) / time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if a.BindingID() != "b-1" || a.UID != BindingRule("b-1") || a.Expires.Sub(a.Created) != 100*time.Hour {
		t.Fatalf("binding ask %+v", a)
	}
	if again, _ := s.OpenAsk(ctx, Ask{Kind: KindSecretBinding, OwnerID: "alice", Host: "git.lab.example", Tool: "gl-lab",
		Rule: BindingRule("b-1")}); again.ID != a.ID {
		t.Fatalf("same binding asked twice: %s %s", again.ID, a.ID)
	}
	long, _ := s.OpenAsk(ctx, Ask{Kind: KindSecretBinding, OwnerID: "bob", Host: "h.example", Tool: "x", Rule: BindingRule("b-2"),
		TimeoutSeconds: int64((500 * time.Hour) / time.Second)})
	if long.Expires.Sub(long.Created) != MaxBindingAskTimeout {
		t.Fatalf("binding ask timeout not capped at 168h: %s", long.Expires.Sub(long.Created))
	}
	if (Ask{Kind: "egress", Rule: BindingRule("b-1")}).BindingID() != "" {
		t.Fatal("an egress ask names a binding")
	}
	if _, err := s.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "approve", CallerID: "alice"}); !IsAdminOnly(err) {
		t.Fatalf("owner answered their own binding ask: %v", err)
	}
	got, err := s.Resolve(ctx, ResolveRequest{ID: a.ID, Decision: "approve", Always: true, CallerID: "root", Admin: true})
	if err != nil || got.State != StateApproved || got.Always || got.DecidedBy != "root" {
		t.Fatalf("admin approve: %+v %v", got, err)
	}
}
