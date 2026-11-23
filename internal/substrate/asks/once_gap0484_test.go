// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package asks

import (
	"context"
	"testing"
)

// TestOnceApprovalIsNotStandingGAP0484: an approval without always never
// runs OnApprove, which adds the host to the actor's registration and so,
// on the controller's next pass, to its policy for the actor's lifetime.
// Before the fix every approval ran it, so `approve ID` (once) was a
// standing approval of the host.
func TestOnceApprovalIsNotStandingGAP0484(t *testing.T) {
	s := NewMemory()
	var joined []string
	s.OnApprove = func(_ context.Context, a Ask) error { joined = append(joined, a.Host); return nil }
	ctx := context.Background()
	once, _ := s.OpenAsk(ctx, Ask{Atespace: "e", Actor: "a", UID: "u", OwnerID: "o", Host: "example.com", Rule: "ask_hosts:example.com"})
	got, err := s.Resolve(ctx, ResolveRequest{ID: once.ID, Decision: "approve", CallerID: "o"})
	if err != nil || got.State != StateApproved || got.Always {
		t.Fatalf("approve once: %+v %v", got, err)
	}
	if len(joined) != 0 {
		t.Fatalf("approve once ran OnApprove (the host joined the registration): %v", joined)
	}
	always, _ := s.OpenAsk(ctx, Ask{Atespace: "e", Actor: "a", UID: "u", OwnerID: "o", Host: "example.org", Rule: "ask_hosts:example.org"})
	if _, err := s.Resolve(ctx, ResolveRequest{ID: always.ID, Decision: "approve", Always: true, CallerID: "o"}); err != nil {
		t.Fatal(err)
	}
	if len(joined) != 1 || joined[0] != "example.org" {
		t.Fatalf("approve always: OnApprove ran for %v", joined)
	}
}
