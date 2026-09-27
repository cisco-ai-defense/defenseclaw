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

package manager

import (
	"context"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// TestPendingCapKeepsAReproposedAsk pins that at the pending-ask cap a new
// proposal of a rule already waiting for the user collapses into its ask
// (on the newest chunk) instead of being rejected, and taking the ask with
// it.
func TestPendingCapKeepsAReproposedAsk(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "capbox"})
	gw, err := e.m.gateway(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e.m.mu.Lock()
	b := e.m.boxes["capbox"]
	bindingID := b.rec.BindingID
	e.m.mu.Unlock()
	ask := func(i int, chunkID string) {
		host := fmt.Sprintf("h%d.example.org", i)
		p := triage.Proposal{Sandbox: "capbox", ChunkID: chunkID, RuleName: fmt.Sprintf("allow_h%d_example_org_443", i),
			RuleDigest: fmt.Sprintf("rule-%d", i), Endpoints: []triage.Endpoint{{Host: host, Port: 443}}}
		e.m.applyTriage(ctx, gw, b, bindingID, p, triage.Decision{Verdict: triage.Ask, Reason: triage.ReasonManual,
			Kind: triage.KindNetworkRule, Host: host, Port: 443, Message: "approvals are manual"})
	}
	for i := range maxPendingApprovals {
		ask(i, fmt.Sprintf("chunk-%d", i))
	}
	ask(0, "chunk-0-again")
	id := approvalID("capbox", "rule-0")
	e.m.mu.Lock()
	a := e.m.approvals[id]
	status, chunkID := a.status, a.chunkID
	e.m.mu.Unlock()
	if status != sandboxapi.ApprovalPending || chunkID != "chunk-0-again" {
		t.Fatalf("the re-proposed ask is %s on %s, want pending on the newest chunk", status, chunkID)
	}
	asks, _ := e.m.Approvals(ctx, "capbox")
	if len(asks) != maxPendingApprovals {
		t.Fatalf("%d asks pending, want %d", len(asks), maxPendingApprovals)
	}
	// A new rule at the cap is still rejected.
	ask(maxPendingApprovals, "chunk-new")
	if asks, _ := e.m.Approvals(ctx, "capbox"); len(asks) != maxPendingApprovals {
		t.Fatalf("the cap let a new ask in: %d pending", len(asks))
	}
}
