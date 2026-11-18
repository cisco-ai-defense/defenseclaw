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

package chainstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// GAP-0601 (review round 2): a secret read a gateway could not record while
// no leader answered reaches the new leader only on the note queue's next
// try. Within StartGrace of its first egress check, the leader answers a
// clear check unavailable, so the callout refuses a send; a hit is answered.
func TestEgressStartGraceGAP0601(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, t.TempDir(), Options{StartGrace: 15 * time.Second})
	in := EgressRequest{Actor: actorA, Host: "example.com", Method: "POST"}
	_, err := h.svc.Egress(ctx, in)
	var we *leader.WireError
	if !errors.As(err, &we) || we.Code != leader.CodeUnavailable {
		t.Fatalf("first check, clear: want unavailable, got %v", err)
	}
	h.advance(10 * time.Second)
	if _, err := h.svc.Egress(ctx, in); !errors.Is(err, errStarting) {
		t.Fatalf("10 s in, clear: want errStarting, got %v", err)
	}
	// The note arrives as a secret read: a hit is answered within the grace.
	h.hook(actorA, "s1", projection(t, guardrail.ToolChainSecretReadThenEgress, 1))
	h.advance(time.Second)
	if v, err := h.svc.Egress(ctx, in); err != nil || !v.Deny {
		t.Fatalf("hit within the grace: %+v %v", v, err)
	}
	// Past the grace: answered as usual.
	h2 := newHarness(t, t.TempDir(), Options{StartGrace: 15 * time.Second})
	_, _ = h2.svc.Egress(ctx, in)
	h2.advance(16 * time.Second)
	if v, err := h2.svc.Egress(ctx, in); err != nil || v.Deny {
		t.Fatalf("past the grace: %+v %v", v, err)
	}
	// No grace (the zero value): answered at once.
	h3 := newHarness(t, t.TempDir(), Options{})
	if v, err := h3.svc.Egress(ctx, in); err != nil || v.Deny {
		t.Fatalf("no grace: %+v %v", v, err)
	}
}
