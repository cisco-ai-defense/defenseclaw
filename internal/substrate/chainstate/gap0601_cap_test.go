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
)

// GAP-0601 review round 1: in a quiet cluster nothing calls a new leader
// until the first actor starts, whose own calls (registration, hooks) then
// came seconds before its clone. The grace ends startGraceCap after the term
// began (Leading), so that clone is answered; a first call inside the cap
// still gets the grace up to the cap.
func TestQuietClusterFirstCloneGAP0601(t *testing.T) {
	h := coldLeader(t)
	h.svc.Leading()
	// Overnight: the first actor's calls come long after the term began.
	h.advance(10 * time.Minute)
	h.otherCall()
	h.advance(time.Second)
	h.cloneAnswered("a quiet cluster's first actor, 1 s after its first call")

	// A first call 20 s into the term: the grace lasts to the cap (30 s).
	h2 := coldLeader(t)
	h2.svc.Leading()
	h2.advance(20 * time.Second)
	h2.otherCall()
	h2.advance(5 * time.Second)
	post := EgressRequest{Actor: actorB, Name: "b", Host: "github.com", Method: "POST"}
	if _, err := h2.svc.Egress(context.Background(), post); !errors.Is(err, errStarting) {
		t.Fatalf("25 s into the term, 5 s after its first call: want errStarting, got %v", err)
	}
	h2.advance(5 * time.Second)
	if v, err := h2.svc.Egress(context.Background(), post); err != nil || v.Deny {
		t.Fatalf("at the cap (30 s into the term): %+v %v", v, err)
	}

	// The cap is twice the grace, and a call early in the term keeps the
	// full grace (the S2 row: a send 6 s after the leader is back).
	if startGraceCap(15*time.Second) != 30*time.Second {
		t.Fatalf("cap %s", startGraceCap(15*time.Second))
	}
	h3 := coldLeader(t)
	h3.svc.Leading()
	h3.advance(2 * time.Second)
	h3.otherCall()
	h3.advance(6 * time.Second)
	if _, err := h3.svc.Egress(context.Background(), post); !errors.Is(err, errStarting) {
		t.Fatalf("6 s after the term's first call: want errStarting, got %v", err)
	}
	h3.advance(9 * time.Second)
	if v, err := h3.svc.Egress(context.Background(), post); err != nil || v.Deny {
		t.Fatalf("15 s after the term's first call: %+v %v", v, err)
	}
}
