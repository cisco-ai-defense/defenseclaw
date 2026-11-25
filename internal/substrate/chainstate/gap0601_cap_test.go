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
	"sync"
	"testing"
	"time"
)

// GAP-0601: the start grace runs from the term's first clear check, as in
// rel, and never past startGraceCap after the term began (Leading, or New
// without it). Exact boundaries; Leading moves the term start.
func TestStartGraceCapGAP0601(t *testing.T) {
	ctx := context.Background()
	post := EgressRequest{Actor: actorB, Name: "b", Host: "github.com", Method: "POST"}
	refused := func(h *harness, when string) {
		t.Helper()
		if _, err := h.svc.Egress(ctx, post); !errors.Is(err, errStarting) {
			t.Fatalf("%s: want errStarting, got %v", when, err)
		}
	}
	answered := func(h *harness, when string) {
		t.Helper()
		if v, err := h.svc.Egress(ctx, post); err != nil || v.Deny {
			t.Fatalf("%s: want a clear answer, got %+v %v", when, v, err)
		}
	}
	if startGraceCap(15*time.Second) != 30*time.Second {
		t.Fatalf("cap %s, want 30 s", startGraceCap(15*time.Second))
	}

	// An early first check keeps the whole grace, to the nanosecond.
	h := coldLeader(t)
	h.advance(5 * time.Second)
	refused(h, "first check 5 s into the term")
	h.advance(15*time.Second - time.Nanosecond)
	refused(h, "just inside the grace of the first check")
	h.advance(time.Nanosecond)
	answered(h, "15 s after the first check")

	// A late first check: the grace ends at the cap.
	h = coldLeader(t)
	h.advance(20 * time.Second)
	refused(h, "first check 20 s into the term")
	h.advance(10*time.Second - time.Nanosecond)
	refused(h, "just inside the cap")
	h.advance(time.Nanosecond)
	answered(h, "at the cap (30 s), 10 s after the first check")

	// Leading moves the term start: New came a lease duration earlier.
	h = coldLeader(t)
	h.advance(45 * time.Second)
	h.svc.Leading()
	h.advance(2 * time.Second)
	refused(h, "2 s after Leading, 47 s after New")
	h.advance(15 * time.Second)
	answered(h, "15 s after the first check of the term")

	// Quiet cluster: the first actor's clone comes minutes after Leading.
	h = coldLeader(t)
	h.svc.Leading()
	h.advance(10 * time.Minute)
	h.cloneAnswered("a quiet cluster's first actor")

	// Leading on no service is a no-op.
	var none *Service
	none.Leading()
}

// Leading and the check race on the term fields (go test -race).
func TestStartGraceTermConcurrentGAP0601(t *testing.T) {
	h := coldLeader(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if j%2 == 0 {
					h.svc.Leading()
				} else {
					_ = h.svc.starting()
				}
			}
		}()
	}
	wg.Wait()
}
