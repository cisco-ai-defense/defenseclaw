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

package leader

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0404: the replay cache kept every call's answer until the map held
// 200,000 of them, expired or not, so the leader's memory grew with every
// hook call (5 leader calls per tool call) and nothing was given back while
// it ran. Now an answer leaves at IdempotencyTTL, and past 64 MiB the
// oldest leave first; a recent answer is still replayed to its retry.
func TestGAP0404ReplayCacheIsBoundedByBytesAndAge(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := &Server{IsLeader: func() bool { return true }, Now: func() time.Time { return now }}
	var runs atomic.Int64
	body := strings.Repeat("x", 16<<10)
	s.Handle("Write", Typed(func(context.Context, struct{}) (string, error) {
		runs.Add(1)
		return body, nil
	}))
	call := func(id string) int {
		req := httptest.NewRequest(http.MethodPost, PathPrefix+"Write", strings.NewReader(`{"request_id":"`+id+`","body":{}}`))
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Code
	}
	const budget = 64 << 20
	const n = 2 * budget / (16 << 10) // twice the budget of 16 KiB answers
	for i := 0; i < n; i++ {
		if code := call(fmt.Sprintf("req-gap0404-%06d", i)); code != http.StatusOK {
			t.Fatalf("call %d: %d", i, code)
		}
		now = now.Add(time.Millisecond)
	}
	s.mu.Lock()
	kept := len(s.done)
	s.mu.Unlock()
	if most := budget / (16 << 10); kept > most {
		t.Fatalf("the replay cache keeps %d answers of 16 KiB (%d MiB), over its %d MiB budget", kept, kept*16>>10, budget>>20)
	}
	// The newest answer is still replayed to a retry, not run again.
	before := runs.Load()
	if code := call(fmt.Sprintf("req-gap0404-%06d", n-1)); code != http.StatusOK || runs.Load() != before {
		t.Fatalf("a retry of the newest call ran again (%d runs, code %d)", runs.Load()-before, code)
	}
	// Past IdempotencyTTL every answer leaves at the next call.
	now = now.Add(IdempotencyTTL + time.Second)
	if code := call("req-gap0404-after"); code != http.StatusOK {
		t.Fatal(code)
	}
	s.mu.Lock()
	kept = len(s.done)
	s.mu.Unlock()
	if kept != 1 {
		t.Fatalf("%d answers kept past IdempotencyTTL, want only the new one", kept)
	}
}
