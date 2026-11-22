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

package intentstore

import (
	"context"
	"testing"
	"time"
)

// Lookup returns what the next AppendToolCall would find and records
// nothing (rel-1-0-10:GAP-0848).
func TestProcessLookupIsReadOnly(t *testing.T) {
	ctx := context.Background()
	p := NewProcess(Limits{MaxSessions: 4, MaxPrior: 4, TTL: time.Hour})
	if _, ok, err := p.Lookup(ctx, "s1"); ok || err != nil {
		t.Fatalf("empty store: ok=%v err=%v", ok, err)
	}
	_ = p.ObservePrompt(ctx, "s1", "build the docs")
	_, _ = p.AppendToolCall(ctx, "s1", ToolCall{Tool: "Bash", Args: "make docs"})
	for range 3 {
		snap, ok, err := p.Lookup(ctx, "s1")
		if !ok || err != nil || snap.UserIntent != "build the docs" || len(snap.Prior) != 1 {
			t.Fatalf("lookup: %+v ok=%v err=%v", snap, ok, err)
		}
	}
	next, _ := p.AppendToolCall(ctx, "s1", ToolCall{Tool: "Read", Args: "README"})
	if len(next.Prior) != 1 {
		t.Fatalf("Lookup recorded calls: the next append found %d earlier calls, want 1", len(next.Prior))
	}
}
