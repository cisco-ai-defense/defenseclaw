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
	"fmt"
	"reflect"
	"testing"
	"time"
)

type testClock struct{ at time.Time }

func (c *testClock) now() time.Time { return c.at }

func newTestProcess(limits Limits) (*Process, *testClock) {
	clock := &testClock{at: time.Unix(1_800_000_000, 0)}
	p := NewProcess(limits)
	p.now = clock.now
	return p, clock
}

func TestProcessKeepsIntentAndPriorCalls(t *testing.T) {
	ctx := context.Background()
	p, _ := newTestProcess(Limits{MaxSessions: 8, MaxPrior: 2, TTL: time.Minute})
	if err := p.ObservePrompt(ctx, "s1", "fix the build"); err != nil {
		t.Fatal(err)
	}
	var got []Snapshot
	for i := 1; i <= 4; i++ {
		snap, err := p.AppendToolCall(ctx, "s1", ToolCall{Tool: "Bash", Args: fmt.Sprint(i)})
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, snap)
	}
	want := []Snapshot{
		{UserIntent: "fix the build"},
		{UserIntent: "fix the build", Prior: []ToolCall{{"Bash", "1"}}},
		{UserIntent: "fix the build", Prior: []ToolCall{{"Bash", "1"}, {"Bash", "2"}}},
		{UserIntent: "fix the build", Prior: []ToolCall{{"Bash", "2"}, {"Bash", "3"}}},
	}
	for i := range want {
		if got[i].UserIntent != want[i].UserIntent || len(got[i].Prior) != len(want[i].Prior) ||
			(len(want[i].Prior) > 0 && !reflect.DeepEqual(got[i].Prior, want[i].Prior)) {
			t.Fatalf("call %d: %+v, want %+v", i+1, got[i], want[i])
		}
	}
	// A new prompt starts a new chain; another key never sees this one.
	_ = p.ObservePrompt(ctx, "s1", "now the docs")
	if snap, _ := p.AppendToolCall(ctx, "s1", ToolCall{Tool: "Read"}); snap.UserIntent != "now the docs" || len(snap.Prior) != 0 {
		t.Fatalf("after a new prompt: %+v", snap)
	}
	if snap, _ := p.AppendToolCall(ctx, "s2", ToolCall{Tool: "Read"}); snap.UserIntent != "" || len(snap.Prior) != 0 {
		t.Fatalf("other key: %+v", snap)
	}
	_ = p.Reset(ctx, "s1")
	if _, ok := p.Peek("s1"); ok {
		t.Fatal("reset kept the key")
	}
}

// A full store drops idle keys first, then the least recently used.
func TestProcessPrunesWhenFull(t *testing.T) {
	ctx := context.Background()
	p, clock := newTestProcess(Limits{MaxSessions: 3, MaxPrior: 7, TTL: 30 * time.Minute})
	for _, key := range []string{"a", "b", "c"} {
		_ = p.ObservePrompt(ctx, key, key)
		clock.at = clock.at.Add(time.Minute)
	}
	_ = p.ObservePrompt(ctx, "d", "d")
	if _, ok := p.Peek("a"); ok {
		t.Fatal("least recently used key kept")
	}
	for _, key := range []string{"b", "c", "d"} {
		if _, ok := p.Peek(key); !ok {
			t.Fatalf("%s dropped", key)
		}
	}
	clock.at = clock.at.Add(time.Hour)
	_ = p.ObservePrompt(ctx, "c", "c again")
	_ = p.ObservePrompt(ctx, "e", "e")
	// The full store pruned b and d (idle past the TTL) before e came in.
	for key, want := range map[string]bool{"b": false, "d": false, "c": true, "e": true} {
		if _, ok := p.Peek(key); ok != want {
			t.Fatalf("%s kept=%t, want %t", key, ok, want)
		}
	}
}

func TestProcessCallCountSumsEverySession(t *testing.T) {
	p, _ := newTestProcess(Limits{MaxSessions: 4, MaxPrior: 4, TTL: time.Hour})
	ctx := context.Background()
	if n := p.CallCount(); n != 0 {
		t.Fatalf("empty store counts %d calls", n)
	}
	_, _ = p.AppendToolCall(ctx, "a", ToolCall{Tool: "Bash", Args: "1"})
	_, _ = p.AppendToolCall(ctx, "a", ToolCall{Tool: "Bash", Args: "2"})
	_, _ = p.AppendToolCall(ctx, "b", ToolCall{Tool: "Read", Args: "3"})
	if n := p.CallCount(); n != 3 {
		t.Fatalf("CallCount = %d, want 3 across two sessions", n)
	}
}
