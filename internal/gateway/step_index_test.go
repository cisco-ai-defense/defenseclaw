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

package gateway

import (
	"sync"
	"testing"
)

// TestStepIndexForTurn_TurnIDPrimary pins the primary turn-boundary
// signal (checkpoint C3): a turn is one prompt-response cycle within a
// session. All events sharing a TurnID return the SAME 1-indexed step;
// a new TurnID increments; sessions are independent.
func TestStepIndexForTurn_TurnIDPrimary(t *testing.T) {
	api := &APIServer{}

	// First turn of session A -> 1, repeated events in the same turn
	// keep returning 1.
	if got := api.stepIndexForTurn("sessA", "turn-1", "pre_tool_call"); got != 1 {
		t.Fatalf("turn-1 first event = %d, want 1", got)
	}
	if got := api.stepIndexForTurn("sessA", "turn-1", "post_tool_call"); got != 1 {
		t.Errorf("turn-1 second event = %d, want 1 (same turn shares step)", got)
	}
	// New turn -> 2.
	if got := api.stepIndexForTurn("sessA", "turn-2", "pre_tool_call"); got != 2 {
		t.Errorf("turn-2 = %d, want 2", got)
	}
	// Revisiting turn-1 still returns its pinned index.
	if got := api.stepIndexForTurn("sessA", "turn-1", "pre_tool_call"); got != 1 {
		t.Errorf("revisit turn-1 = %d, want 1 (pinned)", got)
	}
	// Independent session starts its own counter at 1.
	if got := api.stepIndexForTurn("sessB", "turn-1", "pre_tool_call"); got != 1 {
		t.Errorf("sessB turn-1 = %d, want 1 (session-independent)", got)
	}
}

// TestStepIndexForTurn_NoTurnIDFallback pins the fallback path: with no
// TurnID, a prompt-class event opens a new turn while tool events
// inherit the current turn, and the first event bootstraps to 1.
func TestStepIndexForTurn_NoTurnIDFallback(t *testing.T) {
	api := &APIServer{}

	// First event (a tool call, no prompt yet) bootstraps to turn 1.
	if got := api.stepIndexForTurn("s", "", "pre_tool_call"); got != 1 {
		t.Fatalf("bootstrap event = %d, want 1", got)
	}
	// A subsequent tool event inherits the current turn.
	if got := api.stepIndexForTurn("s", "", "post_tool_call"); got != 1 {
		t.Errorf("tool event = %d, want 1 (inherits current turn)", got)
	}
	// A prompt-class event opens the next turn.
	if got := api.stepIndexForTurn("s", "", "UserPromptSubmit"); got != 2 {
		t.Errorf("prompt event = %d, want 2 (new turn)", got)
	}
	// Tool events after the prompt stay in turn 2.
	if got := api.stepIndexForTurn("s", "", "pre_tool_call"); got != 2 {
		t.Errorf("post-prompt tool event = %d, want 2", got)
	}
	// Another prompt opens turn 3.
	if got := api.stepIndexForTurn("s", "", "user_prompt_submit"); got != 3 {
		t.Errorf("second prompt = %d, want 3", got)
	}
}

// TestStepIndexForTurn_EmptySession returns 0 ("not turn-anchored")
// when there is no session id to anchor the counter to.
func TestStepIndexForTurn_EmptySession(t *testing.T) {
	api := &APIServer{}
	if got := api.stepIndexForTurn("", "turn-1", "pre_tool_call"); got != 0 {
		t.Errorf("empty session = %d, want 0", got)
	}
	if got := api.stepIndexForTurn("   ", "", "UserPromptSubmit"); got != 0 {
		t.Errorf("whitespace session = %d, want 0", got)
	}
}

// TestStepIndexForTurn_Concurrent exercises the mutex under -race: many
// goroutines hammering distinct sessions must not corrupt the map or
// the per-session counters.
func TestStepIndexForTurn_Concurrent(t *testing.T) {
	api := &APIServer{}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			sess := "sess-" + string(rune('A'+n%26))
			for j := 0; j < 100; j++ {
				_ = api.stepIndexForTurn(sess, "", "pre_tool_call")
			}
		}(i)
	}
	wg.Wait()
}
