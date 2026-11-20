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
	"context"
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/intentstore"
)

// lookupFailStore is a Reader whose Lookup fails (a shared store that does
// not answer).
type lookupFailStore struct{ *intentstore.Process }

func (lookupFailStore) Lookup(context.Context, string) (intentstore.Snapshot, bool, error) {
	return intentstore.Snapshot{}, false, errors.New("leader unreachable")
}

// The tool-result judges read the turn's request from the intent store, so a
// replica that did not see the turn's prompt gives the request the replica
// that saw it recorded; a store that cannot be read or fails gives no
// request, never this process's own copy (rel-1-0-10:GAP-0848).
func TestToolResultUserRequestReadsTheIntentStore(t *testing.T) {
	shared := intentstore.NewProcess(intentstore.Limits{MaxSessions: 8, MaxPrior: 4, TTL: toolJudgeContextTTL})
	saw, other := &LLMJudge{}, &LLMJudge{}
	saw.SetIntentStore(shared)
	other.SetIntentStore(shared)
	ctx := ContextWithSessionID(context.Background(), "tr-store-1")
	saw.ObserveSessionPrompt(ctx, "summarize the open tickets")
	if got := other.sessionUserIntent(ctx); got != "summarize the open tickets" {
		t.Fatalf("replica without the prompt: request %q, want the shared one", got)
	}
	// Reading records nothing: the next call still finds no earlier call.
	if snap, _ := shared.Peek(judgeSessionKey(ctx)); len(snap.Prior) != 0 {
		t.Fatalf("Lookup recorded a call: %+v", snap)
	}
	// A new turn seen by one replica is the request on every replica.
	other.ObserveSessionPrompt(ctx, "close the stale tickets")
	if got := saw.sessionUserIntent(ctx); got != "close the stale tickets" {
		t.Fatalf("older turn's request %q after a new prompt on another replica", got)
	}
	// A task this process cleared is no request, as in the tool-call sample.
	saw.ClearSessionTask(ctx)
	if got := saw.sessionUserIntent(ctx); got != "" {
		t.Fatalf("cleared task still given: %q", got)
	}

	// A store without Reader: no request, even though this process saw the
	// prompt and its scope table holds it.
	noRead := &LLMJudge{}
	noRead.SetIntentStore(&sharedIntentStore{})
	noRead.ObserveSessionPrompt(ctx, "export the report")
	if entry, _ := noRead.scopeSessions().get(judgeSessionKey(ctx)); entry.task == "" {
		t.Fatal("test setup: the scope table should hold the task")
	}
	if got := noRead.sessionUserIntent(ctx); got != "" {
		t.Fatalf("a store without Reader gave %q, want unknown", got)
	}

	// A Reader that fails: no request.
	failing := &LLMJudge{}
	failing.SetIntentStore(lookupFailStore{intentstore.NewProcess(intentstore.Limits{MaxSessions: 8, MaxPrior: 4, TTL: toolJudgeContextTTL})})
	failing.ObserveSessionPrompt(ctx, "export the report")
	if got := failing.sessionUserIntent(ctx); got != "" {
		t.Fatalf("a failed Lookup gave %q, want unknown", got)
	}
}
