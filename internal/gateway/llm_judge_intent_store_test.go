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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/intentstore"
)

// sharedIntentStore stands in for a store several replicas share.
type sharedIntentStore struct {
	intent  string
	fail    bool
	appends []string
	resets  []string
}

func (s *sharedIntentStore) ObservePrompt(_ context.Context, _ string, intent string) error {
	s.intent = intent
	return nil
}

func (s *sharedIntentStore) AppendToolCall(_ context.Context, key string, call intentstore.ToolCall) (intentstore.Snapshot, error) {
	s.appends = append(s.appends, key+"/"+call.Tool)
	if s.fail {
		return intentstore.Snapshot{}, errors.New("leader unreachable")
	}
	return intentstore.Snapshot{UserIntent: s.intent, Prior: []intentstore.ToolCall{{Tool: "Read", Args: "README"}}}, nil
}

func (s *sharedIntentStore) Reset(_ context.Context, key string) error {
	s.resets = append(s.resets, key)
	return nil
}

// The judge reads and writes a session's intent only through its store: a
// store set with SetIntentStore is the one every call sees, and a store
// that fails leaves the call judged on its own.
func TestLLMJudgeUsesItsIntentStore(t *testing.T) {
	store := &sharedIntentStore{}
	judge := &LLMJudge{}
	judge.SetIntentStore(store)
	ctx := ContextWithSessionID(context.Background(), "s1")
	judge.ObserveSessionPrompt(ctx, "deploy the web app")
	sample := judge.toolJudgeContextSample(ctx, "Bash", `{"command":"make deploy"}`)
	for _, want := range []string{"deploy the web app", `<RECENT_TOOL_CALL index=1 tool="Read">`, "README", "make deploy"} {
		if !strings.Contains(sample, want) {
			t.Fatalf("sample lacks %q:\n%s", want, sample)
		}
	}
	judge.ResetToolJudgeSession("s1")
	if len(store.appends) != 1 || store.appends[0] != "s1/Bash" || len(store.resets) != 1 || store.resets[0] != "s1" {
		t.Fatalf("store calls: appends %v resets %v", store.appends, store.resets)
	}

	store.fail = true
	sample = judge.toolJudgeContextSample(ctx, "Bash", `{"command":"ls"}`)
	if strings.Contains(sample, "SESSION_USER_INTENT") || strings.Contains(sample, "RECENT_TOOL_CALL") || !strings.Contains(sample, "ls") {
		t.Fatalf("failed store sample:\n%s", sample)
	}

	// A judge built as a literal keeps its own process-local context.
	plain := &LLMJudge{}
	plain.ObserveSessionPrompt(ctx, "local intent")
	if sample := plain.toolJudgeContextSample(ctx, "Bash", "{}"); !strings.Contains(sample, "local intent") {
		t.Fatalf("default store lost the intent:\n%s", sample)
	}
}
