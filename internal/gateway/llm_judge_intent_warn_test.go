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
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/intentstore"
)

// failingIntentStore fails every call, as a shared store whose leader is
// unreachable does.
type failingIntentStore struct{}

func (failingIntentStore) ObservePrompt(context.Context, string, string) error {
	return errors.New("leader: unavailable: not reachable")
}

func (failingIntentStore) AppendToolCall(context.Context, string, intentstore.ToolCall) (intentstore.Snapshot, error) {
	return intentstore.Snapshot{}, errors.New("leader: unavailable: not reachable")
}

func (failingIntentStore) Reset(context.Context, string) error {
	return errors.New("leader: unavailable: not reachable")
}

// A failing intent store is no longer silent: the judge writes one warning
// per minute that names the operation and its consequence, counts the
// failures it held back, and never prints the session key or the intent.
func TestLLMJudgeWarnsWhenItsIntentStoreFails(t *testing.T) {
	var out bytes.Buffer
	clock := time.Date(2026, 11, 12, 21, 0, 0, 0, time.UTC)
	judge := &LLMJudge{intentWarnOut: &out, intentWarnNow: func() time.Time { return clock }}
	judge.SetIntentStore(failingIntentStore{})
	ctx := ContextWithSessionID(context.Background(), "session-secret-key")

	judge.ObserveSessionPrompt(ctx, "rotate the production credentials")
	sample := judge.toolJudgeContextSample(ctx, "Bash", `{"command":"ls"}`)
	judge.ResetToolJudgeSession("session-secret-key")
	if strings.Contains(sample, "SESSION_USER_INTENT") || !strings.Contains(sample, "ls") {
		t.Fatalf("a failed store must leave the call judged on its own:\n%s", sample)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("want one warning inside the minute, got %d:\n%s", len(lines), out.String())
	}
	for _, want := range []string{"[judge] warning: intent store ObservePrompt failed", "leader: unavailable", "not recorded"} {
		if !strings.Contains(lines[0], want) {
			t.Fatalf("warning lacks %q: %s", want, lines[0])
		}
	}
	for _, leak := range []string{"session-secret-key", "production credentials"} {
		if strings.Contains(out.String(), leak) {
			t.Fatalf("warning leaks %q: %s", leak, out.String())
		}
	}

	clock = clock.Add(intentStoreWarnEvery)
	judge.toolJudgeContextSample(ctx, "Bash", `{"command":"pwd"}`)
	lines = strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want a second warning after the interval, got:\n%s", out.String())
	}
	for _, want := range []string{"AppendToolCall failed (2 more failures since the last warning)", "judged without its session intent"} {
		if !strings.Contains(lines[1], want) {
			t.Fatalf("second warning lacks %q: %s", want, lines[1])
		}
	}

	// A store that works writes nothing.
	out.Reset()
	healthy := &LLMJudge{intentWarnOut: &out}
	healthy.ObserveSessionPrompt(ctx, "local intent")
	healthy.toolJudgeContextSample(ctx, "Bash", "{}")
	healthy.ResetToolJudgeSession("session-secret-key")
	if out.Len() != 0 {
		t.Fatalf("a working store warned: %s", out.String())
	}
}
