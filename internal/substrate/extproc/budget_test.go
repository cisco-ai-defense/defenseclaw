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

package extproc

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type slowJudge struct {
	delay time.Duration
	calls atomic.Int32
}

func (s *slowJudge) JudgeToolCall(ctx context.Context, _ ToolCall) (ToolVerdict, error) {
	s.calls.Add(1)
	select {
	case <-time.After(s.delay):
		return ToolVerdict{}, nil
	case <-ctx.Done():
		return ToolVerdict{}, ctx.Err()
	}
}

// TestMessageBudget is GAP-0062: a JSON-RPC batch is judged within one
// budget under the egress filter's message timeout, and the hold and judge
// timeouts can't be set past it.
func TestMessageBudget(t *testing.T) {
	j := &slowJudge{delay: 100 * time.Millisecond}
	h := newHarness(t, func(_ *Config, o *Options) { o.Judge = j })
	calls := make([]string, 0, maxBatchCalls)
	for i := 0; i < maxBatchCalls; i++ {
		calls = append(calls, string(mcpCall("t")))
	}
	r := req("eng-web", "POST", "mcp.example.com", "/mcp")
	start := time.Now()
	v := h.eng.DecideBody(context.Background(), r, Verdict{Allow: true}, []byte("["+strings.Join(calls, ",")+"]"))
	took := time.Since(start)
	if v.Allow || v.Category != CategoryCalloutError {
		t.Fatalf("batch over the budget: %+v", v)
	}
	if took > MessageBudget+300*time.Millisecond || int(j.calls.Load()) >= maxBatchCalls {
		t.Fatalf("took %s for %d calls; budget %s", took, j.calls.Load(), MessageBudget)
	}
	for _, doc := range []string{"ask:\n  hold: 2s\n", "judge:\n  timeout: 1h\n"} {
		if _, err := ParseConfig([]byte(doc)); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
	if _, err := ParseConfig([]byte("ask:\n  hold: 1800ms\njudge:\n  timeout: 1800ms\n")); err != nil {
		t.Errorf("budget-sized timeouts refused: %v", err)
	}
}
