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

package unit

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestTimeWindowInside(t *testing.T) {
	eval := newTestEvaluator(t)
	// support-bot has time_window: "09:00-18:00"
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow inside time window, got deny: %s", dec.Reason)
	}
}

func TestTimeWindowOutside(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 3, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny outside time window")
	}
}

func TestTimeWindowEdgeStart(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 9, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow at window start, got deny: %s", dec.Reason)
	}
}

func TestTimeWindowEdgeEnd(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 18, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny at window end (exclusive)")
	}
}

func TestEnvironmentAllowed(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "staging",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow for staging, got deny: %s", dec.Reason)
	}
}

func TestEnvironmentDisallowed(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "dev",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny for dev environment")
	}
}

func TestEnvironmentEmptyAllowsAll(t *testing.T) {
	eval := newTestEvaluator(t)
	// admin-agent has no environments restriction
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "admin-agent",
		Resource:    "jira.get_issue",
		Params:      map[string]any{},
		Environment: "any-env",
	})
	if !dec.Allowed {
		t.Fatalf("expected allow with empty environments, got deny: %s", dec.Reason)
	}
}

func TestRateLimitUnder(t *testing.T) {
	eval := newTestEvaluator(t)
	// support-bot has rate_limit: max_calls=100, window_seconds=3600
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow under rate limit, got deny: %s", dec.Reason)
	}
}

func TestCombinedConditionsFail(t *testing.T) {
	eval := newTestEvaluator(t)
	// Wrong environment AND outside time window
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-1", "fields": []any{"summary"}},
		Environment: "dev",
		Timestamp:   time.Date(2026, 4, 8, 3, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny when multiple conditions fail")
	}
}
