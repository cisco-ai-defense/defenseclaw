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
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/capability"
)

func TestLoadPolicy(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr bool
		agent   string
		caps    int
	}{
		{
			name:  "valid support-bot",
			file:  "support-bot.capability.yaml",
			agent: "support-bot",
			caps:  3,
		},
		{
			name:  "valid admin-agent",
			file:  "admin-agent.capability.yaml",
			agent: "admin-agent",
			caps:  3,
		},
		{
			name:  "valid readonly-agent",
			file:  "readonly-agent.capability.yaml",
			agent: "readonly-agent",
			caps:  2,
		},
		{
			name:    "invalid missing agent",
			file:    "invalid-missing-agent.capability.yaml",
			wantErr: true,
		},
		{
			name:    "invalid bad constraint",
			file:    "invalid-bad-constraint.capability.yaml",
			wantErr: true,
		},
	}

	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "capabilities")

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(fixtureDir, tt.file)
			pol, err := capability.LoadPolicy(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadPolicy: %v", err)
			}
			if pol.Agent != tt.agent {
				t.Errorf("agent = %q, want %q", pol.Agent, tt.agent)
			}
			if len(pol.Capabilities) != tt.caps {
				t.Errorf("capabilities = %d, want %d", len(pol.Capabilities), tt.caps)
			}
		})
	}
}

func TestLoadAllPolicies(t *testing.T) {
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "capabilities")
	policies, errs := capability.LoadAllPolicies(context.Background(), fixtureDir)

	// 3 valid, 2 invalid
	if len(policies) != 3 {
		t.Errorf("loaded %d policies, want 3", len(policies))
	}
	if len(errs) != 2 {
		t.Errorf("got %d errors, want 2", len(errs))
	}

	if _, ok := policies["support-bot"]; !ok {
		t.Error("missing support-bot policy")
	}
	if _, ok := policies["admin-agent"]; !ok {
		t.Error("missing admin-agent policy")
	}
	if _, ok := policies["readonly-agent"]; !ok {
		t.Error("missing readonly-agent policy")
	}
}

func TestMatchConstraints(t *testing.T) {
	tests := []struct {
		name        string
		constraints map[string]any
		params      map[string]any
		want        bool
	}{
		{
			name:        "empty constraints match anything",
			constraints: map[string]any{},
			params:      map[string]any{"project": "ENG-123"},
			want:        true,
		},
		{
			name:        "glob match success",
			constraints: map[string]any{"project": "ENG-*"},
			params:      map[string]any{"project": "ENG-123"},
			want:        true,
		},
		{
			name:        "glob match failure",
			constraints: map[string]any{"project": "ENG-*"},
			params:      map[string]any{"project": "SALES-456"},
			want:        false,
		},
		{
			name:        "exact match success",
			constraints: map[string]any{"channel": "#support"},
			params:      map[string]any{"channel": "#support"},
			want:        true,
		},
		{
			name:        "exact match failure",
			constraints: map[string]any{"channel": "#support"},
			params:      map[string]any{"channel": "#general"},
			want:        false,
		},
		{
			name:        "list membership all present",
			constraints: map[string]any{"fields": []any{"summary", "status"}},
			params:      map[string]any{"fields": []any{"summary"}},
			want:        true,
		},
		{
			name:        "list membership not in allowed",
			constraints: map[string]any{"fields": []any{"summary", "status"}},
			params:      map[string]any{"fields": []any{"password"}},
			want:        false,
		},
		{
			name:        "missing param key is denied",
			constraints: map[string]any{"project": "ENG-*"},
			params:      map[string]any{},
			want:        false,
		},
		{
			name:        "nil params with constraints is denied",
			constraints: map[string]any{"project": "ENG-*"},
			params:      nil,
			want:        false,
		},
		{
			name:        "nil constraints match anything",
			constraints: nil,
			params:      map[string]any{"anything": "goes"},
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capability.MatchConstraints(tt.constraints, tt.params)
			if got != tt.want {
				t.Errorf("MatchConstraints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func newTestEvaluator(t *testing.T) *capability.Evaluator {
	t.Helper()
	store := newTestStore(t)
	fixtureDir := filepath.Join("..", "..", "test", "fixtures", "capabilities")
	eval, err := capability.NewEvaluator(context.Background(), fixtureDir, store)
	if err != nil {
		t.Fatalf("NewEvaluator: %v", err)
	}
	return eval
}

func TestEvaluateUnknownAgent(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:    "nonexistent",
		Resource: "jira.get_issue",
	})
	if dec.Allowed {
		t.Fatal("expected deny for unknown agent")
	}
	if dec.Reason != "unknown agent" {
		t.Errorf("reason = %q, want %q", dec.Reason, "unknown agent")
	}
}

func TestEvaluateRestricted(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "readonly-agent",
		Resource:    "jira.delete_issue",
		Environment: "production",
	})
	if dec.Allowed {
		t.Fatal("expected deny for restricted resource")
	}
}

func TestEvaluateNoCapability(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "github.create_pr",
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny for resource with no capability")
	}
	if dec.Reason != "no capability for resource" {
		t.Errorf("reason = %q", dec.Reason)
	}
}

func TestEvaluateConstraintMatch(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "ENG-123", "fields": []any{"summary"}},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if !dec.Allowed {
		t.Fatalf("expected allow, got deny: %s", dec.Reason)
	}
	if dec.Capability != "read_jira_ticket" {
		t.Errorf("capability = %q, want %q", dec.Capability, "read_jira_ticket")
	}
}

func TestEvaluateConstraintMismatch(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:       "support-bot",
		Resource:    "jira.get_issue",
		Params:      map[string]any{"project": "SALES-456"},
		Environment: "production",
		Timestamp:   time.Date(2026, 4, 8, 12, 0, 0, 0, time.UTC),
	})
	if dec.Allowed {
		t.Fatal("expected deny for constraint mismatch")
	}
}

func TestEvaluateAdminWildcard(t *testing.T) {
	eval := newTestEvaluator(t)
	dec := eval.Evaluate(context.Background(), capability.EvalRequest{
		Agent:    "admin-agent",
		Resource: "jira.delete_issue",
		Params:   map[string]any{},
	})
	if !dec.Allowed {
		t.Fatalf("expected allow for admin wildcard, got deny: %s", dec.Reason)
	}
}
