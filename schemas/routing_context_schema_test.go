// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package schemas

import "testing"

func TestDefenseClawConfigV8RoutingContextSchema(t *testing.T) {
	t.Parallel()
	schema := compileConfigV8Schema(t)
	doc := func(ctx map[string]any) map[string]any {
		return map[string]any{"config_version": 8, "routing": map[string]any{"classifier": "rules", "context": ctx}}
	}
	valid := map[string]any{
		"recent_user_turns": 8, "include_first_user_turn": true, "max_bytes": 65536,
		"per_turn_bytes": 2048, "include_tool_names": true,
	}
	if err := schema.Validate(doc(valid)); err != nil {
		t.Fatalf("valid routing.context rejected: %v", err)
	}
	if err := schema.Validate(doc(map[string]any{})); err != nil {
		t.Fatalf("empty routing.context rejected: %v", err)
	}
	for name, ctx := range map[string]map[string]any{
		"too many turns":      {"recent_user_turns": 9},
		"negative turns":      {"recent_user_turns": -1},
		"max_bytes too large": {"max_bytes": 65537},
		"per_turn too large":  {"per_turn_bytes": 65537},
		"unknown key":         {"include_tool_results": true},
		"non-boolean":         {"include_tool_names": "yes"},
	} {
		if err := schema.Validate(doc(ctx)); err == nil {
			t.Fatalf("%s: routing.context %v accepted", name, ctx)
		}
	}
	locked := map[string]any{"config_version": 8, "routing": map[string]any{"admin": map[string]any{"locked": []any{"context"}}}}
	if err := schema.Validate(locked); err != nil {
		t.Fatalf("routing.admin.locked [context] rejected: %v", err)
	}
}
