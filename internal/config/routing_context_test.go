// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRoutingContextValidate(t *testing.T) {
	toolLoop := func(r *RoutingConfig) {
		r.Decisions = append([]RoutingDecisionRule{{Name: "loop", Conditions: []RoutingCondition{{Type: "request", Name: "tool_loop"}}, ModelRefs: []string{"fast"}}}, r.Decisions...)
	}
	for _, tc := range []struct {
		name string
		edit func(*RoutingConfig)
		want string
	}{
		{"zero is off", func(*RoutingConfig) {}, ""},
		{"every key", func(r *RoutingConfig) {
			r.Classifier = "rules"
			r.Context = RoutingContextConfig{RecentUserTurns: 8, IncludeFirstUserTurn: true, MaxBytes: 65536, PerTurnBytes: 65536, IncludeToolNames: true}
		}, ""},
		{"max_bytes alone is inactive and valid with vllm_sr", func(r *RoutingConfig) { r.Classifier = "vllm_sr"; r.Context.MaxBytes = 100 }, ""},
		{"too many turns", func(r *RoutingConfig) { r.Context.RecentUserTurns = 9 }, "context.recent_user_turns must be between 0 and 8"},
		{"negative turns", func(r *RoutingConfig) { r.Context.RecentUserTurns = -1 }, "context.recent_user_turns"},
		{"max_bytes over the limit", func(r *RoutingConfig) { r.Context.MaxBytes = 65537 }, "context.max_bytes"},
		{"per_turn_bytes over max_bytes", func(r *RoutingConfig) { r.Context.MaxBytes = 1024; r.Context.PerTurnBytes = 2048 }, "context.per_turn_bytes"},
		{"per_turn_bytes over the default max_bytes", func(r *RoutingConfig) { r.Context.PerTurnBytes = 8193 }, "context.per_turn_bytes"},
		{"vllm_sr reads the newest turn only", func(r *RoutingConfig) { r.Classifier = "vllm_sr"; r.Context.RecentUserTurns = 1 }, "context needs classifier rules or systemone"},
		{"tool_loop needs include_tool_names", func(r *RoutingConfig) { r.Classifier = "rules"; toolLoop(r) }, "request condition tool_loop needs context.include_tool_names"},
		{"tool_loop with include_tool_names", func(r *RoutingConfig) { r.Classifier = "rules"; toolLoop(r); r.Context.IncludeToolNames = true }, ""},
		{"context is lockable", func(r *RoutingConfig) { r.Admin = &RoutingAdminConfig{Locked: []string{"context"}} }, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := validRoutingConfigForTest()
			tc.edit(&r)
			err := r.Validate()
			if tc.want == "" && err != nil {
				t.Fatalf("Validate() = %v", err)
			}
			if tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("Validate() = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestRoutingContextDefaults(t *testing.T) {
	var c RoutingContextConfig
	if c.Active() || !c.IsZero() || c.EffectiveMaxBytes() != 8192 || c.EffectivePerTurnBytes() != 2048 {
		t.Fatalf("zero context = active %v, %d/%d", c.Active(), c.EffectiveMaxBytes(), c.EffectivePerTurnBytes())
	}
	c = RoutingContextConfig{MaxBytes: 1000}
	if c.Active() || c.EffectivePerTurnBytes() != 1000 {
		t.Fatalf("per_turn default above max_bytes = %d, want 1000", c.EffectivePerTurnBytes())
	}
	for _, on := range []RoutingContextConfig{{RecentUserTurns: 1}, {IncludeFirstUserTurn: true}, {IncludeToolNames: true}} {
		if !on.Active() {
			t.Fatalf("%+v is not active", on)
		}
	}
}

func TestRoutingContextYAMLAndMinVersion(t *testing.T) {
	out, err := yaml.Marshal(RoutingConfig{Enabled: true})
	if err != nil || strings.Contains(string(out), "context") {
		t.Fatalf("an unset routing.context is written: %s %v", out, err)
	}
	cfg, err := LoadRuntimeV8FromBytes("config.yaml", []byte("config_version: 9\nrouting:\n  classifier: rules\n  context:\n    recent_user_turns: 2\n    include_first_user_turn: true\n    max_bytes: 4096\n    per_turn_bytes: 1024\n    include_tool_names: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := RoutingContextConfig{RecentUserTurns: 2, IncludeFirstUserTurn: true, MaxBytes: 4096, PerTurnBytes: 1024, IncludeToolNames: true}
	if cfg.Routing.Context != want {
		t.Fatalf("loaded %+v, want %+v", cfg.Routing.Context, want)
	}
	// Upgrade (testdata/upgrade/1.0.9 keeps its golden): a routing block
	// without the key loads with routing.context off and needs no 1.0.10 floor.
	old := "config_version: 9\nrouting:\n  enabled: true\n  version: 0.3.0\n  models:\n    - {name: fast, provider: ollama, model: m}\n  decisions:\n    - {name: d, model_refs: [fast]}\n"
	if cfg, err = LoadRuntimeV8FromBytes("config.yaml", []byte(old)); err != nil {
		t.Fatal(err)
	}
	if cfg.Routing.Context.Active() || !cfg.Routing.Context.IsZero() || RoutingMinVersionKeysInRaw([]byte(old)) != nil {
		t.Fatalf("a 1.0.9 routing block loads context %+v", cfg.Routing.Context)
	}
	if keys := RoutingMinVersionKeysInRaw([]byte("routing:\n  context: {}\n")); !slices.Contains(keys, "routing.context") {
		t.Fatalf("min-version keys = %v, want routing.context", keys)
	}
	if !slices.Contains(RoutingLockableKeys, "context") || !slices.Contains(RoutingRequestConditions, RoutingRequestToolLoop) {
		t.Fatal("context is not lockable or tool_loop is not a request condition")
	}
}
