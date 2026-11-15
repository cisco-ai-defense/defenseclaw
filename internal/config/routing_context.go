// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strings"
)

// RoutingContextConfig is routing.context (1.0.10, rel-1-0-10:GAP-0002):
// bounded recent context for the router. The classifier and the keyword
// signals see the newest human-typed user turn, then up to RecentUserTurns
// older ones (and the first one when IncludeFirstUserTurn), newest first.
// Only text the user typed is read: never tool results, assistant text,
// system prompts or file contents. The zero value is off: the router reads
// the newest typed turn only, as before.
type RoutingContextConfig struct {
	// RecentUserTurns is the number of older user turns read (0 to 8).
	RecentUserTurns int `mapstructure:"recent_user_turns" yaml:"recent_user_turns,omitempty"`
	// IncludeFirstUserTurn also reads the first user turn of the
	// conversation (the task statement of an agent loop).
	IncludeFirstUserTurn bool `mapstructure:"include_first_user_turn" yaml:"include_first_user_turn,omitempty"`
	// MaxBytes bounds the context text (0 = 8192, at most 65536).
	MaxBytes int `mapstructure:"max_bytes" yaml:"max_bytes,omitempty"`
	// PerTurnBytes bounds one turn in it (0 = 2048, at most max_bytes).
	PerTurnBytes int `mapstructure:"per_turn_bytes" yaml:"per_turn_bytes,omitempty"`
	// IncludeToolNames lets keyword signals see the names of the tools the
	// loop called (never their arguments or results) and turns on the
	// request condition tool_loop.
	IncludeToolNames bool `mapstructure:"include_tool_names" yaml:"include_tool_names,omitempty"`
}

// Bounds of routing.context.
const (
	RoutingContextMaxRecentUserTurns  = 8
	RoutingContextDefaultMaxBytes     = 8192
	RoutingContextMaxBytesLimit       = 65536
	RoutingContextDefaultPerTurnBytes = 2048
)

// RoutingRequestToolLoop is the request condition that matches a request
// whose conversation called a tool (needs routing.context.include_tool_names).
const RoutingRequestToolLoop = "tool_loop"

// IsZero reports whether routing.context sets nothing (YAML omitempty).
func (c RoutingContextConfig) IsZero() bool { return c == RoutingContextConfig{} }

// Active reports whether routing.context reads anything beyond the newest
// user turn. max_bytes and per_turn_bytes alone change nothing.
func (c RoutingContextConfig) Active() bool {
	return c.RecentUserTurns > 0 || c.IncludeFirstUserTurn || c.IncludeToolNames
}

// EffectiveMaxBytes returns max_bytes with its default.
func (c RoutingContextConfig) EffectiveMaxBytes() int {
	if c.MaxBytes <= 0 {
		return RoutingContextDefaultMaxBytes
	}
	return c.MaxBytes
}

// EffectivePerTurnBytes returns per_turn_bytes with its default, never
// above the effective max_bytes.
func (c RoutingContextConfig) EffectivePerTurnBytes() int {
	n := c.PerTurnBytes
	if n <= 0 {
		n = RoutingContextDefaultPerTurnBytes
	}
	return min(n, c.EffectiveMaxBytes())
}

func (r *RoutingConfig) validateContext() error {
	c := r.Context
	if c.RecentUserTurns < 0 || c.RecentUserTurns > RoutingContextMaxRecentUserTurns {
		return fmt.Errorf("context.recent_user_turns must be between 0 and %d, got %d", RoutingContextMaxRecentUserTurns, c.RecentUserTurns)
	}
	if c.MaxBytes < 0 || c.MaxBytes > RoutingContextMaxBytesLimit {
		return fmt.Errorf("context.max_bytes must be between 1 and %d (or 0 for %d), got %d", RoutingContextMaxBytesLimit, RoutingContextDefaultMaxBytes, c.MaxBytes)
	}
	if c.PerTurnBytes < 0 || c.PerTurnBytes > c.EffectiveMaxBytes() {
		return fmt.Errorf("context.per_turn_bytes must be between 1 and context.max_bytes (%d), or 0 for %d, got %d", c.EffectiveMaxBytes(), RoutingContextDefaultPerTurnBytes, c.PerTurnBytes)
	}
	if c.Active() && r.EffectiveClassifier() == RoutingClassifierVLLMSR {
		return fmt.Errorf("context needs classifier rules or systemone (vllm_sr classifies the newest user turn only)")
	}
	if c.IncludeToolNames {
		return nil
	}
	for i, d := range r.Decisions {
		for j, cond := range d.Conditions {
			if strings.EqualFold(strings.TrimSpace(cond.Type), RoutingConditionRequest) && strings.TrimSpace(cond.Name) == RoutingRequestToolLoop {
				return fmt.Errorf("decisions[%d].conditions[%d] request condition %s needs context.include_tool_names: true", i, j, RoutingRequestToolLoop)
			}
		}
	}
	return nil
}
