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

package config

import (
	"fmt"
	"sort"
	"strings"
)

// guardrail.cascade.lanes: the live/shadow switch of a guardrail lane.
//
// INTERIM TYPE, owned by s7/cascade-config. Until that branch (the full
// guardrail.cascade block, with scopes, locks and the lane registry) is in
// this tree, the block holds only the lane switch below, at the global scope.
// The key (guardrail.cascade.lanes.<lane>) and the value set (on, shadow, off,
// read case-insensitively) are the ones cascade-config takes, so its
// CascadeConfig replaces GuardrailCascade, its validator and its schema and
// Python field replace these, and the reads through
// GuardrailConfig.NonShellLaneMode move to ResolveCascade(connector).LaneMode.
// Until then the lane fails toward rel/1.0.10: it is live only for the value
// "on" (or no value).

// Lane names under guardrail.cascade.lanes.
const (
	// NonShellLane is the MCP and app tool lane (internal/toolshape and the
	// gateway's nonShellToolFindings and shellToolFindings).
	NonShellLane = "nonshell"

	laneValueShadow = "shadow"
	laneValueOn     = "on"
	laneValueOff    = "off"
)

// GuardrailCascade is guardrail.cascade.
type GuardrailCascade struct {
	// Lanes maps a lane to on, shadow or off (any case). A lane that is not
	// listed has its shipped default (nonshell: on).
	Lanes map[string]string `mapstructure:"lanes" yaml:"lanes,omitempty" json:"lanes,omitempty"`
}

// normalizeLaneValue is a lane value as the loader and the gateway read it:
// trimmed and lower-cased.
func normalizeLaneValue(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

// NonShellLaneMode is the normalized guardrail.cascade.lanes.nonshell: "on"
// (the default, also for a nil config and an unset lane), "shadow" or "off".
// Only "on" is live: in shadow and in off the lane computes nothing and adds
// nothing, so the verdicts are those of a build without it. A value the loader
// refuses (validateGuardrailCascade) reads as "shadow" here, so a config that
// was never validated can not turn the lane on by a spelling.
func (g *GuardrailConfig) NonShellLaneMode() string {
	if g == nil {
		return laneValueOn
	}
	v, set := g.Cascade.Lanes[NonShellLane]
	if !set {
		return laneValueOn
	}
	switch mode := normalizeLaneValue(v); mode {
	case laneValueOn, laneValueShadow, laneValueOff:
		return mode
	}
	return laneValueShadow
}

// validateGuardrailCascade accepts the lanes this build knows, each set to
// on, shadow or off in any case. Any other value (an empty one included), or an
// unknown lane, is an error the loader reports with the key: a lane is never
// silently on.
func validateGuardrailCascade(c GuardrailCascade) error {
	names := make([]string, 0, len(c.Lanes))
	for name := range c.Lanes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name != NonShellLane {
			return fmt.Errorf("guardrail.cascade.lanes.%s: unknown lane (known: %s)", name, NonShellLane)
		}
		switch normalizeLaneValue(c.Lanes[name]) {
		case laneValueOn, laneValueShadow, laneValueOff:
		default:
			return fmt.Errorf("guardrail.cascade.lanes.%s: %q is not a lane value (on, shadow or off)", name, c.Lanes[name])
		}
	}
	return nil
}
