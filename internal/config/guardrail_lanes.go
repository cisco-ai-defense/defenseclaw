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
)

// guardrail.cascade.lanes: the live/shadow switch of a guardrail lane.
//
// Until s7/cascade-config (the full guardrail.cascade block, with scopes,
// locks and the lane registry) is in this tree, the block holds only the lane
// switches below, at the global scope. The key names and values are the ones
// cascade-config registers, so its CascadeConfig replaces GuardrailCascade
// and the reads through GuardrailConfig.NonShellLaneMode stay as they are.

// Lane names under guardrail.cascade.lanes.
const (
	// NonShellLane is the MCP and app tool lane (internal/toolshape and the
	// gateway's nonShellToolFindings and shellToolFindings).
	NonShellLane = "nonshell"

	laneValueShadow = "shadow"
	laneValueOn     = "on"
)

// GuardrailCascade is guardrail.cascade.
type GuardrailCascade struct {
	// Lanes maps a lane to shadow or on. A lane that is not listed has its
	// shipped default (nonshell: on).
	Lanes map[string]string `mapstructure:"lanes" yaml:"lanes,omitempty" json:"lanes,omitempty"`
}

// NonShellLaneMode is the normalized guardrail.cascade.lanes.nonshell: "on"
// (the default, also for a nil config) or "shadow". In shadow the lane
// computes nothing and adds nothing, so the verdicts are those of a build
// without it.
func (g *GuardrailConfig) NonShellLaneMode() string {
	if g == nil {
		return laneValueOn
	}
	if g.Cascade.Lanes[NonShellLane] == laneValueShadow {
		return laneValueShadow
	}
	return laneValueOn
}

// validateGuardrailCascade accepts the lanes this build knows, each set to
// shadow or on. A value outside that, or an
// unknown lane, is an error the loader reports with the key.
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
		switch c.Lanes[name] {
		case laneValueShadow, laneValueOn:
		default:
			return fmt.Errorf("guardrail.cascade.lanes.%s: %q is not a lane value (shadow or on)", name, c.Lanes[name])
		}
	}
	return nil
}
