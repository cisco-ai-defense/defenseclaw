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
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

// maxConfigChangePaths bounds the paths one config.change.applied event
// lists; the event also carries the total.
const maxConfigChangePaths = 64

// unattributedConfigActor is the actor of a config.change.applied event that
// covers more than one generation (GAP-0318).
const unattributedConfigActor = "unattributed"

// configChangeActivity describes an applied config.yaml change for the audit
// trail (spec section 3, step 7): who wrote it (the actor
// config.generation.json recorded for exactly these bytes, such as
// cli:<os-user>), the changed paths, the config generation, the sha256 of the
// applied file and the paths that still need a gateway restart. Values are
// never recorded. previous is the file the last generation was built from;
// without it the changed top-level sections stand in for the paths. ok is
// false when no writer recorded these bytes (a Secure Client host, a missing
// state file), and the caller keeps its plain config-update action.
//
// config.generation.json keeps only the last generation, so the event names
// its writer only when it is the one generation since last, the generation
// the gateway applied before (lastKnown). Generations coalesced by the reload
// debounce, or written while reloads were rejected, carry the paths of other
// writers too: that event says unattributed and gives the generation range
// and the last writer instead (GAP-0318). generation is the applied one.
func configChangeActivity(path string, previous, raw []byte, sections []string, last uint64, lastKnown bool) (in audit.ActivityInput, generation uint64, ok bool) {
	if len(previous) > 0 && bytes.Equal(previous, raw) {
		return audit.ActivityInput{}, 0, false
	}
	state, err := configwrite.ReadGenerationState(path)
	sum := configwrite.SHA256Hex(raw)
	if err != nil || strings.TrimSpace(state.Actor) == "" ||
		!strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), sum) {
		return audit.ActivityInput{}, 0, false
	}
	paths := sections
	if len(previous) > 0 {
		if changed, err := configwrite.ChangedPaths(previous, raw); err == nil && len(changed) > 0 {
			paths = changed
		}
	}
	restart := configwrite.RestartRequired(paths)
	if restart == nil {
		restart = []string{}
	}
	total := len(paths)
	if total > maxConfigChangePaths {
		paths = paths[:maxConfigChangePaths]
	}
	diff := make([]audit.ActivityDiffEntry, len(paths))
	for i, changed := range paths {
		diff[i] = audit.ActivityDiffEntry{Path: changed, Op: "replace"}
	}
	in = audit.ActivityInput{
		Actor:      state.Actor,
		Action:     audit.ActionConfigUpdate,
		TargetType: "config",
		TargetID:   filepath.Base(path),
		Reason:     state.Reason,
		After: map[string]any{
			"config_generation": state.Generation,
			"config_sha256":     sum,
			"changed_paths":     total,
			"restart_required":  restart,
		},
		Diff:     diff,
		Severity: "INFO",
	}
	if lastKnown && (state.Generation > last+1 || state.Generation < last) {
		in.Actor = unattributedConfigActor
		in.After["last_actor"] = state.Actor
		if state.Generation > last {
			in.After["first_generation"] = last + 1
			in.Reason = fmt.Sprintf("generations %d-%d applied together; last writer %s", last+1, state.Generation, state.Actor)
		} else {
			in.Reason = fmt.Sprintf("generation %d follows %d (the generation record was reset); last writer %s", state.Generation, last, state.Actor)
		}
	}
	return in, state.Generation, true
}

// appliedGenerationOf returns the generation config.generation.json records
// for raw, so the next applied change can tell whether it is the only
// generation since (GAP-0318).
func appliedGenerationOf(path string, raw []byte) (uint64, bool) {
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || !strings.EqualFold(strings.TrimPrefix(state.ConfigSHA256, "sha256:"), configwrite.SHA256Hex(raw)) {
		return 0, false
	}
	return state.Generation, true
}
