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

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

// GAP-0935 (rule D12): an unattended run never gets the "use it anyway?"
// ask; on the OSS tiers a use of a skill still being scanned is allowed with
// a MEDIUM alert instead, as for the agents that cannot ask.
func TestB58UnattendedOSSNeverAsks(t *testing.T) {
	r := newB58Rig(t, func(string) bool { return false }, 5*time.Second, 10*time.Millisecond, true)
	defer close(r.scan.release)
	code, out := r.b58Hook(t, "claudecode", "PreToolUse", map[string]any{"tool_name": "Skill", "tool_input": map[string]any{"skill": "evil"}}, b54Dir, b54Skill, nil)
	var action string
	_ = json.Unmarshal(out["action"], &action)
	if code != http.StatusOK || action == "confirm" || len(out["claude_code_output"]) > 0 && string(out["claude_code_output"]) != "null" && json.Valid(out["claude_code_output"]) && containsAsk(out["claude_code_output"]) {
		t.Fatalf("unattended: no ask: %d %s", code, action)
	}
	allowed := false
	for _, p := range r.rowsOf(AuditSkillPending) {
		allowed = allowed || p.d["outcome"] == "allowed"
		if p.d["outcome"] == "asked" {
			t.Fatalf("an asked row for an unattended run: %+v", p)
		}
	}
	medium := false
	for _, a := range r.alerts {
		medium = medium || a.sev == "MEDIUM"
	}
	if !allowed || !medium {
		t.Fatalf("unattended use: rows %+v alerts %+v", r.rows, r.alerts)
	}
}

func containsAsk(raw json.RawMessage) bool {
	var native struct {
		H struct{ PermissionDecision string } `json:"hookSpecificOutput"`
	}
	_ = json.Unmarshal(raw, &native)
	return native.H.PermissionDecision == "ask"
}
