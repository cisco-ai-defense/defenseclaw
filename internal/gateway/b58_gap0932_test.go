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
	"fmt"
	"testing"
	"time"
)

// GAP-0932 (RV3-D): one actor's slow folders take at most its own share of
// the scans in flight, so another actor's new folder is still scanned; past
// its share an actor's new folder waits for a slot inside pending_wait and
// is then skill_scanner_busy (OSS: sent again; managed: refused).
func TestB58PerActorScanCap(t *testing.T) {
	r := newB58Rig(t, func(string) bool { return false }, 5*time.Second, 5*time.Millisecond, false)
	defer close(r.scan.release)
	for i := 0; i < substrateSkillScansInFlight; i++ {
		r.b58Hook(t, "claudecode", "PostToolUse", map[string]any{"tool_name": "Bash"}, b54Dir,
			map[string]string{"SKILL.md": fmt.Sprintf("---\nname: evil\n---\nbody %d", i)}, nil)
	}
	if n := r.f.api.substrateState().inFlightScans(); n > substrateSkillScansPerActor {
		t.Fatalf("one actor holds %d scans in flight, its share is %d", n, substrateSkillScansPerActor)
	}
	busy := 0
	for _, x := range r.rowsOf(AuditSkillPending) {
		if x.d["reason"] == SkillReasonScannerBusy {
			busy++
		}
	}
	if busy == 0 {
		t.Fatalf("no skill_scanner_busy row past the actor's share: %+v", r.rowsOf(AuditSkillPending))
	}
	before := r.scan.calls.Load()
	r.b58Hook(t, "codex", "PostToolUse", map[string]any{"tool_name": "Bash"}, "/sandbox/.codex/skills/victim",
		map[string]string{"SKILL.md": "---\nname: victim\n---\nok"}, nil)
	if r.scan.calls.Load() != before+1 {
		t.Fatalf("another actor's folder was not scanned: calls %d -> %d", before, r.scan.calls.Load())
	}
}

// Managed: past the actor's share the folder is refused as
// skill_scanner_busy, never pending.
func TestB58PerActorScanCapManagedRefusesBusy(t *testing.T) {
	r := newB58Rig(t, b58Every, 5*time.Second, 5*time.Millisecond, false)
	defer close(r.scan.release)
	st := r.f.api.substrateState()
	// Fill the actor's share with scans other hooks of it started.
	for i := 0; i < substrateSkillScansPerActor; i++ {
		go r.b58Hook(t, "claudecode", "PostToolUse", map[string]any{"tool_name": "Bash"}, b54Dir,
			map[string]string{"SKILL.md": fmt.Sprintf("---\nname: evil\n---\nbody %d", i)}, nil)
	}
	for st.inFlightScans() < substrateSkillScansPerActor {
		time.Sleep(time.Millisecond)
	}
	r.b58Hook(t, "claudecode", "PostToolUse", map[string]any{"tool_name": "Bash"}, "/sandbox/.claude/skills/late",
		map[string]string{"SKILL.md": "---\nname: late\n---\nok"}, nil)
	// GAP-0980: busy is no verdict; the folder is held (every call refused
	// until it is scanned), not moved.
	found := false
	for _, u := range r.rowsOf(AuditSkillPending) {
		found = found || (u.d["folder"] == "/sandbox/.claude/skills/late" && u.d["reason"] == SkillReasonScannerBusy && u.d["outcome"] == "refused until scanned")
	}
	if !found || len(r.rowsOf(AuditSkillUnscanned)) != 0 {
		t.Fatalf("managed busy: %+v", r.rows)
	}
}
