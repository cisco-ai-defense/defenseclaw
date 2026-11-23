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
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/skilldigest"
)

// b54Use posts a Claude Code PreToolUse Skill call that carries the folder
// (the kit's use-gate pass) and returns the status and answer.
func (r *b54Rig) b54Use(t *testing.T, dir string, files map[string]string) (int, map[string]json.RawMessage) {
	t.Helper()
	var att []map[string]any
	m := map[string][]byte{}
	for rel, body := range files {
		att = append(att, map[string]any{"role": "skill_file", "path": dir + "/" + rel, "size": len(body), "sha256": "x", "content": []byte(body)})
		m[rel] = []byte(body)
	}
	p, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "s1", "cwd": "/work",
		"tool_name": "Skill", "tool_input": map[string]any{"skill": "evil"}})
	b, _ := json.Marshal(map[string]any{"v": substrateEnvelopeVersion, "connector": "claudecode", "event": "PreToolUse",
		"mode": "interactive", "kit_version": "0.1.0", "payload": json.RawMessage(p),
		"facts": map[string]any{"files": att, "skills": []map[string]any{{"path": dir, "fp": skilldigest.Digest(m), "attached": true}}}})
	rec := r.f.do(t, r.f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", string(b))
	var out map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// B5.4 skill_pending at the use gate: the Skill tool used while its folder
// is still being scanned is asked on OSS (Claude Code PreToolUse can ask).
// Managed installs and the strict tier refuse it while the folder is held
// (GAP-0980), and every other call too.
func TestB54SkillPendingAtUse(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("managed=%v", block), func(t *testing.T) {
			r := newB54Rig(t, block, map[bool]time.Duration{true: 100 * time.Millisecond, false: 5 * time.Second}[block], 20*time.Millisecond)
			defer close(r.scan.release)
			code, out := r.b54Use(t, b54Dir, b54Skill)
			var msg, action string
			_ = json.Unmarshal(out["message"], &msg)
			_ = json.Unmarshal(out["action"], &action)
			if block {
				if code != http.StatusForbidden || msg != `"evil" is still being scanned; DefenseClaw refuses tool calls until the scan finishes. Try again in a few seconds.` {
					t.Fatalf("managed use while scanning: %d %q", code, msg)
				}
				if p := r.rowsOf(AuditSkillPending); len(p) != 1 || p[0].d["outcome"] != "refused until scanned" || len(r.rowsOf(AuditSkillUnscanned)) != 0 {
					t.Fatalf("managed rows %+v", r.rows)
				}
				return
			} else {
				var native struct {
					H struct{ PermissionDecision, PermissionDecisionReason string } `json:"hookSpecificOutput"`
				}
				_ = json.Unmarshal(out["claude_code_output"], &native)
				if code != http.StatusOK || action != "confirm" || native.H.PermissionDecision != "ask" ||
					native.H.PermissionDecisionReason != `DefenseClaw is still checking the skill "evil". Use it anyway?` {
					t.Fatalf("OSS use while scanning: %d %s", code, fmt.Sprint(out))
				}
			}
			found := false
			for _, p := range r.rowsOf(AuditSkillPending) {
				found = found || p.d["outcome"] == "asked"
			}
			if !found {
				t.Fatalf("no pending row with outcome asked: %+v", r.rowsOf(AuditSkillPending))
			}
		})
	}
}

// B5.4 skill_archive: a clean scan of a folder with an archive in it says
// nothing of what the archive holds, so the fail mode decides: managed
// refuses with skill_archive, OSS allows with an alert and gives no receipt.
func TestB54SkillArchiveFollowsFailMode(t *testing.T) {
	files := map[string]string{"SKILL.md": "---\nname: evil\n---\nbody", "payload.zip": "PK\x03\x04rest-of-zip"}
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("managed=%v", block), func(t *testing.T) {
			r := newB54Rig(t, block, 5*time.Second, 0)
			close(r.scan.release)
			out := r.post(t, b54Dir, files)
			q := quarantined(out)
			if block {
				if len(q) != 1 || q[0].Code != SkillReasonArchive || !strings.Contains(q[0].Reason, `DefenseClaw could not look inside "payload.zip" in the skill "evil"`) {
					t.Fatalf("managed archive: %+v", q)
				}
			} else if len(q) != 0 || receipted(out, b54Dir) {
				t.Fatalf("OSS archive must be allowed without a receipt: %+v", out)
			}
			if u := r.rowsOf(AuditSkillUnscanned); len(u) != 1 || u[0].d["reason"] != SkillReasonArchive {
				t.Fatalf("unscanned rows %+v", u)
			}
		})
	}
	// A folder with no archive still passes with a receipt.
	r := newB54Rig(t, true, 5*time.Second, 0)
	close(r.scan.release)
	if out := r.post(t, b54Dir, b54Skill); len(quarantined(out)) != 0 || !receipted(out, b54Dir) {
		t.Fatalf("clean folder: %+v", out)
	}
}
