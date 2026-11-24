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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/substrate/skilldigest"
)

// GAP-0931: managed installs and the strict tier never leave a skill folder
// pending. The hook that brings the folder waits for the whole scan (as the
// parent did, bounded by skills.scan.timeout) and the folder gets a verdict
// or the fail mode (skill_scan_timeout), for every connector; a PreToolUse
// that uses a folder its own pass refused is refused. The OSS tiers keep
// pending_wait and add no block.

var b58Connectors = []string{"claudecode", "codex", "copilot", "opencode", "cursor"}

// b58UIDs are one actor per connector (the registration's connector names
// the hook route it may post to).
var b58UIDs = map[string]string{
	"claudecode": "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e01", "codex": "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e02",
	"copilot": "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e03", "opencode": "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e04",
	"cursor": "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e05",
}

// newB58Rig is the B5.4 rig with one actor per connector; block decides
// per connector (managed: every one, strict: the strict ones). unattended
// registers every actor as a --task run.
func newB58Rig(t *testing.T, block func(string) bool, timeout, wait time.Duration, unattended bool) *b54Rig {
	t.Helper()
	r := newB54Rig(t, false, timeout, wait)
	st := r.f.api.substrateState()
	st.cfg.BlockUnscannedSkills = block
	ft := st.cfg.Actors.(*fakeActorTokens)
	ft.mu.Lock()
	for c, uid := range b58UIDs {
		ft.tokens["tok-b58-"+c] = identity.Actor{Atespace: "eng-web", Name: "b58-" + c, UID: uid, Subject: "actor/eng-web/b58-" + c}
		r.f.live["eng-web/b58-"+c] = identity.LiveActor{UID: uid, State: identity.ActorRunning}
	}
	ft.mu.Unlock()
	for c, uid := range b58UIDs {
		reg := registry.Registration{Atespace: "eng-web", Name: "b58-" + c, UID: uid, Connector: c, Profile: "eng", Person: ownerOf(alice), Unattended: unattended}
		if unattended {
			reg.BatchID = "b58"
		}
		if err := r.f.regs.Put(context.Background(), reg); err != nil {
			t.Fatal(err)
		}
	}
	return r
}

// b58Hook posts one hook of connector with the folder dir attached (files
// nil: nothing attached) and the kit's path facts.
func (r *b54Rig) b58Hook(t *testing.T, connector, event string, payload map[string]any, dir string, files map[string]string, paths []map[string]any) (int, map[string]json.RawMessage) {
	t.Helper()
	payload["hook_event_name"], payload["session_id"] = event, "s1"
	if _, ok := payload["cwd"]; !ok {
		payload["cwd"] = "/work"
	}
	p, _ := json.Marshal(payload)
	env := map[string]any{"v": substrateEnvelopeVersion, "connector": connector, "event": event,
		"mode": "interactive", "kit_version": "0.1.0", "payload": json.RawMessage(p)}
	facts := map[string]any{}
	if files != nil {
		var att []map[string]any
		m := map[string][]byte{}
		for rel, body := range files {
			att = append(att, map[string]any{"role": "skill_file", "path": dir + "/" + rel, "size": len(body), "sha256": "x", "content": []byte(body)})
			m[rel] = []byte(body)
		}
		facts["files"] = att
		facts["skills"] = []map[string]any{{"path": dir, "fp": skilldigest.Digest(m), "attached": true}}
	}
	if paths != nil {
		facts["paths"] = paths
	}
	if len(facts) > 0 {
		env["facts"] = facts
	}
	b, _ := json.Marshal(env)
	rec := r.f.do(t, r.f.actor, http.MethodPost, "/api/v1/substrate/hook/"+connector, "tok-b58-"+connector, string(b))
	var out map[string]json.RawMessage
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func b58Every(string) bool { return true }

// b58FolderEvent is a hook of each connector that runs the folder pass.
var b58FolderEvent = map[string]string{"claudecode": "PostToolUse", "codex": "PostToolUse", "copilot": "postToolUse", "opencode": "PostToolUse", "cursor": "postToolUse"}

// A scan that ends inside the post's deadline (pending_wait): the hook gets
// its verdict (managed, every connector).
func TestB58ManagedSkillWaitsForTheVerdict(t *testing.T) {
	for _, c := range b58Connectors {
		t.Run(c, func(t *testing.T) {
			r := newB58Rig(t, b58Every, 5*time.Second, 2*time.Second, false)
			r.scan.bad = true
			go func() {
				for r.f.api.substrateState().inFlightScans() == 0 {
					time.Sleep(time.Millisecond)
				}
				time.Sleep(40 * time.Millisecond)
				close(r.scan.release)
			}()
			_, out := r.b58Hook(t, c, b58FolderEvent[c], map[string]any{"tool_name": "Bash"}, b54Dir, b54Skill, nil)
			if b := r.rowsOf(AuditSkillBlocked); len(b) != 1 || b[0].d["reason"] != SkillReasonFinding || len(r.rowsOf(AuditSkillPending)) != 0 {
				t.Fatalf("%s: the verdict of a scan past pending_wait: %v %+v", c, out, r.rows)
			}
			if q := quarantined(out); c == "claudecode" && (unscannedIn(out, b54Dir) || len(q) != 1 || q[0].Code != SkillReasonFinding) {
				t.Fatalf("%s: the answer must carry the verdict: %v", c, out)
			}
		})
	}
}

var b58Alias = map[string]string{"SKILL.md": "---\nname: helper\ndescription: x\n---\nfixture body"}

// The Claude Code use routes of a folder still being scanned (RV3-A, RV3-B
// and the other aliases), managed. Red at 131a19c94f: the folder post is
// answered pending and each use below is allowed.
func TestB58ManagedUseRoutes(t *testing.T) {
	routes := []struct {
		name    string
		tool    string
		input   map[string]any
		paths   []map[string]any
		carries bool // the kit runs the folder pass in this PreToolUse
	}{
		{name: "bash-cat-SKILL.md (RV3-A)", tool: "Bash", input: map[string]any{"command": "cat " + b54Dir + "/SKILL.md"}},
		{name: "skill-frontmatter-name (RV3-B)", tool: "Skill", input: map[string]any{"skill": "helper"}, carries: true},
		{name: "skill-folder-name", tool: "Skill", input: map[string]any{"skill": "evil"}, carries: true},
		{name: "skill-plugin-prefix", tool: "Skill", input: map[string]any{"skill": "tools:helper"}, carries: true},
		{name: "skill-case", tool: "Skill", input: map[string]any{"skill": "Helper"}, carries: true},
		{name: "read-relative", tool: "Read", input: map[string]any{"file_path": "SKILL.md"}, carries: true,
			paths: []map[string]any{{"field": "tool_input.file_path", "path": "SKILL.md", "abs": b54Dir + "/SKILL.md", "type": "file", "uid": 1000, "gid": 1000}}},
		{name: "read-symlink", tool: "Read", input: map[string]any{"file_path": "/work/link/SKILL.md"}, carries: true,
			paths: []map[string]any{{"field": "tool_input.file_path", "path": "/work/link/SKILL.md", "abs": "/work/link/SKILL.md", "resolved": b54Dir + "/SKILL.md", "type": "file", "uid": 1000, "gid": 1000}}},
	}
	for _, rt := range routes {
		t.Run(rt.name, func(t *testing.T) {
			r := newB58Rig(t, b58Every, 5*time.Second, 2*time.Second, false)
			r.scan.bad = true
			close(r.scan.release)
			// The folder arrives with a hook first (SessionStart, PostToolUse)
			// and the scan refuses it.
			_, out := r.b58Hook(t, "claudecode", "PostToolUse", map[string]any{"tool_name": "Write"}, b54Dir, b58Alias, nil)
			if q := quarantined(out); unscannedIn(out, b54Dir) || len(q) != 1 {
				t.Fatalf("the folder post must refuse the folder, not name it pending: %v", out)
			}
			if !rt.carries {
				return
			}
			// The kit moved it; a use that still carries it (a second copy, a
			// kit that did not move it) is refused at the use gate.
			input := map[string]any{"tool_name": rt.tool, "tool_input": rt.input}
			if rt.tool == "Read" {
				input["cwd"] = b54Dir
			}
			code, out := r.b58Hook(t, "claudecode", "PreToolUse", input, b54Dir, b58Alias, rt.paths)
			if code != http.StatusForbidden {
				t.Fatalf("%s: a use of a refused folder: %d %v", rt.name, code, out)
			}
		})
	}
}

// The OSS tiers are unchanged: the folder stays pending after pending_wait
// and no use is refused (Bash, Skill by either name, every connector);
// Claude Code asks for a Skill use, by its frontmatter name too.
func TestB58OSSTiersAddNoBlock(t *testing.T) {
	for _, c := range b58Connectors {
		t.Run(c, func(t *testing.T) {
			r := newB58Rig(t, func(string) bool { return false }, 5*time.Second, 10*time.Millisecond, false)
			defer close(r.scan.release)
			_, out := r.b58Hook(t, c, b58FolderEvent[c], map[string]any{"tool_name": "Bash"}, b54Dir, b58Alias, nil)
			if len(quarantined(out)) != 0 || len(r.rowsOf(AuditSkillPending)) != 1 || len(r.rowsOf(AuditSkillUnscanned)) != 0 {
				t.Fatalf("OSS: the folder is pending and not hidden: %v %+v", out, r.rows)
			}
			if c == "claudecode" && !unscannedIn(out, b54Dir) {
				t.Fatalf("OSS: the kit is told to send it again: %v", out)
			}
			for _, use := range []struct {
				tool  string
				input map[string]any
				files map[string]string
			}{
				{"Bash", map[string]any{"command": "cat " + b54Dir + "/SKILL.md"}, nil},
				{"Skill", map[string]any{"skill": "helper"}, b58Alias},
				{"Read", map[string]any{"file_path": b54Dir + "/SKILL.md"}, b58Alias},
			} {
				code, out := r.b58Hook(t, c, "PreToolUse", map[string]any{"tool_name": use.tool, "tool_input": use.input}, b54Dir, use.files, nil)
				if code == http.StatusForbidden || len(quarantined(out)) != 0 || (c == "claudecode" && code != http.StatusOK) {
					t.Fatalf("OSS %s %s: no new block: %d %v", c, use.tool, code, out)
				}
				for _, x := range r.rows {
					if x.d["outcome"] == "refused" {
						t.Fatalf("OSS %s %s: a refused row: %+v", c, use.tool, x)
					}
				}
				var action string
				_ = json.Unmarshal(out["action"], &action)
				if c == "claudecode" && use.tool == "Skill" && action != "confirm" {
					t.Fatalf("OSS Claude Code Skill(helper) of the pending folder evil asks: %v", fmt.Sprint(out))
				}
			}
		})
	}
}
