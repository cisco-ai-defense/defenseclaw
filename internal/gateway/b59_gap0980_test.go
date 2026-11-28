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
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
)

// GAP-0980 / GAP-0982: one deadline per hook post (skills.pending_wait, the
// slot wait and every folder, scanned in parallel), under the kit's first
// attempt, in every tier. Times are scaled: 10 ms here = 1 s.

type b59Slow struct {
	d time.Duration
	n atomic.Int32
}

func (s *b59Slow) ScanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) (bool, string, error) {
	s.n.Add(1)
	select {
	case <-time.After(s.d):
		return false, "", nil
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
}

func b59State(sc SubstrateSkillScanner, block bool, timeout, wait time.Duration) *substrateState {
	st := &substrateState{}
	st.cfg.Skills = sc
	st.cfg.BlockUnscannedSkills = func(string) bool { return block }
	st.cfg.SkillScanLimits = func() (time.Duration, time.Duration) { return timeout, wait }
	return st
}

func b59Actor(uid string) context.Context {
	key, _ := sandboxreg.SubstrateKey("eng-web", uid)
	return withSubstrateActor(context.Background(), substrateActor{Atespace: "eng-web", Name: "b59-" + uid[len(uid)-4:], UID: uid,
		Subject: "actor/eng-web/b59-" + uid[len(uid)-4:], RegistrationKey: key, verified: substrateVerified})
}

func b59Facts(dirs ...string) *SubstrateFacts {
	f := &SubstrateFacts{}
	for _, dir := range dirs {
		files := map[string]string{"SKILL.md": "---\nname: helper\n---\nbody of " + dir + "\n"}
		rels := make([]string, 0, len(files))
		for rel := range files {
			rels = append(rels, rel)
		}
		sort.Strings(rels)
		var own []SubstrateAttachedFile
		for _, rel := range rels {
			c := files[rel]
			own = append(own, SubstrateAttachedFile{Role: substrateSkillRoleFile, Path: dir + "/" + rel, Content: []byte(c), Size: int64(len(c))})
		}
		f.Files = append(f.Files, own...)
		f.Skills = append(f.Skills, SubstrateSkillFingerprint{Path: dir, FP: substrateSkillFolderDigest(dir, own), Attached: true})
	}
	return f
}

// b59KitPost is the kit's post: attempt 1 (9 s), then the retry (12 s) on
// the next replica. It reports whether an attempt was answered in budget.
func b59KitPost(sts []*substrateState, uid string, f *SubstrateFacts) (bool, substrateSkillAnswer) {
	for i, b := range []time.Duration{90 * time.Millisecond, 120 * time.Millisecond} {
		ctx, cancel := context.WithTimeout(b59Actor(uid), b)
		a := sts[i%len(sts)].substrateSkills(withSkillPostStart(ctx), "claudecode", f)
		late := ctx.Err() != nil
		cancel()
		if !late {
			return true, a
		}
	}
	return false, substrateSkillAnswer{}
}

// RV5-B: a managed post is answered inside the kit's first attempt however
// long the scan, a valid scan.timeout, the replica or the folder count;
// the slow folders are held (pending, refused), never moved. Red at
// 434598be28: no answer in the kit's budget (the post waits the scans, one
// folder after another).
func TestB59ManagedPostAnsweredInsideKitBudget(t *testing.T) {
	rows := []struct {
		name            string
		timeout, scan   time.Duration
		replicas, nfold int
	}{
		{"scan.timeout 40s, scan 30s", 400 * time.Millisecond, 300 * time.Millisecond, 1, 1},
		{"scan 15s, retry on another replica", 200 * time.Millisecond, 150 * time.Millisecond, 2, 1},
		{"two 13s folders in one post", 200 * time.Millisecond, 130 * time.Millisecond, 1, 2},
		{"eight 13s folders in one post", 200 * time.Millisecond, 130 * time.Millisecond, 1, 8},
	}
	for i, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			sc := &b59Slow{d: r.scan}
			var sts []*substrateState
			for j := 0; j < r.replicas; j++ {
				sts = append(sts, b59State(sc, true, r.timeout, 80*time.Millisecond))
			}
			var dirs []string
			for j := 0; j < r.nfold; j++ {
				dirs = append(dirs, fmt.Sprintf("/home/agent/.claude/skills/slow%d", j))
			}
			start := time.Now()
			ok, ans := b59KitPost(sts, fmt.Sprintf("7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e%02d", i), b59Facts(dirs...))
			if !ok || time.Since(start) > 90*time.Millisecond {
				t.Fatalf("no answer inside the kit's first attempt (%v)", time.Since(start))
			}
			if len(ans.Quarantine) != 0 || len(ans.held) != r.nfold {
				t.Fatalf("slow folders must be held, not moved: quarantine=%+v held=%+v", ans.Quarantine, ans.held)
			}
		})
	}
}

// A scan that ends inside the deadline gets its verdict in that post, and
// a held folder gets its verdict in the next post once the scan is done
// (the scan went on after the deadline).
func TestB59HeldFolderVerdictNextPost(t *testing.T) {
	sc := &b59Slow{d: 120 * time.Millisecond}
	st := b59State(sc, true, 400*time.Millisecond, 50*time.Millisecond)
	f := b59Facts("/home/agent/.claude/skills/late")
	uid := "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3f01"
	a := st.substrateSkills(withSkillPostStart(b59Actor(uid)), "claudecode", f)
	if len(a.held) != 1 || len(a.Scanned) != 0 {
		t.Fatalf("first post: %+v", a)
	}
	time.Sleep(30 * time.Millisecond)
	// The next post joins the scan still running and gets its verdict.
	a = st.substrateSkills(withSkillPostStart(b59Actor(uid)), "claudecode", f)
	if len(a.held) != 0 || len(a.Scanned) != 1 || sc.n.Load() != 1 {
		t.Fatalf("next post: held=%+v scanned=%+v scans=%d", a.held, a.Scanned, sc.n.Load())
	}
}

// GAP-0982: the write gate and the folder pass of one post share the one
// deadline; the OSS tiers keep it too (pending, no block).
func TestB59OSSPendingAtDeadline(t *testing.T) {
	sc := &b59Slow{d: 300 * time.Millisecond}
	st := b59State(sc, false, 400*time.Millisecond, 50*time.Millisecond)
	start := time.Now()
	a := st.substrateSkills(withSkillPostStart(b59Actor("7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3f02")), "claudecode",
		b59Facts("/home/agent/.claude/skills/a", "/home/agent/.claude/skills/b"))
	if took := time.Since(start); took > 150*time.Millisecond || len(a.pending) != 2 || len(a.held) != 0 || len(a.Quarantine) != 0 {
		t.Fatalf("OSS: %v pending=%d held=%d quarantine=%d", took, len(a.pending), len(a.held), len(a.Quarantine))
	}
}

// Every connector, managed and strict: a scan past the post's deadline is
// answered at the deadline (not at skills.scan.timeout); the folder is not
// moved, and every PreToolUse call (Bash here, which names no skill) is
// refused with substrate_pending until it has a verdict. Red at 434598be28
// (the post waits the whole scan).
func TestB59ManagedSlowScanHeldEveryConnector(t *testing.T) {
	for _, c := range b58Connectors {
		for tier, block := range map[string]func(string) bool{"managed": b58Every, "strict": func(x string) bool { return x == c }} {
			t.Run(c+"/"+tier, func(t *testing.T) {
				r := newB58Rig(t, block, 5*time.Second, 20*time.Millisecond, false)
				defer close(r.scan.release)
				start := time.Now()
				r.b58Hook(t, c, b58FolderEvent[c], map[string]any{"tool_name": "Bash"}, b54Dir, b54Skill, nil)
				if took := time.Since(start); took > 2*time.Second {
					t.Fatalf("the post waited %v, past its deadline", took)
				}
				p := r.rowsOf(AuditSkillPending)
				if len(p) != 1 || p[0].d["outcome"] != "refused until scanned" || len(r.rowsOf(AuditSkillBlocked)) != 0 || len(r.rowsOf(AuditSkillUnscanned)) != 0 {
					t.Fatalf("a slow folder must be held, not moved: %+v", r.rows)
				}
				code, out := r.b58Hook(t, c, "PreToolUse", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "ls /tmp"}}, b54Dir, b54Skill, nil)
				var msg string
				_ = json.Unmarshal(out["message"], &msg)
				var held []SubstrateUnscanned
				_ = json.Unmarshal(out[SubstratePendingField], &held)
				if code != http.StatusForbidden || !strings.Contains(msg, `"evil" is still being scanned`) || len(held) != 1 || held[0].Path != b54Dir {
					t.Fatalf("a call while the folder is held: %d %q %+v", code, msg, held)
				}
			})
		}
	}
}
