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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// B5.4 S2 (GAP-0477): the skill pass's pending state, reason codes, audit
// rows and messages.

// b54Scanner blocks every scan until release is closed (or its context
// ends), then answers verdict. No sleeps: the tests drive it by channel.
type b54Scanner struct {
	release     chan struct{}
	bad         bool
	unavailable bool
	calls       atomic.Int32
}

func (s *b54Scanner) ScanSkillFolder(ctx context.Context, name, _ string, _ []SubstrateAttachedFile) (bool, string, error) {
	s.calls.Add(1)
	if s.unavailable {
		return false, "", fmt.Errorf("%w: sidecar down", ErrSubstrateSkillScannerUnavailable)
	}
	select {
	case <-s.release:
	case <-ctx.Done():
		return false, "", ctx.Err()
	}
	if s.bad {
		return true, "CRITICAL prompt injection in " + name, nil
	}
	return false, "", nil
}

type b54Row struct {
	action, sev string
	d           map[string]any
}

type b54Rig struct {
	*gap0164Rig
	scan *b54Scanner
	mu   sync.Mutex
	rows []b54Row
}

func newB54Rig(t *testing.T, block bool, timeout, wait time.Duration) *b54Rig {
	t.Helper()
	r := &b54Rig{gap0164Rig: &gap0164Rig{}, scan: &b54Scanner{release: make(chan struct{})}}
	r.f = newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Skills = r.scan
		c.SkillReceiptKey = []byte("shared receipt key for all replicas")
		c.BlockUnscannedSkills = func(string) bool { return block }
		c.SkillScanLimits = func() (time.Duration, time.Duration) { return timeout, wait }
	})
	st := r.f.api.substrateState()
	st.alert = func(_ context.Context, sev, summary string, d map[string]any) {
		r.mu.Lock()
		r.alerts = append(r.alerts, gap0164Alert{sev, summary, fmt.Sprint(d["folder"])})
		r.mu.Unlock()
	}
	st.action = func(_ context.Context, action, sev string, d map[string]any) {
		r.mu.Lock()
		r.rows = append(r.rows, b54Row{action, sev, d})
		r.mu.Unlock()
	}
	return r
}

func (r *b54Rig) rowsOf(action string) []b54Row {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []b54Row
	for _, x := range r.rows {
		if x.action == action {
			out = append(out, x)
		}
	}
	return out
}

func unscannedIn(out map[string]json.RawMessage, dir string) bool {
	var u []SubstrateUnscanned
	_ = json.Unmarshal(out[substrateUnscannedField], &u)
	for _, x := range u {
		if x.Path == dir {
			return true
		}
	}
	return false
}

const b54Dir = "/sandbox/.claude/skills/evil"

var b54Skill = map[string]string{"SKILL.md": "---\nname: evil\n---\nfixture body"}

// A scan still running after pending_wait (OSS tiers): the folder is not
// hidden, the kit is told to send it again, and the next hook gets the
// verdict. Managed and strict never leave a folder pending (GAP-0931,
// b58_gap0931_test.go).
func TestB54SkillPendingThenBlocked(t *testing.T) {
	for _, block := range []bool{false} {
		t.Run(fmt.Sprintf("managed=%v", block), func(t *testing.T) {
			r := newB54Rig(t, block, 5*time.Second, 20*time.Millisecond)
			r.scan.bad = true
			out := r.post(t, b54Dir, b54Skill)
			if q := quarantined(out); len(q) != 0 {
				t.Fatalf("a folder still being checked was quarantined: %+v", q)
			}
			if !unscannedIn(out, b54Dir) || receipted(out, b54Dir) {
				t.Fatalf("pending folder must be sent again and get no receipt: %s", out[substrateUnscannedField])
			}
			if p := r.rowsOf(AuditSkillPending); len(p) != 1 || p[0].d["reason"] != SkillReasonPending {
				t.Fatalf("pending rows %+v", p)
			}
			close(r.scan.release)
			out = r.post(t, b54Dir, b54Skill)
			q := quarantined(out)
			if len(q) != 1 || q[0].Code != SkillReasonFinding ||
				!strings.Contains(q[0].Reason, `DefenseClaw blocked the skill "evil": CRITICAL`) ||
				!strings.Contains(q[0].Reason, "/sandbox/.claude/.defenseclaw-quarantine") {
				t.Fatalf("the verdict after the scan: %+v", q)
			}
			if b := r.rowsOf(AuditSkillBlocked); len(b) != 1 || b[0].d["reason"] != SkillReasonFinding || b[0].d["connector"] != "claudecode" {
				t.Fatalf("blocked rows %+v", b)
			}
		})
	}
}

// Past skills.scan.timeout the fail mode decides: managed refuses with
// skill_scan_timeout, OSS allows with an alert (no new OSS block).
func TestB54SkillScanTimeoutFollowsFailMode(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("managed=%v", block), func(t *testing.T) {
			r := newB54Rig(t, block, 20*time.Millisecond, 0)
			out := r.post(t, b54Dir, b54Skill)
			q := quarantined(out)
			u := r.rowsOf(AuditSkillUnscanned)
			if len(u) != 1 || u[0].d["reason"] != SkillReasonScanTimeout {
				t.Fatalf("unscanned rows %+v", u)
			}
			if block {
				if len(q) != 1 || q[0].Code != SkillReasonScanTimeout || u[0].d["outcome"] != "refused" {
					t.Fatalf("managed: %+v %+v", q, u)
				}
				return
			}
			if len(q) != 0 || receipted(out, b54Dir) || u[0].d["outcome"] != "allowed" {
				t.Fatalf("OSS: %+v %+v", q, u)
			}
		})
	}
}

// Scanner down: the existing fail mode with the new reason code and text.
func TestB54ScannerDownReasonAndRow(t *testing.T) {
	r := newB54Rig(t, true, 5*time.Second, 5*time.Second)
	r.scan.unavailable = true
	q := quarantined(r.post(t, b54Dir, b54Skill))
	if len(q) != 1 || q[0].Code != SkillReasonScannerDown || !strings.Contains(q[0].Reason, "the skill scanner is not running") {
		t.Fatalf("%+v", q)
	}
	if u := r.rowsOf(AuditSkillUnscanned); len(u) != 1 || u[0].sev != "HIGH" {
		t.Fatalf("%+v", u)
	}
}

// A clean folder: one scanned row however often it is posted, and a
// receipt.
func TestB54CleanSkillScannedRowOnce(t *testing.T) {
	r := newB54Rig(t, true, 5*time.Second, 5*time.Second)
	close(r.scan.release)
	for i := 0; i < 2; i++ {
		if out := r.post(t, b54Dir, b54Skill); !receipted(out, b54Dir) {
			t.Fatalf("post %d: no receipt", i)
		}
	}
	if s := r.rowsOf(AuditSkillScanned); len(s) != 1 || s[0].sev != "INFO" {
		t.Fatalf("scanned rows %+v", s)
	}
}

// Hooks that bring the same content while its scan runs share one scan.
func TestB54ConcurrentHooksShareOneScan(t *testing.T) {
	r := newB54Rig(t, false, 5*time.Second, 5*time.Second)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.post(t, b54Dir, b54Skill)
		}()
	}
	for r.f.api.substrateState().inFlightScans() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(r.scan.release)
	wg.Wait()
	if n := r.scan.calls.Load(); n > 4 || n < 1 {
		t.Fatalf("calls %d", n)
	}
}

// The write gate: a skill write whose scan is still running is waited for
// in managed installs (GAP-0931: refused as skill_scan_timeout at the
// timeout, never pending) and allowed with an alert in OSS.
func TestB54SkillWritePendingManagedRefusesOSSAllows(t *testing.T) {
	for _, block := range []bool{true, false} {
		t.Run(fmt.Sprintf("managed=%v", block), func(t *testing.T) {
			r := newB54Rig(t, block, map[bool]time.Duration{true: 100 * time.Millisecond, false: 5 * time.Second}[block], 20*time.Millisecond)
			defer close(r.scan.release)
			st := r.f.api.substrateState()
			p, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Write", "cwd": "/work",
				"tool_input": map[string]any{"file_path": b54Dir + "/SKILL.md", "content": b54Skill["SKILL.md"]}})
			msg := st.substrateSkillWriteRefusal(context.Background(), substrateEnvelope{Connector: "claudecode", Event: "PreToolUse", Payload: p})
			rows := r.rowsOf(AuditSkillPending)
			if block {
				// GAP-0980: refused at the post's deadline, not waited to the
				// scan timeout; the agent writes again and gets the verdict.
				if len(rows) != 1 || rows[0].d["outcome"] != "refused" || len(r.rowsOf(AuditSkillUnscanned)) != 0 || msg != skillPendingMessage("evil") {
					t.Fatalf("managed: %q %+v", msg, r.rows)
				}
				return
			}
			if len(rows) != 1 {
				t.Fatalf("pending rows %+v (msg %q)", rows, msg)
			}
			if msg != "" || rows[0].d["outcome"] != "allowed" || len(r.alerts) != 1 || r.alerts[0].sev != "MEDIUM" {
				t.Fatalf("OSS: %q %+v %+v", msg, rows, r.alerts)
			}
		})
	}
}

func (st *substrateState) inFlightScans() int {
	st.scanMu.Lock()
	defer st.scanMu.Unlock()
	return len(st.scans)
}

// The Python mirror of the skill audit actions (alert_semantics.py).
func TestB54SkillAuditActionsMirroredInPython(t *testing.T) {
	raw, err := os.ReadFile("../../cli/defenseclaw/alert_semantics.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []string{AuditSkillScanned, AuditSkillBlocked, AuditSkillUnscanned, AuditSkillPending} {
		if !strings.Contains(string(raw), `"`+a+`"`) {
			t.Errorf("%s is not in SUBSTRATE_SKILL_AUDIT_ACTIONS", a)
		}
	}
}
