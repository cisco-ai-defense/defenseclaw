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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/policy"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// b54LiveScanner is the gateway's runtime skill scan against a real scanner
// sidecar (the same steps as cli.runtimeSkillScanner).
type b54LiveScanner struct{ rt *attest.RuntimeScanner }

func (s b54LiveScanner) ScanSkillFolder(ctx context.Context, name, dir string, files []SubstrateAttachedFile) (bool, string, error) {
	a := attest.RuntimeAsset{Kind: config.AdmissionTypeSkill, Name: name, Path: dir}
	for _, f := range files {
		a.Files = append(a.Files, attest.AttachedFile{Role: attest.RoleSkillFile, Path: f.Path, Content: f.Content, Truncated: f.Truncated})
	}
	d, err := s.rt.Scan(ctx, a)
	if err != nil {
		return false, "", err
	}
	if d.Unavailable {
		return false, "", fmt.Errorf("%w: %s", ErrSubstrateSkillScannerUnavailable, d.Reason)
	}
	return d.Action == "block", d.Reason, nil
}

// Live (B5.4, GAP-0477 J17): the hook pass of this build against a running
// scanner sidecar. DC_B54_LIVE_SCAN_DIR is the sidecar's shared folder and
// DC_B54_LIVE_FIXTURE a skill folder on the test host. Skipped without them.
func TestB54LiveSidecarHookPass(t *testing.T) {
	scanDir, fixture := os.Getenv("DC_B54_LIVE_SCAN_DIR"), os.Getenv("DC_B54_LIVE_FIXTURE")
	if scanDir == "" || fixture == "" {
		t.Skip("live only: set DC_B54_LIVE_SCAN_DIR and DC_B54_LIVE_FIXTURE")
	}
	remote, err := scanner.NewRemoteSkillScanner(config.SkillScannerConfig{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	remote.Dir = scanDir
	files := map[string]string{}
	entries, err := os.ReadDir(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(fixture, e.Name())); err == nil && e.Type().IsRegular() {
			files[e.Name()] = string(b)
		}
	}
	for _, block := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed=%v", block), func(t *testing.T) {
			r := newB54Rig(t, block, 20*time.Second, 10*time.Second)
			r.f.api.substrateState().cfg.Skills = b54LiveScanner{rt: &attest.RuntimeScanner{Skill: remote, Compiled: policy.CompileAdmission(&config.Config{})}}
			dir := "/sandbox/.claude/skills/" + filepath.Base(fixture)
			start := time.Now()
			out := r.post(t, dir, files)
			q := quarantined(out)
			t.Logf("hook answered in %v: quarantine=%+v", time.Since(start).Round(time.Millisecond), q)
			if len(q) != 1 || q[0].Code != SkillReasonFinding || !strings.Contains(q[0].Reason, "DefenseClaw blocked the skill") {
				t.Fatalf("not blocked by the sidecar scan: %+v", q)
			}
			b := r.rowsOf(AuditSkillBlocked)
			if len(b) != 1 {
				t.Fatalf("blocked rows %+v", b)
			}
			t.Logf("audit %s %s reason=%v detail=%v", b[0].action, b[0].sev, b[0].d["reason"], b[0].d["detail"])
		})
	}
	t.Run("pending then blocked", func(t *testing.T) {
		r := newB54Rig(t, true, 20*time.Second, 200*time.Millisecond)
		r.f.api.substrateState().cfg.Skills = b54LiveScanner{rt: &attest.RuntimeScanner{Skill: remote, Compiled: policy.CompileAdmission(&config.Config{})}}
		dir := "/sandbox/.claude/skills/" + filepath.Base(fixture) + "-p"
		out := r.post(t, dir, files)
		if len(quarantined(out)) != 0 || !unscannedIn(out, dir) || len(r.rowsOf(AuditSkillPending)) != 1 {
			t.Fatalf("first hook: %s %+v", out[substrateUnscannedField], r.rowsOf(AuditSkillPending))
		}
		for r.f.api.substrateState().inFlightScans() > 0 {
			time.Sleep(50 * time.Millisecond)
		}
		q := quarantined(r.post(t, dir, files))
		t.Logf("pending, then the next hook: quarantine=%+v", q)
		if len(q) != 1 || q[0].Code != SkillReasonFinding {
			t.Fatalf("second hook: %+v", q)
		}
	})
	t.Run("sidecar down", func(t *testing.T) {
		down, err := scanner.NewRemoteSkillScanner(config.SkillScannerConfig{}, 0)
		if err != nil {
			t.Fatal(err)
		}
		down.Dir = t.TempDir()
		for _, block := range []bool{true, false} {
			r := newB54Rig(t, block, 20*time.Second, 10*time.Second)
			r.f.api.substrateState().cfg.Skills = b54LiveScanner{rt: &attest.RuntimeScanner{Skill: down, Compiled: policy.CompileAdmission(&config.Config{})}}
			q := quarantined(r.post(t, "/sandbox/.claude/skills/x", files))
			t.Logf("sidecar down, managed=%v: quarantine=%+v alerts=%+v", block, q, r.alerts)
			if block != (len(q) == 1 && q[0].Code == SkillReasonScannerDown) {
				t.Fatalf("managed=%v: %+v", block, q)
			}
		}
	})
}
