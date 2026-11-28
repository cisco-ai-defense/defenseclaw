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
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// B5.4 (GAP-0477): substrate.skills keys, their defaults and bounds.
func TestSubstrateSkillsConfigDefaultsAndBounds(t *testing.T) {
	var s SubstrateConfig
	if !s.SkillScanEnabled() || s.EffectiveSkillScanTimeout() != 20*time.Second || s.EffectiveSkillPendingWait() != 8*time.Second {
		t.Fatalf("defaults: on=%v timeout=%v wait=%v", s.SkillScanEnabled(), s.EffectiveSkillScanTimeout(), s.EffectiveSkillPendingWait())
	}
	off := false
	s.Skills = SubstrateSkillsConfig{Scan: SubstrateSkillsScanConfig{Enabled: &off, Timeout: "45s"}, PendingWait: "3s"}
	if s.SkillScanEnabled() || s.EffectiveSkillScanTimeout() != 45*time.Second || s.EffectiveSkillPendingWait() != 3*time.Second {
		t.Fatalf("set: on=%v timeout=%v wait=%v", s.SkillScanEnabled(), s.EffectiveSkillScanTimeout(), s.EffectiveSkillPendingWait())
	}
	// GAP-0982: a post must be answered inside the kit's 9 s first attempt.
	for _, w := range []string{"9s", "5m"} {
		s.Skills.PendingWait = w
		if s.EffectiveSkillPendingWait() != 8*time.Second {
			t.Fatalf("a pending_wait of %s (over 8s) must not be used: %v", w, s.EffectiveSkillPendingWait())
		}
	}
	for _, tc := range []struct{ timeout, wait, key string }{
		{"0s", "", "skills.scan.timeout"},
		{"11m", "", "skills.scan.timeout"},
		{"", "9s", "skills.pending_wait"},
		{"", "61s", "skills.pending_wait"},
		{"", "soon", "skills.pending_wait"},
	} {
		c := SubstrateConfig{Skills: SubstrateSkillsConfig{Scan: SubstrateSkillsScanConfig{Timeout: tc.timeout}, PendingWait: tc.wait}}
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%+v: want a %s error, got %v", tc, tc.key, err)
		}
	}
	raw := "skills:\n  scan:\n    enabled: false\n    timeout: 30s\n  pending_wait: 5s\n"
	var back SubstrateConfig
	if err := yaml.Unmarshal([]byte(raw), &back); err != nil {
		t.Fatal(err)
	}
	if back.SkillScanEnabled() || back.Skills.Scan.Timeout != "30s" || back.Skills.PendingWait != "5s" {
		t.Fatalf("yaml: %+v", back.Skills)
	}
}
