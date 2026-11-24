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
)

// B2 2.4: git_push tightens deny > ask > allow between substrate.admin and
// a profile; unset follows substrate.git.push_branch, whose deny is the
// cluster's off switch and wins over every floor.
func TestB2GitPushFloorAndOffSwitch(t *testing.T) {
	for _, c := range []struct {
		admin, profile, def, want string
	}{
		{"", "", "", SubstrateGitPushAsk},
		{"", "", "allow", SubstrateGitPushAllow},
		{"", "allow", "ask", SubstrateGitPushAllow},
		{"ask", "allow", "allow", SubstrateGitPushAsk},
		{"deny", "allow", "allow", SubstrateGitPushDeny},
		{"", "Deny", "allow", SubstrateGitPushDeny},
		{"", "allow", "deny", SubstrateGitPushDeny},
		{"allow", "", "DENY", SubstrateGitPushDeny},
	} {
		floor, err := TightenSandboxAdmin(SandboxAdminConfig{GitPush: c.admin}, &SandboxAdminConfig{GitPush: c.profile})
		if err != nil {
			t.Fatalf("%+v: %v", c, err)
		}
		if got := floor.EffectiveGitPush(c.def); got != c.want {
			t.Errorf("admin %q profile %q push_branch %q: %q, want %q", c.admin, c.profile, c.def, got, c.want)
		}
	}
	if (SubstrateGitConfig{}).EffectivePushBranch() != SubstrateGitPushAsk {
		t.Fatal("push_branch default is not ask")
	}
	if !strings.Contains(strings.Join(SandboxSubstrateOnlyKeys, ","), "git_push") {
		t.Fatal("git_push is not a Substrate-only floor key (openshell.admin would take it)")
	}
}
