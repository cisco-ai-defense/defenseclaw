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

package sandboxcli

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1200: with allow_unblock: false and user_approvals unset, explain said
// the user may approve asks "for a session or for good", while the managed
// gateway refuses `approve --always`. The Approvals row says what the
// gateway's check (sandboxreg.CheckApprovals) allows, for every
// combination.
func TestManagedApprovalsRowMatchesTheGatewaysCheck(t *testing.T) {
	no, yes := false, true
	for _, tc := range []struct {
		approvals string
		unblock   bool
		want      string
	}{
		{"", true, "you may approve asks for a session or for good"},
		{"", false, "you may approve asks for this session only; you can't unblock destinations"},
		{"session", true, "you may approve asks for this session only"},
		{"session", false, "you may approve asks for this session only; you can't unblock destinations"},
		{"none", true, "you can't approve asks; they are refused"},
		{"none", false, "you can't approve asks; they are refused; you can't unblock destinations"},
	} {
		m := managedExplainFixture()
		m.UserApprovals, m.AllowUnblock = tc.approvals, tc.unblock
		got := ""
		for _, r := range managedExplainRowsFor(m, nil, "", time.Now()) {
			if r.label == "Approvals" {
				got = r.text
			}
		}
		if got != tc.want {
			t.Fatalf("approvals %q allow_unblock %v: %q, want %q", tc.approvals, tc.unblock, got, tc.want)
		}
		// The row agrees with what the gateway does with `approve --always`.
		floor := config.OpenShellAdminConfig{UserApprovals: tc.approvals, AllowUnblock: &no}
		if tc.unblock {
			floor.AllowUnblock = &yes
		}
		always := sandboxreg.CheckApprovals(floor, sandboxrelay.DecisionEgressAllow, sandboxrelay.DecisionScopeAlways) == nil
		if forGood := got == "you may approve asks for a session or for good"; forGood != always {
			t.Fatalf("approvals %q allow_unblock %v: row %q, but approve --always allowed=%v", tc.approvals, tc.unblock, got, always)
		}
	}
}
