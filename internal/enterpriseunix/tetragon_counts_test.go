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

package enterpriseunix

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
)

// GAP-0096: a session-count warning reads as a sentence for one session and
// for several, and the readiness line keeps an account name as it is
// spelled (the output's sentence case capitalized it: Dcr-std1).
func TestTetragonSessionCountsAgree(t *testing.T) {
	for code, want := range map[string][2]string{
		kernelpolicy.WarnRootsOverLimit: {
			"1 live agent session is over the 8-session limit of the monitor controls (the controls do not count its opens, and its user's burn-in pauses",
			"3 live agent sessions are over the 8-session limit of the monitor controls (the controls do not count their opens, and their users' burn-in pauses",
		},
		kernelpolicy.WarnSessionPolicyPending: {
			"1 agent session is waiting for an enabled controls policy that includes its process id (its user accrues no covered time",
			"3 agent sessions are waiting for an enabled controls policy that includes their process ids (their users accrue no covered time",
		},
		kernelpolicy.WarnSessionsPredateControls: {
			"1 agent session of an enforced user started before the kernel controls loaded (Tetragon marks an agent's processes when the agent starts, so it is monitored, not denied); restart it to be denied",
			"3 agent sessions of enforced users started before the kernel controls loaded (Tetragon marks an agent's processes when the agent starts, so these are monitored, not denied); restart them to be denied",
		},
	} {
		if got := tetragonMessage(code+":1", tetragonFacts{}); !strings.HasPrefix(got, want[0]) {
			t.Errorf("%s:1 = %q\nwant prefix %q", code, got, want[0])
		}
		if got := tetragonMessage(code+":3", tetragonFacts{}); !strings.HasPrefix(got, want[1]) {
			t.Errorf("%s:3 = %q\nwant prefix %q", code, got, want[1])
		}
		if got := tetragonMessage(code, tetragonFacts{}); !strings.HasPrefix(got, "some ") || !strings.Contains(got, " are ") {
			t.Errorf("%s without a count = %q", code, got)
		}
	}
	in := withUsers(readyInputs("observe"))
	in.State.UIDs[0].User = "Dcr-Mixed.Case"
	in.State.UIDs[0].Reason = kernelpolicy.WarnRootsOverLimit
	text := readinessText(t, tetragonReadiness(in, "observe", readyProbes, readinessNow))
	if !strings.Contains(text, "  ! The user Dcr-Mixed.Case runs more than 8 agent sessions") {
		t.Fatalf("readiness text:\n%s", text)
	}
	in.State.UIDs[0].User = "dcr-std1"
	text = readinessText(t, tetragonReadiness(in, "observe", readyProbes, readinessNow))
	if !strings.Contains(text, "  ! The user dcr-std1 runs more than 8 agent sessions") || strings.Contains(text, "Dcr-std1") {
		t.Fatalf("readiness text:\n%s", text)
	}
}
