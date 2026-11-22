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

package cli

import (
	"strings"
	"testing"
)

// GAP-0399: in policy_conflict the controller keeps the agent on deny-only
// and replaces every later foreign change with deny-only again, so a foreign
// policy never stays in force (GAP-0055, a security choice). The help said
// the controller stops reverting, which would leave the other writer's
// policy, and the access it grants, in force.
func TestSubstratePolicyResetHelpSaysDenyOnly(t *testing.T) {
	long := newSubstratePolicyResetCmd().Long
	if strings.Contains(long, "stops after three reverts") || strings.Contains(long, "stops reverting") {
		t.Errorf("the help says the controller stops reverting:\n%s", long)
	}
	for _, want := range []string{"deny-only", "replaced with deny-only again", "never stays in force", "writes the full policy again"} {
		if !strings.Contains(long, want) {
			t.Errorf("the help lacks %q:\n%s", want, long)
		}
	}
}
