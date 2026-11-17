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
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0388: status of an unattended run on a queue profile said asks are
// denied although the ask was queued in approvals.
func TestGAP0388StatusModeFollowsTheProfileAskRule(t *testing.T) {
	for raw, want := range map[string]string{
		`{"unattended":true,"unattended_asks":"queue","ask_timeout":"5m0s"}`: "unattended (asks wait for up to 5m0s for a person: defenseclaw substrate approvals)",
		`{"unattended":true,"unattended_asks":"deny"}`:                       "unattended (asks are denied)",
		`{"unattended":true}`:                                                "unattended (asks are denied)",
	} {
		var a api.Actor
		if err := json.Unmarshal([]byte(raw), &a); err != nil {
			t.Fatal(err)
		}
		if got := substrateUnattendedMode(a); got != want {
			t.Fatalf("%s: Mode %q, want %q", raw, got, want)
		}
	}
}
