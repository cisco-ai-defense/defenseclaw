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

package gateway

import "testing"

func TestMergeCodexToolResultVerdictsRanksRawAction(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name         string
		sourceRaw    string
		untrustedRaw string
		want         string
	}{
		{name: "source block survives untrusted allow", sourceRaw: "block", untrustedRaw: "allow", want: "block"},
		{name: "untrusted block outranks source allow", sourceRaw: "allow", untrustedRaw: "block", want: "block"},
		{name: "missing source adopts untrusted action", sourceRaw: "", untrustedRaw: "allow", want: "allow"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := mergeCodexToolResultVerdicts(
				&ToolInspectVerdict{Action: "allow", RawAction: test.sourceRaw, Severity: "NONE"},
				&ToolInspectVerdict{Action: "allow", RawAction: test.untrustedRaw, Severity: "NONE"},
			)
			if got.RawAction != test.want {
				t.Fatalf("RawAction=%q, want %q", got.RawAction, test.want)
			}
		})
	}
}
