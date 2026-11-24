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

	"github.com/defenseclaw/defenseclaw/internal/cliusage"
)

// GAP-0429: after the anchors Secret is replaced with another key, every
// stage bundle stops verifying and its atespaces fall back. The controller
// writes only an alert event; doctor, as an administrator, must name the
// stages and fail. A non-administrator (403), a cluster with bundles off
// (501) and an older cluster (404) get no row at all.
func TestGAP0429DoctorFailsWhenStageBundlesNoLongerVerify(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantExit int
		want     []string
		notWant  []string
	}{
		{
			name:     "anchors replaced: both stages fail to verify",
			body:     `{"stages":{"s-803aa76cb2":{},"s-f2beeb1201":{}},"problems":[{"stage":"s-803aa76cb2","code":"signature_invalid","error":"x"},{"stage":"s-f2beeb1201","code":"signature_invalid","error":"x"}]}`,
			wantExit: 1,
			want: []string{"fail  policy_bundles", "2 of 2 stage(s) no longer verify", "s-803aa76cb2 (signature_invalid)",
				"not ready: 1 problem(s)", "policy_bundles: apply a bundle signed by a key of the bundle-anchors Secret"},
		},
		{
			name: "every stage verifies",
			body: `{"stages":{"canary":{},"all":{}},"receipts":[]}`,
			want: []string{"ok    policy_bundles", "each of 2 stage(s) verifies", "the cluster components were not checked"},
		},
		{
			name: "no bundle applied",
			body: `{"stages":{}}`,
			want: []string{"ok    policy_bundles", "no policy bundle is applied"},
		},
		{
			name: "no anchors and nothing applied",
			body: `{"stages":{},"anchors_error":"bundle anchor_missing: no trust anchor file"}`,
			want: []string{"warn  policy_bundles", "cannot read its bundle trust anchors", "the cluster components were not checked"},
		},
		{name: "not an administrator", status: 403, notWant: []string{"policy_bundles"}},
		{name: "bundles off", status: 501, notWant: []string{"policy_bundles"}},
		{name: "older cluster", status: 404, notWant: []string{"policy_bundles"}},
		{name: "store unavailable", status: 503, want: []string{"warn  policy_bundles", "could not be read", "the cluster components were not checked"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubAdminFake(t)
			if tc.status != 0 {
				f.statusStatus = tc.status
			}
			f.statusBody = tc.body
			c := f.context()
			subAdminSeams(t, func() (*substrateSession, error) { return f.session(t, c), nil }, nil)
			out, _, err := runSubAdmin(newSubstrateDoctorCmd())
			if got := cliusage.ExitCode(err); (err == nil && tc.wantExit != 0) || (err != nil && got != tc.wantExit) {
				t.Fatalf("exit %d (err %v), want %d\n%s", got, err, tc.wantExit, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(out, w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(out, w) {
					t.Errorf("output has %q:\n%s", w, out)
				}
			}
		})
	}
}
