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

// GAP-0437: policy_bundles fails when the bundle pulled for an OCI stage was
// refused and warns while one is not pulled yet; a pulled, applied stage is
// OK as before.
func TestGAP0437DoctorBundlesOCIStages(t *testing.T) {
	const ref = `"ref":"registry.example.com/p@sha256:ab"`
	cases := []struct {
		name     string
		body     string
		wantExit int
		want     []string
	}{
		{name: "refused", wantExit: 1,
			body: `{"stages":{"prod":{}},"oci":[{"stage":"prod",` + ref + `,"state":"processed","result":"refused","code":"key_unknown"}]}`,
			want: []string{"fail  policy_bundles", "refused for stage(s) prod (key_unknown)", "keep their last verified bundle"}},
		{name: "pending",
			body: `{"stages":{},"oci":[{"stage":"prod",` + ref + `,"state":"pending"}]}`,
			want: []string{"warn  policy_bundles", "stage(s) prod is not pulled yet", "the cluster components were not checked"}},
		{name: "applied",
			body: `{"stages":{"prod":{}},"oci":[{"stage":"prod",` + ref + `,"state":"processed","result":"applied"}]}`,
			want: []string{"ok    policy_bundles", "the active bundle of each of 1 stage(s) verifies"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubAdminFake(t)
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
		})
	}
}
