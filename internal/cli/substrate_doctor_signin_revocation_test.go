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

// B5.1: the 503 revocation_unavailable message sends people to
// `defenseclaw substrate doctor`, so the laptop doctor has a
// signin_revocation row. An administrator sees the gateway's own
// substrate.signin_revocation row; a gateway without it (older than 1.0.11)
// is a warning; a gateway whose list of ended sign-ins is too old refuses
// every sign-in (the doctor route too), which the row reads from the
// sign_in answer; a non-administrator gets no row.
func TestSubstrateDoctorSignInRevocationRow(t *testing.T) {
	cases := []struct {
		name         string
		actorsStatus int
		actorsReason string
		doctorStatus int
		doctorBody   string
		wantExit     int
		want         []string
		notWant      []string
	}{
		{
			name: "on",
			want: []string{"ok    signin_revocation", "the gateway says: on: 0 person-wide end(s) active", "the cluster components were not checked"},
		},
		{
			name:       "off on the cluster",
			doctorBody: `{"checks":[{"id":"substrate.signin_revocation","status":"warn","detail":"ending sign-ins is off: a copied sign-in token works until it expires (up to 24 h)","fix":"set substrate.identity.revocation.enabled: true and restart the gateway"}]}`,
			want: []string{"warn  signin_revocation", "ending sign-ins is off", "to fix: set substrate.identity.revocation.enabled: true",
				"the cluster components were not checked"},
		},
		{
			name:       "older gateway: no such row",
			doctorBody: `{"checks":[{"id":"substrate.model_upstreams_private","status":"pass","detail":"x"}]}`,
			want:       []string{"warn  signin_revocation", "older than 1.0.11", "keeps working until it expires (up to 24 h)", "upgrade DefenseClaw on the cluster", "the cluster components were not checked"},
		},
		{
			name:         "older gateway: no doctor route",
			doctorStatus: 404,
			want:         []string{"warn  signin_revocation", "older than 1.0.11", "the cluster components were not checked"},
		},
		{name: "not an administrator", doctorStatus: 403, notWant: []string{"signin_revocation"}},
		{
			name:         "list too old: every sign-in refused",
			actorsStatus: 503, actorsReason: "revocation_unavailable",
			// The doctor route is refused the same way.
			doctorStatus: 503, doctorBody: "revocation_unavailable",
			wantExit: 1,
			want: []string{"fail  sign_in", "can't check ended sign-ins right now (see signin_revocation)",
				"fail  signin_revocation", "can't read its list of ended sign-ins right now", "leader pod", "not ready: 2 problem(s)"},
			// Inside doctor, "run defenseclaw substrate doctor" would send
			// the reader in a circle.
			notWant: []string{"run defenseclaw substrate doctor"},
		},
		{
			name:       "the gateway's row fails",
			doctorBody: `{"checks":[{"id":"substrate.signin_revocation","status":"fail","detail":"this gateway's list of ended sign-ins is 2m0s old (limit 1m0s)\u001b[31m","fix":"check that the leader pod is running"}]}`,
			wantExit:   1,
			want:       []string{"fail  signin_revocation", "is 2m0s old (limit 1m0s)", "signin_revocation: check that the leader pod is running", "not ready: 1 problem(s)"},
			notWant:    []string{"\x1b"},
		},
		{
			name:         "doctor route unavailable",
			doctorStatus: 503, doctorBody: "secret_store_unavailable",
			want: []string{"warn  signin_revocation", "could not be read", "the cluster components were not checked"},
		},
		{name: "not signed in", actorsStatus: 401, notWant: []string{"signin_revocation"}, wantExit: 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSubAdminFake(t)
			if tc.actorsStatus != 0 {
				f.actorsStatus = tc.actorsStatus
			}
			f.actorsReason, f.doctorStatus, f.doctorBody = tc.actorsReason, tc.doctorStatus, tc.doctorBody
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
