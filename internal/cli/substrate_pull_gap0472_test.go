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
	"errors"
	"testing"
)

// GAP-0472: pull --apply --yes wrote every flagged file. --yes takes the
// safe answer (no) and never accepts flagged files for the user; only
// --allow-flagged or a terminal answer of y does.
func TestGAP0472PullApplyYesDoesNotAcceptFlaggedFiles(t *testing.T) {
	asked := 0
	ask := func(answer bool) func() (bool, error) {
		return func() (bool, error) { asked++; return answer, nil }
	}
	cases := []struct {
		name                        string
		f                           substratePullFlags
		sensitive, tty, answer      bool
		wantAccept, wantWrite, asks bool
	}{
		{name: "--apply --yes, flagged, terminal", f: substratePullFlags{apply: true, yes: true}, sensitive: true, tty: true, wantAccept: false, wantWrite: true},
		{name: "--apply --yes, flagged, no terminal", f: substratePullFlags{apply: true, yes: true}, sensitive: true, wantAccept: false, wantWrite: true},
		{name: "--apply, flagged, no terminal", f: substratePullFlags{apply: true}, sensitive: true, wantAccept: false, wantWrite: true},
		{name: "--apply, flagged, answered no", f: substratePullFlags{apply: true}, sensitive: true, tty: true, answer: false, wantAccept: false, wantWrite: false, asks: true},
		{name: "--apply, flagged, answered yes", f: substratePullFlags{apply: true}, sensitive: true, tty: true, answer: true, wantAccept: true, wantWrite: true, asks: true},
		{name: "--apply --allow-flagged", f: substratePullFlags{apply: true, allowFlagged: true, yes: true}, sensitive: true, tty: true, wantAccept: true, wantWrite: true},
		{name: "--apply --yes, nothing flagged", f: substratePullFlags{apply: true, yes: true}, tty: true, wantAccept: false, wantWrite: true},
	}
	for _, tc := range cases {
		asked = 0
		accept, write, err := substratePullAccept(&tc.f, tc.sensitive, tc.tty, ask(tc.answer))
		if err != nil || accept != tc.wantAccept || write != tc.wantWrite || (asked == 1) != tc.asks {
			t.Errorf("%s: accept %v write %v asked %d err %v; want accept %v write %v asks %v", tc.name, accept, write, asked, err, tc.wantAccept, tc.wantWrite, tc.asks)
		}
	}
	if _, _, err := substratePullAccept(&substratePullFlags{apply: true}, true, true, func() (bool, error) { return false, errors.New("eof") }); err == nil {
		t.Error("a failed question was taken as an answer")
	}
}
