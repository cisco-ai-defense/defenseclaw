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

package workspace

import (
	"strings"
	"testing"
)

// GAP-0720: each clone failure gets its own advice; a host the rules refuse
// wins over the 403 a refused CONNECT looks like.
func TestGAP0720CloneErrorAdvice(t *testing.T) {
	for _, tc := range []struct {
		e    CloneError
		want string
		cred bool
	}{
		{CloneError{Message: "CONNECT tunnel failed, response 403", Refused: "git.corp.example"}, "not_in_allow_only", false},
		{CloneError{Message: "CONNECT tunnel failed, response 403"}, "needs a credential", true},
		{CloneError{Message: "write error: No space left on device"}, "disk is full", false},
		{CloneError{Message: "git@ghe.corp.example: Permission denied (publickey)."}, "substrate.git.https_rewrite", false},
	} {
		if got := tc.e.Error(); !strings.Contains(got, tc.want) || tc.e.NeedsCredential() != tc.cred {
			t.Errorf("%q: %s (cred %v)", tc.e.Message, got, tc.e.NeedsCredential())
		}
	}
}
