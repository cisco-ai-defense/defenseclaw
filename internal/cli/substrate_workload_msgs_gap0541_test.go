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

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0541: a workload whose profile has no launcher atespace was told "you
// may not use that profile ... leave --profile out" although it named no
// profile. The cluster now says profile_no_atespace and the launcher names
// the profile and the fix.
func TestGAP0541ProfileWithNoLauncherAtespaceNamesTheFix(t *testing.T) {
	msg := substrateAPIMessage(&api.Error{Status: 403, Reason: "profile_no_atespace", Detail: "ci-profile"})
	if !strings.Contains(msg, "your profile ci-profile has no launcher atespace") || !strings.Contains(msg, "substrate.launcher_atespaces") ||
		strings.Contains(msg, "leave --profile out") {
		t.Fatalf("message = %q", msg)
	}
}

// GAP-0543: a token whose subject or claims the cluster does not allow was
// told to sign in again, which repeats the same refusal. It now says the
// identity is not allowed; an expired or bad token still says sign in.
func TestGAP0543IdentityRefusalDoesNotSaySignInAgain(t *testing.T) {
	for _, reason := range []string{"subject", "claims"} {
		msg := substrateAPIMessage(&api.Error{Status: 401, Reason: reason})
		if strings.Contains(msg, "Sign in again with") || !strings.Contains(msg, "does not allow this identity") {
			t.Errorf("%s: %q", reason, msg)
		}
	}
	if msg := substrateAPIMessage(&api.Error{Status: 401, Reason: "expired"}); !strings.Contains(msg, "Sign in again with") {
		t.Errorf("expired: %q", msg)
	}
}
