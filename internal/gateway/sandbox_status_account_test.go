// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func managedStatusJSON(t *testing.T, f *sandboxDaemonFixture) string {
	t.Helper()
	st, err := sandboxapi.NewUnixClient(f.socket).Status(context.Background())
	if err != nil || st.Managed == nil {
		t.Fatalf("status = %+v, %v", st, err)
	}
	raw, err := json.Marshal(st.Managed)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// GAP-1985: a profile that sets sandbox.allowed false is sent in the status
// as the account's verdict, apart from the policy being unreadable.
func TestManagedStatusCarriesAnAccountThatTheProfileRefuses(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	f.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{Profile: "no-sandbox", Allowed: false}, nil
	}
	f.run(t)
	if got := managedStatusJSON(t, f); !strings.Contains(got, `"account_denied":true`) {
		t.Fatalf("a refused account is not in the status: %s", got)
	}

	f2 := newSandboxDaemonFixture(t)
	f2.relay.explain = func(sandboxrelay.ExplainRequest) (sandboxapi.ManagedExplain, error) {
		return sandboxapi.ManagedExplain{}, sandboxapi.Errorf(sandboxapi.CodeUnavailable, "down")
	}
	f2.run(t)
	if got := managedStatusJSON(t, f2); strings.Contains(got, `"account_denied"`) {
		t.Fatalf("an unreadable policy was taken for a refusal: %s", got)
	}
}
