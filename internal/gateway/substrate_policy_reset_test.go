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

import (
	"context"
	"net/http"
	"testing"
)

// The admin reset of policy_conflict: admins only, audited with who asked.
func TestSubstratePolicyResetRoute(t *testing.T) {
	var got []string
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.PolicyReset = func(_ context.Context, atespace, actor, by, reason string) error {
			got = append(got, atespace+"/"+actor+"|"+by+"|"+reason)
			return nil
		}
	})
	path := "/api/v1/substrate/actors/eng-web/alice-1/policy/reset"
	if rec := f.do(t, f.admin, http.MethodPost, path, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, path, "p-alice", `{"reason":"mine"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("a user reset policy: %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, path, "tok-alice", ""); rec.Code == http.StatusAccepted {
		t.Fatal("the actor listener serves the reset")
	}
	if rec := f.do(t, f.admin, http.MethodPost, path, "p-admin", `{"reason":"GitOps fixed"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("admin reset: %d %s", rec.Code, rec.Body)
	}
	if len(got) != 1 || got[0] == "" || got[0][:len("eng-web/alice-1|")] != "eng-web/alice-1|" {
		t.Fatalf("requests = %v", got)
	}
	if rec := f.do(t, f.admin, http.MethodPost, path, "p-admin", `{bad`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body: %d", rec.Code)
	}
}
