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

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	substrateapi "github.com/defenseclaw/defenseclaw/internal/cli/substratecli/api"
)

// GAP-0397: `defenseclaw substrate policy reset ATESPACE/NAME` reaches the
// route the admin listener registers. The launcher's client is driven
// against the real admin handler (router, sign-in, CSRF gate), so a path
// drift between the two fails here, as the relative "policy/reset" did.
func TestLauncherPolicyResetReachesTheAdminRoute(t *testing.T) {
	var got []string
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.PolicyReset = func(_ context.Context, atespace, actor, by, reason string) error {
			got = append(got, atespace+"/"+actor+"|"+reason)
			return nil
		}
	})
	srv := httptest.NewServer(f.admin)
	defer srv.Close()
	client := func(tok string) *substrateapi.Client {
		t.Helper()
		c, err := substrateapi.New(substrateapi.Options{Base: srv.URL, Token: func(context.Context) (string, error) { return tok, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	ctx := t.Context()

	out, err := client("p-admin").PolicyReset(ctx, "eng-web/alice-1", "GitOps fixed")
	if err != nil {
		t.Fatalf("admin reset: %v", err)
	}
	if out["status"] != "requested" || out["atespace"] != "eng-web" || out["actor"] != "alice-1" {
		t.Fatalf("answer = %v", out)
	}
	if len(got) != 1 || got[0] != "eng-web/alice-1|GitOps fixed" {
		t.Fatalf("requests = %v", got)
	}
	// No reason: still the same route.
	if _, err := client("p-admin").PolicyReset(ctx, "eng-web/bob-1", ""); err != nil {
		t.Fatalf("admin reset without a reason: %v", err)
	}
	if len(got) != 2 || got[1] != "eng-web/bob-1|" {
		t.Fatalf("requests = %v", got)
	}
	// A person who is not an administrator is refused by the route (403),
	// not missed by the router (404).
	_, err = client("p-alice").PolicyReset(ctx, "eng-web/alice-1", "mine")
	if e, ok := substrateapi.AsError(err); !ok || e.Status != http.StatusForbidden {
		t.Fatalf("user reset: %v, want 403", err)
	}
	// A reference that is not ATESPACE/NAME never leaves the client.
	for _, ref := range []string{"alice-1", "/alice-1", "eng-web/", "eng-web/a/b"} {
		if _, err := client("p-admin").PolicyReset(ctx, ref, ""); err == nil {
			t.Errorf("%q was sent", ref)
		}
	}
	if len(got) != 2 {
		t.Fatalf("requests = %v", got)
	}
}
