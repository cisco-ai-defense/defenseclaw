// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net/url"
	"strings"
	"testing"
)

// GAP-2035: `agent-identities --user <bare name>` with an empty listing
// asked the resolve route without root's caller facts, so on an SSSD-joined
// host the gateway service could not resolve the bare name and the view was
// refused (rc 2) for an existing account. The check sends the account as
// root resolves it, as profile-explain does.
func TestEmptyListingCheckSendsRootsCallerFacts(t *testing.T) {
	previousFacts, previousGet := enterpriseExplainCallerFacts, enterpriseIdentityViewGet
	t.Cleanup(func() { enterpriseExplainCallerFacts, enterpriseIdentityViewGet = previousFacts, previousGet })
	enterpriseExplainCallerFacts = func(user string) string {
		if user == "alice" {
			return "facts-of-alice"
		}
		return ""
	}
	var asked string
	enterpriseIdentityViewGet = func(path string, out any) (string, error) {
		asked = path
		return "", nil
	}
	if err := refuseUnknownIdentityViewAccount("alice"); err != nil {
		t.Fatal(err)
	}
	_, raw, _ := strings.Cut(asked, "?")
	query, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	if query.Get("user") != "alice" || query.Get("caller_facts") != "facts-of-alice" {
		t.Fatalf("asked %q; want user=alice with root's caller facts", asked)
	}
	if err := refuseUnknownIdentityViewAccount("nobody"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(asked, "caller_facts") {
		t.Fatalf("asked %q; an account root does not resolve sends no caller facts", asked)
	}
}
