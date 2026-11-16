// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

type viewProofResolver struct{ account unixidentity.Account }

func (r viewProofResolver) LookupUser(name string) (unixidentity.Account, error) {
	if name != r.account.Name {
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	return r.account, nil
}

func (r viewProofResolver) LookupUID(uid int) (unixidentity.Account, error) {
	if uid != r.account.UID {
		return unixidentity.Account{}, unixidentity.ErrNotFound
	}
	return r.account, nil
}

func (viewProofResolver) AccountIncarnation(int, string) (string, bool) { return "files", true }

// GAP-1948 (RV4-3): root's agent identity view sends holder_proof for a uid
// filter too, the proof of the home of the account that holds the uid now,
// so the first view by uid after a recreate hides the earlier holder's rows
// (GAP-1876). A SID filter sends none.
func TestIdentityViewHolderProofForAUIDFilter(t *testing.T) {
	home := t.TempDir()
	previous := enterpriseIdentityViewRootResolver
	t.Cleanup(func() { enterpriseIdentityViewRootResolver = previous })
	enterpriseIdentityViewRootResolver = func(context.Context) (enterpriseIdentityViewResolver, bool) {
		return viewProofResolver{unixidentity.Account{UID: 52100, Name: "fcuid1", Home: home}}, true
	}
	want := "52100:" + enterprisehooks.LegacyAgentOwnerToken("files", home)
	for _, filter := range []string{"52100", "fcuid1"} {
		if got := enterpriseIdentityViewHolderProof(filter); got != want {
			t.Fatalf("--user %s: holder_proof %q, want %q", filter, got, want)
		}
	}
	if got := enterpriseIdentityViewHolderProof("S-1-5-21-1-2-3-1001"); got != "" {
		t.Fatalf("SID filter: holder_proof %q, want none", got)
	}
}
