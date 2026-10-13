//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The managed ACP enrollment of a deleted account is revoked like its hook
// rows: after the third definitive miss, or at once by repair; a live
// account keeps its enrollment (GAP-0367).
func TestGoneUnixACPPrincipalsRevokesDeletedAccounts(t *testing.T) {
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: 1001}}}
	local := func() (map[string]int, error) { return map[string]int{"alice": 1001}, nil }
	state := &UnixEnumeratorState{Version: 1}
	opts := UnixGoneACPOptions{
		Principals: []string{"uid:1001", "uid:1051", "home:abc"}, Resolver: resolver, LocalAccounts: local,
		DirectoryConfigured: func() bool { return false }, State: state,
	}
	for cycle := 1; cycle < UnixRevokeAfterMisses; cycle++ {
		if gone, _ := GoneUnixACPPrincipals(t.Context(), opts); len(gone) != 0 {
			t.Fatalf("cycle %d revoked %v before the third miss", cycle, gone)
		}
	}
	if gone, _ := GoneUnixACPPrincipals(t.Context(), opts); !reflect.DeepEqual(gone, []string{"uid:1051"}) {
		t.Fatalf("third miss: gone = %v, want uid:1051", gone)
	}
	opts.State, opts.Immediate = &UnixEnumeratorState{Version: 1}, true
	if gone, _ := GoneUnixACPPrincipals(t.Context(), opts); !reflect.DeepEqual(gone, []string{"uid:1051"}) {
		t.Fatalf("repair: gone = %v, want uid:1051 at once", gone)
	}
}
