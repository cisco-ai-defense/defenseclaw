// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"
)

const routeCredentialTestKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestUserScopedRouteTokenIsItsOwnKind(t *testing.T) {
	route, err := UserScopedRouteToken(routeCredentialTestKey, "ClaudeCode", "1001")
	if err != nil {
		t.Fatal(err)
	}
	hook, _ := UserScopedHookAPIToken(routeCredentialTestKey, "claudecode", "1001")
	if route == hook || len(route) != 64 {
		t.Fatalf("route credential must differ from the hook credential and be 64 hex: %q", route)
	}
	again, _ := UserScopedRouteToken(routeCredentialTestKey, "claudecode", "1001")
	other, _ := UserScopedRouteToken(routeCredentialTestKey, "claudecode", "1002")
	codex, _ := UserScopedRouteToken(routeCredentialTestKey, "codex", "1001")
	if again != route || other == route || codex == route {
		t.Fatal("route credential must be bound to connector and identity, and stable")
	}
	if _, err := UserScopedRouteToken(routeCredentialTestKey, "claudecode", "alice"); err == nil {
		t.Fatal("an account name is not an identity")
	}
}

func TestRouteEpochRotatesTheRouteCredential(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	plain, err := ManagedRouteToken(routeCredentialTestKey, nil, "codex", sid)
	if err != nil {
		t.Fatal(err)
	}
	direct, _ := UserScopedRouteToken(routeCredentialTestKey, "codex", sid)
	if plain != direct {
		t.Fatal("without an epoch the route credential derives from the per-user key")
	}
	first, _ := NewRouteEpoch()
	second, _ := NewRouteEpoch()
	a, _ := ManagedRouteToken(routeCredentialTestKey, &first, "codex", sid)
	b, _ := ManagedRouteToken(routeCredentialTestKey, &second, "codex", sid)
	if a == plain || a == b {
		t.Fatal("each epoch must give a new credential")
	}
	lower, _ := ManagedRouteToken(routeCredentialTestKey, &first, "codex", "s-1-5-21-1-2-3-1001")
	if lower != a {
		t.Fatal("SID case must not change the credential")
	}
	first.Generations[sid] = 1
	bumped, _ := ManagedRouteToken(routeCredentialTestKey, &first, "codex", sid)
	if bumped == a {
		t.Fatal("a generation bump must give a new credential")
	}
	otherUser, _ := ManagedRouteToken(routeCredentialTestKey, &first, "codex", "S-1-5-21-1-2-3-1002")
	delete(first.Generations, sid)
	otherBefore, _ := ManagedRouteToken(routeCredentialTestKey, &first, "codex", "S-1-5-21-1-2-3-1002")
	if otherUser != otherBefore {
		t.Fatal("a bump for one account must not change another account credential")
	}
}
