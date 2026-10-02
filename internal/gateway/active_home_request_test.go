// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
)

func TestCodexRequestHelpersResolveHomeAgainstTheVerifiedCaller(t *testing.T) {
	plain := codexHookRequest{CWD: "/work"}
	if got, want := plain.resolvedActiveHome(), trustedSameHostHome(); got != want {
		t.Fatalf("request without a handler-resolved home=%q want the per-user home %q", got, want)
	}
	peerCtx := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1001, Home: "/home/alice"})
	if got := plain.withTrustedActiveHome(peerCtx).resolvedActiveHome(); got != "/home/alice" {
		t.Fatalf("hook-socket request home=%q want /home/alice", got)
	}
	unresolved := withManagedHookPeer(context.Background(), managedHookPeer{UID: 1002})
	if got := plain.withTrustedActiveHome(unresolved).resolvedActiveHome(); got != unresolvedCallerHome {
		t.Fatalf("an unresolved caller home = %q, want the sentinel %q", got, unresolvedCallerHome)
	}
	if got, want := plain.withTrustedActiveHome(context.Background()).resolvedActiveHome(), trustedSameHostHome(); got != want {
		t.Fatalf("per-user handler home=%q want %q", got, want)
	}
}

func TestTrustedActiveHomeIsTheSentinelOffTheHookSocketOnAServiceAccountGateway(t *testing.T) {
	marked := withServiceAccountGateway(context.Background())
	if got := trustedActiveHome(marked); got != unresolvedCallerHome {
		t.Fatalf("a request off the verified hook socket resolved home %q on a service-account gateway", got)
	}
	restoreHome := userScopedIdentityHome
	userScopedIdentityHome = func(identity string) string {
		if identity == "4101" {
			return "/home/carol"
		}
		return ""
	}
	t.Cleanup(func() { userScopedIdentityHome = restoreHome })
	bound := context.WithValue(marked, verifiedUserScopedIdentityContextKey{}, "4101")
	if got := trustedActiveHome(bound); got != "/home/carol" {
		t.Fatalf("per-user credential caller home=%q, want the bound account's home", got)
	}
	unknown := context.WithValue(marked, verifiedUserScopedIdentityContextKey{}, "4102")
	if got := trustedActiveHome(unknown); got != unresolvedCallerHome {
		t.Fatalf("per-user credential caller without a home=%q, want the sentinel", got)
	}
	peerCtx := withManagedHookPeer(marked, managedHookPeer{UID: 1001, Home: "/home/alice"})
	if got := trustedActiveHome(peerCtx); got != "/home/alice" {
		t.Fatalf("hook-socket caller home=%q", got)
	}
	if got, want := trustedActiveHome(context.Background()), trustedSameHostHome(); got != want {
		t.Fatalf("per-user gateway home=%q want %q", got, want)
	}
}
