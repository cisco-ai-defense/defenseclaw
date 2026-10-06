// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	osuser "os/user"
	"testing"
)

// TestResolvePeerDirectoryFactsWithoutSpool pins the per-user macOS path: with
// no guardian identity spool record the account's groups still resolve, so a
// users or groups assignment is not reported as default_lookup_failed.
func TestResolvePeerDirectoryFactsWithoutSpool(t *testing.T) {
	setIdentitySpoolDir("")
	current, err := osuser.Current()
	if err != nil {
		t.Skipf("current user: %v", err)
	}
	facts, err := resolvePeerDirectoryFacts(current.Uid)
	if err != nil || facts.ResolvedAt.IsZero() || len(facts.Groups) == 0 {
		t.Fatalf("facts = %+v, err = %v; want resolved groups", facts, err)
	}
}
