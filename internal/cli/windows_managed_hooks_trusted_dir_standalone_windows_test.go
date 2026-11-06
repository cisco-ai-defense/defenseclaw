//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// g582 round 4 (class audit E6): the lifecycle and teardown folder check asks
// the standalone refusal before it re-stamps a drifted state-root or
// transaction folder, and returns the refusal without repairing.
func TestWindowsManagedHooksTrustedDirAsksTheStandaloneRefusalFirst(t *testing.T) {
	dir := t.TempDir()
	drift := errors.New("untrusted write entry")
	previousStrict, previousRefusal := windowsManagedHooksStrictDirCheck, windowsManagedHooksInPlaceRefusal
	t.Cleanup(func() {
		windowsManagedHooksStrictDirCheck, windowsManagedHooksInPlaceRefusal = previousStrict, previousRefusal
	})
	t.Setenv(managed.TrustStrictAncestorsEnv, "")
	windowsManagedHooksStrictDirCheck = func(string, string) error { return drift }
	asked := 0
	windowsManagedHooksInPlaceRefusal = func(path string, kind managed.ObjectKind) error {
		asked++
		if path != dir || kind != managed.ObjectStateDirectory {
			t.Fatalf("refusal asked for %s %s", path, kind)
		}
		return managed.RefuseStandaloneContentDrift(drift)
	}
	err := validateWindowsManagedHooksTrustedDir(dir, managed.ObjectStateDirectory, "state root")
	var refused *managed.StandaloneContentDriftError
	if asked != 1 || !errors.As(err, &refused) || !errors.Is(err, drift) {
		t.Fatalf("asked=%d err=%v, want the standalone refusal joined with the drift", asked, err)
	}
}
