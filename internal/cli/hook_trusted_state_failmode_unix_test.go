// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Owner decision 2026-10-20: the standalone `--enterprise-managed` hook takes
// its fail mode from the root-owned runtime descriptor only. A connector the
// administrator's config resolves open (OpenHookConnectors) fails open and
// drops the strict-availability pin; every other connector, and the
// inherited DEFENSECLAW_FAIL_MODE, stays closed and strict.
func TestStandaloneHookRuntimeTakesTheDescriptorFailMode(t *testing.T) {
	descriptor := testDescriptor()
	descriptor.OpenHookConnectors = []string{"codex"}
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return descriptor, nil },
		noMarkers, "/nonexistent-secure-client")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "")
	for _, tc := range []struct {
		connector string
		want      string
		strict    bool
	}{
		{"codex", "open", false},
		{"claudecode", "closed", true},
	} {
		if prepareEnterpriseManagedHookRuntime(tc.connector) {
			t.Fatal("a present descriptor is never a no-op")
		}
		opts := buildHookOptionsForRuntime(tc.connector, "PreToolUse", "", "", true)
		if opts.ManagedRuntimeFailure != "" || !opts.ManagedStandalone {
			t.Fatalf("%s: unexpected runtime state %+v", tc.connector, opts)
		}
		if opts.FailMode != tc.want || opts.StrictAvailability != tc.strict {
			t.Fatalf("%s: fail mode %q strict %v, want %q strict %v", tc.connector, opts.FailMode, opts.StrictAvailability, tc.want, tc.strict)
		}
	}
	// Strict availability from the environment still closes an open hook.
	t.Setenv("DEFENSECLAW_STRICT_AVAILABILITY", "1")
	if prepareEnterpriseManagedHookRuntime("codex") {
		t.Fatal("a present descriptor is never a no-op")
	}
	if opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true); !opts.StrictAvailability {
		t.Fatalf("DEFENSECLAW_STRICT_AVAILABILITY=1 did not force strict availability: %+v", opts)
	}
}
