// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// GAP-1034: only the resolver's "no runtime selected" result is pending; the
// unregistered SID, a drift, a boundary and a clean result claim nothing; and
// readOwnStatus puts the blocked rows into the answer it returns.
func TestOwnStatusPendingForReadsTheHooksOwnPendingResult(t *testing.T) {
	previous := ownStatusRuntimeResolve
	t.Cleanup(func() { ownStatusRuntimeResolve = previous })
	pending := fmt.Errorf("selector: %w", enterprisehooks.ErrWindowsManagedRuntimeGenerationPending)
	// The caller's profile folder; the account was enrolled before for Claude Code only.
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	enrollMarker(t, home, "claudecode")
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"pending", pending, true},
		{"pending tagged drift", fmt.Errorf("%w: %w", enterprisehooks.ErrWindowsManagedRuntimeDrift, pending), true},
		{"enrolled", nil, false},
		{"unregistered", fmt.Errorf("%w: sid", enterprisehooks.ErrWindowsManagedSIDUnregistered), false},
		{"drift", fmt.Errorf("%w: acl", enterprisehooks.ErrWindowsManagedRuntimeDrift), false},
		{"boundary", fmt.Errorf("%w: link", enterprisehooks.ErrWindowsManagedRuntimeBoundary), false},
		{"unreadable", errors.New("access denied"), false},
	} {
		ownStatusRuntimeResolve = func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
			return enterprisehooks.WindowsManagedHookRuntime{}, tc.err
		}
		if got := ownStatusPendingFor("claudecode"); got != tc.want {
			t.Errorf("%s: pending = %t, want %t", tc.name, got, tc.want)
		}
	}

	// Pending, but never enrolled for this connector (no marker): no claim (GAP-1010).
	ownStatusRuntimeResolve = func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{}, pending
	}
	if ownStatusPendingFor("codex") {
		t.Error("a never-enrolled connector was called blocked")
	}
	if !ownStatusPendingFor("claudecode") {
		t.Error("an enrolled connector that is pending was not called blocked")
	}

	previousFetch := ownStatusPipeFetch
	t.Cleanup(func() { ownStatusPipeFetch = previousFetch })
	ownStatusPipeFetch = func(context.Context) ([]byte, error) {
		return []byte(`{"claude_code":{"protected":true},"cowork":{"protected":true,"state":"protected"},` +
			`"connectors":{"claudecode":{"protected":true,"state":"protected"}}}`), nil
	}
	ownStatusRuntimeResolve = func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{}, pending
	}
	body, err := readOwnStatus(context.Background())
	if err != nil || !strings.Contains(string(body), `"state":"blocked"`) || strings.Contains(string(body), `"state":"protected"`) {
		t.Fatalf("readOwnStatus = %s, %v; want blocked rows", body, err)
	}
	ownStatusRuntimeResolve = func(string, string) (enterprisehooks.WindowsManagedHookRuntime, error) {
		return enterprisehooks.WindowsManagedHookRuntime{}, nil
	}
	body, err = readOwnStatus(context.Background())
	if err != nil || strings.Contains(string(body), "blocked") {
		t.Fatalf("an enrolled account's answer changed: %s, %v", body, err)
	}
}
