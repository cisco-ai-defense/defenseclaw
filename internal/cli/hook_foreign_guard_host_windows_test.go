//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A user-created summary folder, with a file of any content or a folder at
// the summary name, is rejected by the real summary loader and must still
// leave the hook unchanged through the real directory check.
func TestHostForeignHookGuardIgnoresUserCreatedSummaryOnWindows(t *testing.T) {
	for _, plant := range []string{"file", "folder"} {
		runtimeDir := filepath.Join(t.TempDir(), "Cisco", "DefenseClaw-HookRuntime")
		summary := filepath.Join(runtimeDir, enterprisepolicy.PublicPolicyFileName)
		if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if plant == "file" {
			if err := os.WriteFile(summary, []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
		} else if err := os.Mkdir(summary, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := enterprisepolicy.LoadPublicPolicy(summary); err == nil || errors.Is(err, enterprisepolicy.ErrNoPublicPolicy) {
			t.Fatalf("%s: the real loader must reject a user-created summary, got %v", plant, err)
		}
		if err := platformHookForeignGuardSummaryDirTrusted(runtimeDir); err == nil {
			t.Fatalf("%s: a user-created summary folder must not be trusted", plant)
		}
		previous, previousRegistered := hookForeignGuardSummaryPath, hookForeignGuardStandaloneRegistered
		hookForeignGuardSummaryPath = func() (string, bool) { return summary, true }
		// A Secure Client or unmanaged host: no standalone registration
		// (pinned, since the host running the test may carry a real one).
		hookForeignGuardStandaloneRegistered = func() bool { return false }
		for _, managedEnterprise := range []bool{true, false} {
			opts := hookexec.Options{Connector: "codex", ManagedEnterprise: managedEnterprise, Stdin: strings.NewReader("{}")}
			applyHostEnterpriseForeignHookGuard(&opts)
			if opts.ManagedEnterprise != managedEnterprise || opts.ManagedRuntimeFailure != "" {
				hookForeignGuardSummaryPath, hookForeignGuardStandaloneRegistered = previous, previousRegistered
				t.Fatalf("%s managed=%v: a user-created summary must not change the hook: %+v", plant, managedEnterprise, opts)
			}
		}
		// The same untrusted directory on a host that carries the
		// registration is a standalone host whose directory drifted: the
		// real loader rejects the summary and the hook fails closed.
		hookForeignGuardStandaloneRegistered = func() bool { return true }
		opts := hookexec.Options{Connector: "codex", Stdin: strings.NewReader("{}")}
		applyHostEnterpriseForeignHookGuard(&opts)
		hookForeignGuardSummaryPath, hookForeignGuardStandaloneRegistered = previous, previousRegistered
		if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "enterprise_machine_policy_summary_untrusted" {
			t.Fatalf("%s: a registered standalone host must fail closed: %+v", plant, opts)
		}
	}

	// The directory check also rejects an absent directory and a file in its
	// place.
	root := t.TempDir()
	if err := platformHookForeignGuardSummaryDirTrusted(filepath.Join(root, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("absent directory: %v", err)
	}
	file := filepath.Join(root, "DefenseClaw-HookRuntime")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := platformHookForeignGuardSummaryDirTrusted(file); err == nil {
		t.Fatal("a file in place of the summary directory must not be trusted")
	}
}

// The registration the gate reads is the per-user gateway guard's
// administrator-only standalone marker.
func TestHostForeignHookGuardRegistrationIsTheStandaloneMarker(t *testing.T) {
	previous := managedHostWindowsStandalone
	t.Cleanup(func() { managedHostWindowsStandalone = previous })
	for _, registered := range []bool{true, false} {
		managedHostWindowsStandalone = func() (string, bool) { return `HKLM\` + WindowsEnterpriseMarkerKey, registered }
		if got := hookForeignGuardStandaloneRegistered(); got != registered {
			t.Fatalf("registration = %v, want %v", got, registered)
		}
	}
}
