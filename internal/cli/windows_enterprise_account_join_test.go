// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-6:GAP-0344: the Windows account join keys read the identity spool
// the guardian writes, the standalone layout's hook-guardian-state folder
// the services are pinned to, whatever data_dir or the shell's environment
// say (an elevated shell has no pin; a per-user style data_dir under a
// profile named another folder).
func TestWindowsAccountJoinReadsTheGuardianSpoolOfTheLayout(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(layout.GuardianAuthDir, enterprisehooks.IdentitySpoolDirName)
	if !strings.HasSuffix(strings.ToLower(want), strings.ToLower(`\hook-guardian-state\identity`)) {
		t.Fatalf("standalone spool %s", want)
	}
	pins := windowsEnterpriseServicePins(layout)
	pins[managed.HookGuardianAuthorizationDirEnv] = layout.GuardianAuthDir
	for _, dataDir := range []string{layout.DataDir, `C:\Users\dcw-std1\.defenseclaw`} {
		for _, env := range []string{"", `C:\elsewhere`} {
			t.Setenv(managed.HookGuardianAuthorizationDirEnv, env)
			sources := windowsAccountJoinSources(&config.Config{DataDir: dataDir}, layout)
			if sources.SpoolDir != want {
				t.Errorf("data_dir %s, pin %q: spool %s, want %s", dataDir, env, sources.SpoolDir, want)
			}
			if guardian := enterprisehooks.IdentitySpoolDir(pins[managed.HookGuardianAuthorizationDirEnv]); guardian != sources.SpoolDir {
				t.Errorf("the guardian writes %s, account-keys reads %s", guardian, sources.SpoolDir)
			}
		}
	}
}

// rel-1-0-6:GAP-0277: the Windows status inputs ask the bundle store for the
// signing time of the confirmed bundle that carries next_not_after.
func TestWindowsAccountJoinSourcesAskTheConfirmedBundleForTheSigningTime(t *testing.T) {
	store := enterprisebundle.NewStore(t.TempDir(), t.TempDir())
	previousStore, previousSigned := bundleStore, windowsConfirmedAccountJoinSignedAt
	bundleStore = func() (*enterprisebundle.Store, error) { return store, nil }
	signed := time.Date(2026, 10, 25, 8, 30, 0, 0, time.UTC)
	var asked *enterprisebundle.Store
	windowsConfirmedAccountJoinSignedAt = func(s *enterprisebundle.Store, generation int, at time.Time) (time.Time, bool) {
		asked = s
		return signed, generation == 2
	}
	t.Cleanup(func() { bundleStore, windowsConfirmedAccountJoinSignedAt = previousStore, previousSigned })
	sources := windowsAccountJoinSources(&config.Config{}, managed.StandaloneLayout{LifecycleDir: t.TempDir()})
	if sources.SignedAt == nil {
		t.Fatal("the status inputs have no signing time")
	}
	if at, ok := sources.SignedAt(2, signed.Add(time.Hour)); !ok || !at.Equal(signed) || asked != store {
		t.Fatalf("signing time %v, %v from %p, want %v from %p", at, ok, asked, signed, store)
	}
}
