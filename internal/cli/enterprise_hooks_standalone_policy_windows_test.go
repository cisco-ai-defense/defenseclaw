// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// A Windows user whose connectors are all machine policy (Cursor, Codex,
// Claude) has no per-user manifest row, but can still add a user-level
// foreign hook; the guardian must clean it for every eligible profile, not
// only for users with rows.
func TestWindowsForeignCleanupCoversEligibleUsersWithoutRows(t *testing.T) {
	previousOptions, previousProfiles := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles
	previousCleanup, previousBlocks := enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsEligibleProfiles = previousOptions, previousProfiles
		enterpriseForeignHookCleanup, enterpriseForeignHookCollectBlocks = previousCleanup, previousBlocks
		enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	})
	enterpriseHookWindowsForeignCleanupState.last, enterpriseHookWindowsForeignCleanupState.fingerprint = time.Time{}, ""
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"cursor"}, true, nil
	}
	const alice, bob = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	enterpriseHookWindowsEligibleProfiles = func(context.Context) ([]enterprisehooks.TargetCredentials, error) {
		return []enterprisehooks.TargetCredentials{
			{UserHome: `C:\Users\alice`, UID: -1, GID: -1, SID: alice},
			{UserHome: `C:\Users\bob`, UID: -1, GID: -1, SID: bob},
		}, nil
	}
	var calls []string
	enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, name, dataDir string) (enterprisepolicy.CleanupResult, error) {
		calls = append(calls, target.SID+"|"+name+"|"+dataDir)
		return enterprisepolicy.CleanupResult{}, nil
	}
	var collected []string
	enterpriseForeignHookCollectBlocks = func(target enterprisehooks.TargetCredentials) ([]enterprisepolicy.BlockSummary, int, error) {
		collected = append(collected, target.SID)
		return nil, 0, nil
	}
	rows := []enterpriseHookReconcileRow{{OK: true, SID: bob, UserHome: `C:\Users\bob`, Connector: "cursor"}}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformFinish(context.Background(), &log, rows, time.Now())
	if strings.Join(calls, ",") != alice+`|cursor|C:\Users\alice\.defenseclaw` {
		t.Fatalf("cleanup must run for the eligible user without rows and skip the row's own connector: %v\n%s", calls, log.String())
	}
	if strings.Join(collected, ",") != bob+","+alice {
		t.Fatalf("block records must be collected for every user: %v", collected)
	}
}

// The guardian routes OpenCode rows by OpenCode's machine policy: the
// managed config under the trusted ProgramData, in force only while the
// trusted managed plugin is installed and named there.
func TestWindowsOpenCodeMachinePolicyCheckNamesTheManagedConfig(t *testing.T) {
	layout, _, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		t.Skipf("no standalone layout: %v", err)
	}
	path, inForce := windowsOpenCodeMachinePolicy()
	if dir := filepath.Join(programData, "opencode"); !strings.EqualFold(filepath.Dir(path), dir) {
		t.Fatalf("OpenCode policy path = %q, want one in %s", path, dir)
	}
	if _, err := os.Lstat(enterprisepolicy.OpenCodeManagedPluginPath(layout)); errors.Is(err, os.ErrNotExist) && inForce {
		t.Fatal("OpenCode machine policy reported in force without the managed plugin")
	}
}

// Every guardian reconcile re-checks the Claude Code version floor, even
// when the Go-owned policy fails, and only in the standalone profile.
func TestWindowsGuardianRechecksTheClaudeVersionFloor(t *testing.T) {
	previousOptions, previousFloor, previousWSL := enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsClaudeVersionFloor, enterpriseHookWindowsWSL
	t.Cleanup(func() {
		enterpriseHookWindowsGuardianOptions, enterpriseHookWindowsClaudeVersionFloor, enterpriseHookWindowsWSL = previousOptions, previousFloor, previousWSL
	})
	wslCalls := 0
	enterpriseHookWindowsWSL = func(enterprisepolicy.Options) (enterprisepolicy.State, error) {
		wslCalls++
		return enterprisepolicy.State{}, errors.New("registry denied")
	}
	standalone := false
	enterpriseHookWindowsGuardianOptions = func() (enterprisepolicy.Options, []string, bool, error) {
		return enterprisepolicy.Options{}, []string{"claudecode"}, standalone, nil
	}
	var calls [][]string
	enterpriseHookWindowsClaudeVersionFloor = func(_ enterprisepolicy.Options, connectors []string) (enterprisepolicy.State, error) {
		calls = append(calls, connectors)
		return enterprisepolicy.State{}, errors.New("lock timeout")
	}
	var log bytes.Buffer
	enterpriseHookStandalonePlatformPrepare(&log)
	if len(calls) != 0 || wslCalls != 0 || log.Len() != 0 {
		t.Fatalf("a Secure Client guardian must not touch the floor or the WSL policy: %v %d %q", calls, wslCalls, log.String())
	}
	standalone = true
	enterpriseHookStandalonePlatformPrepare(&log)
	if len(calls) != 1 || strings.Join(calls[0], ",") != "claudecode" {
		t.Fatalf("the floor must be re-checked every reconcile: %v", calls)
	}
	if !strings.Contains(log.String(), "Claude Code version floor: lock timeout") {
		t.Fatalf("a floor failure must be reported: %q", log.String())
	}
	if wslCalls != 1 || !strings.Contains(log.String(), "WSL agent sessions: registry denied") {
		t.Fatalf("the WSL policy must be reconciled every pass and its failure reported: %d %q", wslCalls, log.String())
	}
}
