// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWriteEnterpriseHookGuardianState(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook guardian persistence is unsupported on native Windows; lifecycle gate coverage remains active")
	}
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	dir := t.TempDir()
	authorizationDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	rows := []enterpriseHookReconcileRow{
		{User: "alice", Connector: "codex", OK: true},
		{User: "bob", Connector: "claudecode", OK: false, Error: "hook config file missing"},
	}
	if err := writeEnterpriseHookGuardianState(dir, "/etc/defenseclaw/hook-guardian/targets.yaml", rows, 1); err != nil {
		t.Fatalf("writeEnterpriseHookGuardianState: %v", err)
	}
	path := filepath.Join(dir, hookGuardianStateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state enterpriseHookGuardianState
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if state.OK {
		t.Fatalf("state.OK = %v, want false", state.OK)
	}
	if state.TargetCount != 2 || state.SuccessCount != 1 || state.FailureCount != 1 {
		t.Fatalf("counts = target %d success %d failure %d, want 2/1/1", state.TargetCount, state.SuccessCount, state.FailureCount)
	}
	if len(state.Results) != 2 || state.Results[1].Error == "" {
		t.Fatalf("results = %+v, want persisted rows", state.Results)
	}
	if info, statErr := os.Stat(authorizationDir); statErr != nil {
		t.Fatalf("stat authorization dir: %v", statErr)
	} else if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("authorization dir mode = %o, want 750", got)
	}
	authorizationPath := filepath.Join(authorizationDir, hookGuardianAuthorizationFile)
	if info, statErr := os.Stat(authorizationPath); statErr != nil {
		t.Fatalf("stat authorization file: %v", statErr)
	} else if got := info.Mode().Perm(); got != 0o640 {
		t.Fatalf("authorization file mode = %o, want 640", got)
	}
}

func TestEnterpriseHookGuardianFailureIssuesExposeTargetCause(t *testing.T) {
	state := enterpriseHookGuardianState{
		FailureCount: 2,
		Results: []enterpriseHookReconcileRow{
			{
				User:      "alice",
				SID:       "S-1-5-21-111-222-333-1001",
				Connector: "claudecode",
				OK:        false,
				Error:     "publish managed policy: access denied",
			},
			{
				User:      "bob",
				Connector: "codex",
				OK:        false,
			},
			{
				User:      "carol",
				Connector: "codex",
				OK:        true,
			},
		},
	}

	issues := enterpriseHookGuardianFailureIssues(state)
	want := []string{
		"last guardian reconcile failed for claudecode@S-1-5-21-111-222-333-1001: publish managed policy: access denied",
		"last guardian reconcile failed for codex@bob: no target error was recorded",
	}
	if !reflect.DeepEqual(issues, want) {
		t.Fatalf("issues = %#v, want %#v", issues, want)
	}
}

func TestCompareEnterpriseHookGuardianRecordsRejectsStaleOrFutureReconcile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		updatedAt string
		want      string
	}{
		{
			name:      "stale",
			updatedAt: time.Now().Add(-managed.HookGuardianMaxAge - time.Minute).UTC().Format(time.RFC3339),
			want:      "not fresh",
		},
		{
			name:      "future",
			updatedAt: time.Now().Add(managed.HookGuardianFutureSkew + time.Minute).UTC().Format(time.RFC3339),
			want:      "not fresh",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := enterpriseHookGuardianState{Version: 1, UpdatedAt: tc.updatedAt, OK: true}
			authorization := enterpriseHookGuardianAuthorization{Version: 1, UpdatedAt: tc.updatedAt, OK: true}
			issues := compareEnterpriseHookGuardianRecords(state, authorization, "")
			if !strings.Contains(strings.Join(issues, "\n"), tc.want) {
				t.Fatalf("issues = %v, want %q", issues, tc.want)
			}
		})
	}
}

func TestWriteEnterpriseHookGuardianStateRefusesSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook guardian symlink writer is unreachable on native Windows; lifecycle gate coverage remains active")
	}
	stubEnterpriseHookAuthorizationTrustForTempDir(t)
	dir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, t.TempDir())
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, hookGuardianStateFile)); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	err := writeEnterpriseHookGuardianState(dir, "manifest.yaml", nil, 0)
	if err == nil || !strings.Contains(err.Error(), "refusing to write through symlink") {
		t.Fatalf("writeEnterpriseHookGuardianState error = %v, want symlink refusal", err)
	}
}

func stubEnterpriseHookAuthorizationTrustForTempDir(t *testing.T) {
	t.Helper()
	originalDirTrust := enterpriseHookAuthorizationDirTrustCheck
	originalFileTrust := enterpriseHookAuthorizationFileTrustCheck
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		enterpriseHookAuthorizationDirTrustCheck = originalDirTrust
		enterpriseHookAuthorizationFileTrustCheck = originalFileTrust
	})
}

func TestWriteEnterpriseHookGuardianStatePreservesProtectedTargets(t *testing.T) {
	originalOwnershipSetter := enterpriseHookAuthorizationOwnershipSetter
	originalDirTrust := enterpriseHookAuthorizationDirTrustCheck
	originalFileTrust := enterpriseHookAuthorizationFileTrustCheck
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter = originalOwnershipSetter
		enterpriseHookAuthorizationDirTrustCheck = originalDirTrust
		enterpriseHookAuthorizationFileTrustCheck = originalFileTrust
	})
	dir := t.TempDir()
	authorizationDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state dir: %v", err)
	}
	successRows := []enterpriseHookReconcileRow{{
		User:      "alice",
		UserHome:  "/home/alice",
		Connector: "codex",
		OK:        true,
		Result: &enterprisehooks.InstallResult{
			Connector:                  "codex",
			UserHome:                   "/home/alice",
			HookContractLockUpdatedAt:  "2026-08-16T12:34:56.987654321Z",
			HookContractEntryUpdatedAt: "2026-08-16T12:34:55.123456789Z",
		},
	}}
	if err := writeEnterpriseHookGuardianState(dir, "manifest.yaml", successRows, 0); err != nil {
		t.Fatalf("write initial state: %v", err)
	}
	protected, err := previousEnterpriseHookSuccess(dir, "alice", "/home/alice", "", "codex")
	if err != nil {
		t.Fatalf("previousEnterpriseHookSuccess: %v", err)
	}
	if !protected {
		t.Fatal("previousEnterpriseHookSuccess = false after successful state")
	}
	protection, err := previousEnterpriseHookProtection(
		dir,
		"alice",
		"/home/alice",
		"",
		"codex",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !protection.PreviouslyProtected ||
		protection.HookContractLockUpdatedAt != "2026-08-16T12:34:56.987654321Z" ||
		protection.HookContractEntryUpdatedAt != "2026-08-16T12:34:55.123456789Z" {
		t.Fatalf("protected recovery evidence = %+v", protection)
	}

	failureRows := []enterpriseHookReconcileRow{{
		User:      "alice",
		UserHome:  "/home/alice",
		Connector: "codex",
		OK:        false,
		Error:     "temporary tamper failure",
	}}
	if err := writeEnterpriseHookGuardianState(dir, "manifest.yaml", failureRows, 1); err != nil {
		t.Fatalf("write failure state: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(authorizationDir, hookGuardianAuthorizationFile))
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	var state enterpriseHookGuardianAuthorization
	if err := json.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal state: %v", err)
	}
	if len(state.ProtectedTargets) != 1 || state.ProtectedTargets[0].Connector != "codex" {
		t.Fatalf("ProtectedTargets = %+v, want preserved codex target", state.ProtectedTargets)
	}
	protected, err = previousEnterpriseHookSuccess(dir, "alice", "/home/alice", "", "codex")
	if err != nil {
		t.Fatalf("previousEnterpriseHookSuccess after failure: %v", err)
	}
	if !protected {
		t.Fatal("previousEnterpriseHookSuccess = false after failed state overwrote results")
	}
}

func TestPreviousEnterpriseHookSuccessIgnoresServiceWritableStatus(t *testing.T) {
	dataDir := t.TempDir()
	authorizationDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	forged := enterpriseHookGuardianState{ProtectedTargets: []enterpriseHookReconcileRow{{
		User: "alice", UserHome: "/home/alice", Connector: "codex", OK: true,
	}}}
	data, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, hookGuardianStateFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	protected, err := previousEnterpriseHookSuccess(dataDir, "alice", "/home/alice", "", "codex")
	if err != nil {
		t.Fatalf("previousEnterpriseHookSuccess: %v", err)
	}
	if protected {
		t.Fatal("service-writable status file granted privileged repair authorization")
	}
}

func TestEnterpriseHookRowMatchRejectsMismatchedAuthoritativeSID(t *testing.T) {
	row := enterpriseHookReconcileRow{
		User:      "alice",
		UserHome:  `C:\Users\alice`,
		SID:       "S-1-5-21-111-222-333-1001",
		Connector: "codex",
		OK:        true,
	}
	if enterpriseHookRowMatches(
		row,
		"alice",
		filepath.Clean(`C:\Users\alice`),
		"S-1-5-21-111-222-333-1002",
		"codex",
	) {
		t.Fatal("mismatched SIDs fell back to matching user/home authorization")
	}
}

func TestCompareEnterpriseHookGuardianRecordsRejectsExtraStaleProtectedTarget(t *testing.T) {
	updatedAt := time.Now().UTC().Format(time.RFC3339)
	alice := enterpriseHookReconcileRow{
		User:      "alice",
		UserHome:  `C:\Users\alice`,
		SID:       "S-1-5-21-111-222-333-1001",
		Connector: "codex",
		OK:        true,
	}
	bob := enterpriseHookReconcileRow{
		User:      "bob",
		UserHome:  `C:\Users\bob`,
		SID:       "S-1-5-21-111-222-333-1002",
		Connector: "codex",
		OK:        true,
	}
	state := enterpriseHookGuardianState{
		Version:      1,
		UpdatedAt:    updatedAt,
		OK:           true,
		TargetCount:  1,
		SuccessCount: 1,
		Results:      []enterpriseHookReconcileRow{alice},
	}
	authorization := enterpriseHookGuardianAuthorization{
		Version:          1,
		UpdatedAt:        updatedAt,
		OK:               true,
		TargetCount:      1,
		SuccessCount:     1,
		ProtectedTargets: []enterpriseHookReconcileRow{alice, bob},
	}
	issues := compareEnterpriseHookGuardianRecords(state, authorization, "")
	if got := strings.Join(issues, "\n"); !strings.Contains(got, "extra or stale target codex@"+bob.SID) {
		t.Fatalf("issues = %v, want stale protected-target rejection", issues)
	}
}

func TestEnterpriseHookProtectedTargetSetsRejectRemovedOrDisabledStaleTarget(t *testing.T) {
	enabled := enterpriseHookReconcileRow{
		SID:       "S-1-5-21-111-222-333-1001",
		Connector: "codex",
		OK:        true,
	}
	removedOrDisabled := enterpriseHookReconcileRow{
		SID:       "S-1-5-21-111-222-333-1002",
		Connector: "claudecode",
		OK:        true,
	}
	issues := compareEnterpriseHookProtectedTargetSets(
		[]enterpriseHookReconcileRow{enabled},
		[]enterpriseHookReconcileRow{enabled, removedOrDisabled},
	)
	if got := strings.Join(issues, "\n"); !strings.Contains(got, "extra or stale target claudecode@"+removedOrDisabled.SID) {
		t.Fatalf("issues = %v, want removed/disabled target rejection", issues)
	}
}

func TestWriteEnterpriseHookGuardianStateRevokesRemovedManifestTarget(t *testing.T) {
	originalOwnershipSetter := enterpriseHookAuthorizationOwnershipSetter
	originalDirTrust := enterpriseHookAuthorizationDirTrustCheck
	originalFileTrust := enterpriseHookAuthorizationFileTrustCheck
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
	enterpriseHookAuthorizationDirTrustCheck = func(string) error { return nil }
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() {
		enterpriseHookAuthorizationOwnershipSetter = originalOwnershipSetter
		enterpriseHookAuthorizationDirTrustCheck = originalDirTrust
		enterpriseHookAuthorizationFileTrustCheck = originalFileTrust
	})

	dataDir := t.TempDir()
	authorizationDir := t.TempDir()
	t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
	rows := []enterpriseHookReconcileRow{{
		User:      "alice",
		UserHome:  "/home/alice",
		Connector: "codex",
		OK:        true,
	}}
	if err := writeEnterpriseHookGuardianState(dataDir, "manifest.yaml", rows, 0); err != nil {
		t.Fatalf("write initial authorization: %v", err)
	}
	if err := writeEnterpriseHookGuardianState(dataDir, "manifest.yaml", nil, 0); err != nil {
		t.Fatalf("write authorization after manifest removal: %v", err)
	}

	state, exists, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if err != nil {
		t.Fatalf("load authorization: %v", err)
	}
	if !exists {
		t.Fatal("authorization ledger is missing")
	}
	if len(state.ProtectedTargets) != 0 || state.TargetCount != 0 || state.SuccessCount != 0 || !state.OK {
		t.Fatalf("authorization after removal = %+v, want empty healthy ledger", state)
	}
	protected, err := previousEnterpriseHookSuccess(dataDir, "alice", "/home/alice", "", "codex")
	if err != nil {
		t.Fatalf("previousEnterpriseHookSuccess: %v", err)
	}
	if protected {
		t.Fatal("removed manifest target retained privileged repair authorization")
	}
}

func TestEnterpriseHookGuardianStateRejectsSparseOversizedInput(t *testing.T) {
	originalCfg := cfg
	originalTrust := enterpriseHookGuardianStateFileTrustCheck
	trustChecked := false
	cfg = &config.Config{DeploymentMode: "managed_enterprise"}
	enterpriseHookGuardianStateFileTrustCheck = func(string) error {
		trustChecked = true
		return nil
	}
	t.Cleanup(func() {
		cfg = originalCfg
		enterpriseHookGuardianStateFileTrustCheck = originalTrust
	})

	dataDir := t.TempDir()
	path := filepath.Join(dataDir, hookGuardianStateFile)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(enterpriseHookGuardianStateMaxBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, exists, err := loadEnterpriseHookGuardianState(dataDir)
	if !exists || err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized state exists=%v error=%v, want bounded refusal", exists, err)
	}
	if !trustChecked {
		t.Fatal("guardian state was read before managed trust validation")
	}
}

func TestEnterpriseHookAuthorizationRejectsSparseOversizedInput(t *testing.T) {
	originalTrust := enterpriseHookAuthorizationFileTrustCheck
	enterpriseHookAuthorizationFileTrustCheck = func(string) error { return nil }
	t.Cleanup(func() { enterpriseHookAuthorizationFileTrustCheck = originalTrust })

	dataDir := t.TempDir()
	path := managed.HookGuardianAuthorizationPath(dataDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(enterpriseHookGuardianAuthorizationMaxBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	_, exists, err := loadEnterpriseHookGuardianAuthorization(dataDir)
	if !exists || err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized authorization exists=%v error=%v, want bounded refusal", exists, err)
	}
}

func TestEnterpriseHookScopedTokenUsesManagedDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enterprise hook scoped tokens are unsupported on native Windows; lifecycle gate coverage remains active")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod managed data dir: %v", err)
	}
	token, err := enterpriseHookScopedToken(dir, "codex")
	if err != nil {
		t.Fatalf("enterpriseHookScopedToken: %v", err)
	}
	if token == "" || token == "gateway-token" {
		t.Fatalf("token = %q, want generated scoped token", token)
	}
	path, err := connector.HookAPITokenFilePath(dir, "codex")
	if err != nil {
		t.Fatalf("HookAPITokenFilePath: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scoped token: %v", err)
	}
	if strings.TrimSpace(string(data)) != token {
		t.Fatalf("token file = %q, want generated token", strings.TrimSpace(string(data)))
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat scoped token: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("scoped token mode = %o, want 600", got)
	}
}

func TestEnterpriseHookScopedOTLPTokenUsesManagedDataDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("enterprise OTLP scoped tokens are unsupported on native Windows; lifecycle gate coverage remains active")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod managed data dir: %v", err)
	}
	token, err := enterpriseHookScopedOTLPToken(dir, "codex")
	if err != nil {
		t.Fatalf("enterpriseHookScopedOTLPToken: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64", len(token))
	}
	path, err := connector.OTLPPathTokenFilePath(dir, connector.OTLPScopeCodex)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scoped OTLP token: %v", err)
	}
	if strings.TrimSpace(string(data)) != token {
		t.Fatalf("token file does not contain the returned token")
	}
	if info, err := os.Stat(path); err != nil {
		t.Fatalf("stat scoped OTLP token: %v", err)
	} else if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("scoped OTLP token mode = %o, want 600", got)
	}
	if token, err := enterpriseHookScopedOTLPToken(dir, "cursor"); err != nil || token != "" {
		t.Fatalf("non-OTLP connector token = %q, %v; want empty", token, err)
	}
}

func TestEnterpriseHookWatchEventRelevantIgnoresLockHousekeeping(t *testing.T) {
	for _, tc := range []struct {
		name  string
		event fsnotify.Event
		want  bool
	}{
		{name: "settings write", event: fsnotify.Event{Name: "/home/alice/.claude/settings.json", Op: fsnotify.Write}, want: true},
		{name: "hook chmod", event: fsnotify.Event{Name: "/home/alice/.defenseclaw/hooks/codex-hook.sh", Op: fsnotify.Chmod}, want: true},
		{name: "settings lock create", event: fsnotify.Event{Name: "/home/alice/.claude/settings.json.lock", Op: fsnotify.Create}, want: false},
		{name: "settings lock remove", event: fsnotify.Event{Name: "/home/alice/.claude/settings.json.lock", Op: fsnotify.Remove}, want: false},
		{name: "untracked op", event: fsnotify.Event{Name: "/home/alice/.claude/settings.json"}, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := enterpriseHookWatchEventRelevant(tc.event); got != tc.want {
				t.Fatalf("enterpriseHookWatchEventRelevant(%+v) = %v, want %v", tc.event, got, tc.want)
			}
		})
	}
}

func TestEnterpriseHookWatchOwnedEventActionable(t *testing.T) {
	exclusivePath := filepath.FromSlash("/home/alice/.defenseclaw/hooks/codex-hook.sh")
	sharedPath := filepath.FromSlash("/home/alice/.codex/config.toml")
	unownedPath := filepath.FromSlash("/home/alice/.codex/history.jsonl")
	exclusiveOwned := map[string]struct{}{exclusivePath: {}}
	sharedOwned := map[string]struct{}{sharedPath: {}}

	for _, tc := range []struct {
		name      string
		event     fsnotify.Event
		exclusive map[string]struct{}
		shared    map[string]struct{}
		want      bool
	}{
		{
			name:      "exclusive write remains actionable",
			event:     fsnotify.Event{Name: exclusivePath, Op: fsnotify.Write},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      true,
		},
		{
			name:      "shared create from rename into place is actionable",
			event:     fsnotify.Event{Name: sharedPath, Op: fsnotify.Create},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      true,
		},
		{
			name:      "shared remove remains actionable",
			event:     fsnotify.Event{Name: sharedPath, Op: fsnotify.Remove},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      true,
		},
		{
			name:      "shared rename remains actionable",
			event:     fsnotify.Event{Name: sharedPath, Op: fsnotify.Rename},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      true,
		},
		{
			name:      "shared write self-noise remains suppressed",
			event:     fsnotify.Event{Name: sharedPath, Op: fsnotify.Write},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      false,
		},
		{
			name:      "shared chmod self-noise remains suppressed",
			event:     fsnotify.Event{Name: sharedPath, Op: fsnotify.Chmod},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      false,
		},
		{
			name:      "unowned path remains suppressed",
			event:     fsnotify.Event{Name: unownedPath, Op: fsnotify.Create},
			exclusive: exclusiveOwned,
			shared:    sharedOwned,
			want:      false,
		},
		{
			name:  "empty ownership maps preserve pre-startup fallback",
			event: fsnotify.Event{Name: unownedPath, Op: fsnotify.Write},
			want:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := enterpriseHookWatchOwnedEventActionable(tc.event, tc.exclusive, tc.shared); got != tc.want {
				t.Fatalf("enterpriseHookWatchOwnedEventActionable(%+v) = %v, want %v", tc.event, got, tc.want)
			}
		})
	}
}

func TestEnterpriseHookWatchEventInSettleWindow(t *testing.T) {
	base := time.Date(2026, 7, 17, 15, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name        string
		now         time.Time
		settleUntil time.Time
		op          fsnotify.Op
		want        bool
	}{
		{
			// Zero settleUntil means "never reconciled yet" — the
			// watcher must not suppress the very first fsnotify event
			// after boot; otherwise startup-time tamper is missed.
			name:        "never reconciled: not suppressed",
			now:         base,
			settleUntil: time.Time{},
			op:          fsnotify.Write,
			want:        false,
		},
		{
			// Chmod event well inside the post-reconcile settle
			// window: this is the guardian's own chmod tail from
			// hardenInstallFootprint. Suppress to break the
			// self-trigger loop.
			name:        "chmod inside window: suppressed",
			now:         base.Add(500 * time.Millisecond),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Chmod,
			want:        true,
		},
		{
			// Write event inside window — same rationale as Chmod;
			// reconcile writes hook scripts and .token files, so
			// their post-reconcile tail must be suppressed too.
			name:        "write inside window: suppressed",
			now:         base.Add(500 * time.Millisecond),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Write,
			want:        true,
		},
		{
			// Right at the boundary — Before() is strictly less-than,
			// so an event at exactly settleUntil is NOT suppressed.
			name:        "chmod at boundary: not suppressed",
			now:         base.Add(2 * time.Second),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Chmod,
			want:        false,
		},
		{
			// Event after the window closed.
			name:        "chmod outside window: not suppressed",
			now:         base.Add(3 * time.Second),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Chmod,
			want:        false,
		},
		{
			// Remove inside the window may be a user atomic
			// replacement of a protected file. Reconcile instead of
			// deciding from path existence, which is identical for a
			// guardian rename tail and an attacker rename-over.
			name:        "remove inside window: not suppressed",
			now:         base.Add(500 * time.Millisecond),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Remove,
			want:        false,
		},
		{
			// Remove OUTSIDE the settle window: real user tamper. The
			// guardian's atomic-write tail lives inside the window
			// (typically ~ms); anything after the window is a user
			// action and must trigger reconcile.
			name:        "remove outside window: not suppressed",
			now:         base.Add(3 * time.Second),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Remove,
			want:        false,
		},
		{
			// Rename inside the window may be an atomic
			// replacement, so it must arm reconcile.
			name:        "rename inside window: not suppressed",
			now:         base.Add(500 * time.Millisecond),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Rename,
			want:        false,
		},
		{
			// Create can be the visible part of replacing a missing
			// protected path and should not be swallowed by the
			// settle window.
			name:        "create inside window: not suppressed",
			now:         base.Add(500 * time.Millisecond),
			settleUntil: base.Add(2 * time.Second),
			op:          fsnotify.Create,
			want:        false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := enterpriseHookWatchEventInSettleWindow(tc.now, tc.settleUntil, tc.op)
			if got != tc.want {
				t.Fatalf("enterpriseHookWatchEventInSettleWindow(now=%v settleUntil=%v op=%v) = %v, want %v", tc.now, tc.settleUntil, tc.op, got, tc.want)
			}
		})
	}
}

func TestEnterpriseHookWatchNextRepairRetryDelayIsBounded(t *testing.T) {
	delay := time.Duration(0)
	want := []time.Duration{
		time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		15 * time.Second,
		15 * time.Second,
	}
	for i, expected := range want {
		delay = enterpriseHookWatchNextRepairRetryDelay(delay)
		if delay != expected {
			t.Fatalf("retry delay %d = %s, want %s", i, delay, expected)
		}
	}
}

func TestEnterpriseHookReconcileRowsHash(t *testing.T) {
	rowsA := []enterpriseHookReconcileRow{
		{User: "alice", UserHome: "/Users/alice", Connector: "codex", OK: true},
		{User: "bob", UserHome: "/Users/bob", Connector: "cursor", OK: true},
	}
	rowsB := []enterpriseHookReconcileRow{
		{User: "bob", UserHome: "/Users/bob", Connector: "cursor", OK: true},
		{User: "alice", UserHome: "/Users/alice", Connector: "codex", OK: true},
	}
	rowsC := []enterpriseHookReconcileRow{
		{User: "alice", UserHome: "/Users/alice", Connector: "codex", OK: false, Error: "boom"},
		{User: "bob", UserHome: "/Users/bob", Connector: "cursor", OK: true},
	}
	rowsD := []enterpriseHookReconcileRow{
		{User: "alice", UserHome: "/Users/alice", Connector: "codex", OK: true},
		{User: "bob", UserHome: "/Users/bob", Connector: "cursor", OK: true},
		{User: "charlie", UserHome: "/Users/charlie", Connector: "claudecode", OK: true},
	}

	// Row order must not matter — the watcher iterates in whatever
	// order the manifest resolves, but a "nothing changed" hash must
	// still match after a benign reorder.
	if h1, h2 := enterpriseHookReconcileRowsHash(rowsA), enterpriseHookReconcileRowsHash(rowsB); h1 != h2 {
		t.Fatalf("row-order should not affect hash: A=%s B=%s", h1, h2)
	}
	// Same identities but one now failed → hash must differ so the
	// watch loop treats it as a change (operator needs to see it).
	if h1, h2 := enterpriseHookReconcileRowsHash(rowsA), enterpriseHookReconcileRowsHash(rowsC); h1 == h2 {
		t.Fatalf("outcome change (OK true→false) must flip the hash, both = %s", h1)
	}
	// Adding a new target must flip the hash.
	if h1, h2 := enterpriseHookReconcileRowsHash(rowsA), enterpriseHookReconcileRowsHash(rowsD); h1 == h2 {
		t.Fatalf("adding a target must flip the hash, both = %s", h1)
	}
	// Empty input has a stable, non-empty representative — callers
	// use hash equality to detect "no change", and the boot-time
	// zero-value ("") must not collide with an actual empty run.
	if got := enterpriseHookReconcileRowsHash(nil); got == "" {
		t.Fatalf("empty rows must have a non-empty hash, got %q", got)
	}
}

func TestEnterpriseHooksReconcileManagedRejectsUntrustedManifest(t *testing.T) {
	dir := t.TempDir()
	manifest := filepath.Join(dir, "targets.yaml")
	if err := os.WriteFile(manifest, []byte("version: 1\ntargets: []\n"), 0o666); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.Chmod(manifest, 0o666); err != nil {
		t.Fatalf("chmod manifest: %v", err)
	}

	origCfg := cfg
	origManifest := enterpriseHookManifest
	origJSON := enterpriseHookJSON
	origAPIAddr := enterpriseHookAPIAddr
	origProxyAddr := enterpriseHookProxyAddr
	origMutationPreflight := enterpriseHooksMutationIdentityPreflight
	t.Cleanup(func() {
		cfg = origCfg
		enterpriseHookManifest = origManifest
		enterpriseHookJSON = origJSON
		enterpriseHookAPIAddr = origAPIAddr
		enterpriseHookProxyAddr = origProxyAddr
		enterpriseHooksMutationIdentityPreflight = origMutationPreflight
	})

	cfg = &config.Config{DataDir: dir, DeploymentMode: "managed_enterprise"}
	cfg.Gateway.Token = "tok"
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	enterpriseHookManifest = manifest
	enterpriseHookJSON = false
	enterpriseHookAPIAddr = ""
	enterpriseHookProxyAddr = ""
	// This unit isolates manifest trust. Production intentionally performs
	// the LocalSystem mutation gate first, before reading any manifest bytes.
	enterpriseHooksMutationIdentityPreflight = func() error { return nil }

	cmd := &cobra.Command{}
	err := runEnterpriseHooksReconcile(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "manifest trust check failed") {
		t.Fatalf("runEnterpriseHooksReconcile error = %v, want trust check failure", err)
	}
}

func TestEnterpriseHookManagedRuntimeRejectsUserOwnedDataDir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root-owned temp dirs are valid managed runtime dirs")
	}
	origCfg := cfg
	t.Cleanup(func() {
		cfg = origCfg
	})

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod data dir: %v", err)
	}
	cfg = &config.Config{DataDir: dir, DeploymentMode: "managed_enterprise"}

	err := validateEnterpriseHookManagedRuntime()
	if err == nil || !strings.Contains(err.Error(), "data_dir trust check failed") {
		t.Fatalf("validateEnterpriseHookManagedRuntime error = %v, want data_dir trust check failure", err)
	}
}

func TestEnterpriseHooksUninstallAcceptsSIDWithoutDeletedProfile(t *testing.T) {
	originalConnector := enterpriseHookConnector
	originalUser := enterpriseHookUser
	originalHome := enterpriseHookUserHome
	originalSID := enterpriseHookSID
	originalDataDir := enterpriseHookDataDir
	originalJSON := enterpriseHookJSON
	originalRemove := enterpriseHooksRemoveManagedPolicy
	t.Cleanup(func() {
		enterpriseHookConnector = originalConnector
		enterpriseHookUser = originalUser
		enterpriseHookUserHome = originalHome
		enterpriseHookSID = originalSID
		enterpriseHookDataDir = originalDataDir
		enterpriseHookJSON = originalJSON
		enterpriseHooksRemoveManagedPolicy = originalRemove
	})

	enterpriseHookConnector = "claudecode"
	enterpriseHookUser = ""
	enterpriseHookUserHome = ""
	enterpriseHookSID = "S-1-5-21-111-222-333-1001"
	enterpriseHookDataDir = ""
	enterpriseHookJSON = false
	called := false
	enterpriseHooksRemoveManagedPolicy = func(_ context.Context, opts enterprisehooks.InstallOptions) error {
		called = true
		if opts.OwnerSID != enterpriseHookSID || opts.UserHome != "" || opts.ConnectorName != "claudecode" {
			t.Fatalf("RemoveManagedPolicy opts = %+v", opts)
		}
		return nil
	}
	cmd := &cobra.Command{}
	cmd.SetOut(&strings.Builder{})
	if err := runEnterpriseHooksUninstall(cmd, nil); err != nil {
		t.Fatalf("runEnterpriseHooksUninstall: %v", err)
	}
	if !called {
		t.Fatal("RemoveManagedPolicy was not called")
	}
}

func TestResolveEnterpriseHookTargetValuesResolvesSIDOnlyProfile(t *testing.T) {
	original := enterpriseHookSIDProfilePath
	t.Cleanup(func() { enterpriseHookSIDProfilePath = original })
	enterpriseHookSIDProfilePath = func(sid string) (string, error) {
		if sid != "S-1-5-21-111-222-333-1001" {
			t.Fatalf("resolver SID = %q", sid)
		}
		return `C:\Users\alice`, nil
	}
	target, err := resolveEnterpriseHookTargetValues("", "", -1, -1, "S-1-5-21-111-222-333-1001", "")
	if err != nil {
		t.Fatalf("resolveEnterpriseHookTargetValues: %v", err)
	}
	if target.home != `C:\Users\alice` || target.sid != "S-1-5-21-111-222-333-1001" {
		t.Fatalf("target = %+v, want resolved SID-only profile", target)
	}
}

func TestEnterpriseHooksClaudeEffectivePolicyVerified(t *testing.T) {
	tests := []struct {
		name string
		rows []enterpriseHookReconcileRow
		want bool
	}{
		{
			name: "no generic row carries approved-client proof",
			rows: []enterpriseHookReconcileRow{
				{Connector: "codex", OK: false},
			},
			want: false,
		},
		{
			name: "OK Claude rows prove local integrity but not effective precedence",
			rows: []enterpriseHookReconcileRow{
				{Connector: "ClaudeCode", OK: true},
				{Connector: " claudecode ", OK: true},
				{Connector: "codex", OK: false},
			},
			want: false,
		},
		{
			name: "one failed Claude target rejects aggregate evidence",
			rows: []enterpriseHookReconcileRow{
				{Connector: "claudecode", OK: true},
				{Connector: "claudecode", OK: false, Error: "effective policy inactive"},
			},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := enterpriseHooksClaudeEffectivePolicyVerified(tc.rows); got != tc.want {
				t.Fatalf("enterpriseHooksClaudeEffectivePolicyVerified() = %t, want %t", got, tc.want)
			}
		})
	}
}
