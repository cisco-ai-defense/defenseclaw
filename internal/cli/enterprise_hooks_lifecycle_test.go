// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/spf13/cobra"
)

type enterpriseHooksTreeEntry struct {
	Mode       fs.FileMode
	Size       int64
	ModTimeNS  int64
	LinkTarget string
	Digest     [sha256.Size]byte
}

func TestEnterpriseHooksWindowsAdministratorGatePrecedesRootAndCommandLifecycle(t *testing.T) {
	for _, command := range []string{"install", "uninstall", "reconcile", "watch", "status", "verify"} {
		t.Run(command, func(t *testing.T) {
			restoreEnterpriseHooksLifecycleTestState(t)
			enterpriseHooksPlatformPreflight = func() error {
				return fmt.Errorf("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
			}

			scope := t.TempDir()
			sentinel := filepath.Join(scope, "sentinel.txt")
			if err := os.WriteFile(sentinel, []byte("unchanged\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			dataDir := filepath.Join(scope, "data")
			authorizationDir := filepath.Join(scope, "authorization")
			manifest := filepath.Join(scope, "manifest", "targets.yaml")
			userHome := filepath.Join(scope, "home", "alice")
			t.Setenv("DEFENSECLAW_HOME", dataDir)
			t.Setenv(hookGuardianAuthorizationDirEnv, authorizationDir)
			testenv.SetHome(t, filepath.Join(scope, "home"))
			t.Setenv("USERPROFILE", filepath.Join(scope, "home"))

			before := snapshotEnterpriseHooksTree(t, scope)
			rootPreRunCalled := false
			commandRunCalled := false
			enterpriseHooksRuntimeGOOS = func() string { return "windows" }
			enterpriseHooksRootPersistentPreRun = func(*cobra.Command, []string) error {
				rootPreRunCalled = true
				return nil
			}
			blockedRun := func(*cobra.Command, []string) error {
				commandRunCalled = true
				return fmt.Errorf("command lifecycle must not run")
			}
			enterpriseHooksInstallRunE = blockedRun
			enterpriseHooksUninstallRunE = blockedRun
			enterpriseHooksReconcileRunE = blockedRun
			enterpriseHooksWatchRunE = blockedRun
			enterpriseHooksStatusRunE = blockedRun
			enterpriseHooksVerifyRunE = blockedRun

			args := []string{"enterprise", "hooks", command}
			switch command {
			case "install", "uninstall":
				args = append(args, "--connector", "codex", "--user", "alice", "--user-home", userHome)
			case "reconcile", "watch", "status", "verify":
				args = append(args, "--manifest", manifest)
			}
			var stdout, stderr bytes.Buffer
			rootCmd.SetOut(&stdout)
			rootCmd.SetErr(&stderr)
			rootCmd.SetArgs(args)

			started := time.Now()
			_, err := rootCmd.ExecuteC()
			elapsed := time.Since(started)
			if err == nil {
				t.Fatal("ExecuteC error = nil, want unsupported-platform failure")
			}
			diagnostic := stdout.String() + stderr.String() + err.Error()
			if !strings.Contains(diagnostic, "require an elevated administrator or LocalSystem") {
				t.Fatalf("diagnostic = %q, want native Windows administrator requirement", diagnostic)
			}
			if elapsed >= time.Second {
				t.Fatalf("command returned in %s, want less than 1s", elapsed)
			}
			if rootPreRunCalled {
				t.Fatal("root persistent pre-run ran before the Windows platform gate")
			}
			if commandRunCalled {
				t.Fatal("command handler ran before the Windows platform gate")
			}

			after := snapshotEnterpriseHooksTree(t, scope)
			if !reflect.DeepEqual(after, before) {
				t.Fatalf("disposable tree changed:\nbefore: %#v\nafter:  %#v", before, after)
			}
			for _, path := range []string{
				dataDir,
				filepath.Join(dataDir, "audit.db"),
				filepath.Join(dataDir, hookGuardianStateFile),
				authorizationDir,
				filepath.Join(authorizationDir, hookGuardianAuthorizationFile),
				filepath.Join(dataDir, "logs"),
				filepath.Join(dataDir, "gateway.pid"),
				filepath.Join(userHome, ".defenseclaw"),
				filepath.Join(userHome, ".claude", "settings.json"),
				filepath.Join(userHome, ".codex", "config.toml"),
				filepath.Dir(manifest),
			} {
				if _, statErr := os.Lstat(path); !os.IsNotExist(statErr) {
					t.Errorf("unexpected platform-gate side effect at %s (stat error %v)", path, statErr)
				}
			}
		})
	}
}

func TestEnterpriseHooksSupportedPlatformChainsRootPreRunAndCommand(t *testing.T) {
	for _, command := range []string{"install", "uninstall", "reconcile", "watch", "status", "verify"} {
		t.Run(command, func(t *testing.T) {
			restoreEnterpriseHooksLifecycleTestState(t)
			enterpriseHooksRuntimeGOOS = func() string { return "linux" }
			var calls []string
			enterpriseHooksRootPersistentPreRun = func(*cobra.Command, []string) error {
				calls = append(calls, "root-pre-run")
				return nil
			}
			commandRun := func(*cobra.Command, []string) error {
				calls = append(calls, command+"-run")
				return nil
			}
			switch command {
			case "install":
				enterpriseHooksInstallRunE = commandRun
			case "uninstall":
				enterpriseHooksUninstallRunE = commandRun
			case "reconcile":
				enterpriseHooksReconcileRunE = commandRun
			case "watch":
				enterpriseHooksWatchRunE = commandRun
			case "status":
				enterpriseHooksStatusRunE = commandRun
			case "verify":
				enterpriseHooksVerifyRunE = commandRun
			}

			rootCmd.SetArgs([]string{"enterprise", "hooks", command})
			if _, err := rootCmd.ExecuteC(); err != nil {
				t.Fatalf("ExecuteC: %v", err)
			}
			want := []string{"root-pre-run", command + "-run"}
			if !reflect.DeepEqual(calls, want) {
				t.Fatalf("lifecycle calls = %v, want %v", calls, want)
			}
		})
	}
}

func TestEnterpriseHooksStatusDoesNotInitializeAbsentDataRoot(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	originalJSON := enterpriseHookJSON
	t.Cleanup(func() { enterpriseHookJSON = originalJSON })

	scope := t.TempDir()
	dataDir := filepath.Join(scope, "absent-data")
	cfg = &config.Config{
		DataDir:        dataDir,
		DeploymentMode: "unmanaged_byod",
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	enterpriseHookJSON = true
	enterpriseHooksRuntimeGOOS = func() string { return runtime.GOOS }
	enterpriseHooksPlatformPreflight = func() error { return nil }
	fullPreRunCalled := false
	enterpriseHooksFullRootPersistentPreRun = func(*cobra.Command, []string) error {
		fullPreRunCalled = true
		return errors.New("status must not initialize the audit runtime")
	}
	configOnlyCalled := false
	enterpriseHooksConfigOnlyPersistentPreRun = func(*cobra.Command, []string) error {
		configOnlyCalled = true
		if _, err := os.Lstat(dataDir); !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("config-only pre-run observed a created data root: %v", err)
		}
		return nil
	}

	before := snapshotEnterpriseHooksTree(t, scope)
	var stdout, stderr bytes.Buffer
	rootCmd.SetOut(&stdout)
	rootCmd.SetErr(&stderr)
	rootCmd.SetArgs([]string{"enterprise", "hooks", "status", "--json"})
	if _, err := rootCmd.ExecuteC(); err != nil {
		t.Fatalf("enterprise hooks status: %v; stderr=%s", err, stderr.String())
	}
	if !configOnlyCalled || fullPreRunCalled {
		t.Fatalf(
			"status pre-run calls = config-only:%t full:%t, want true/false",
			configOnlyCalled,
			fullPreRunCalled,
		)
	}
	var report enterpriseHookStatusReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode status JSON %q: %v", stdout.String(), err)
	}
	if !report.OK || report.Enabled {
		t.Fatalf("unmanaged status = %+v, want healthy disabled report", report)
	}
	after := snapshotEnterpriseHooksTree(t, scope)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("status mutated absent explicit data root:\nbefore: %#v\nafter:  %#v", before, after)
	}
	for _, path := range []string{
		dataDir,
		filepath.Join(dataDir, "audit.db"),
		filepath.Join(dataDir, hookGuardianStateFile),
		filepath.Join(dataDir, "authorization"),
	} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("read-only Status created %s (stat error %v)", path, err)
		}
	}
}

func TestEnterpriseHooksNativeWindowsAdministratorPreflightSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows smoke test")
	}
	restoreEnterpriseHooksLifecycleTestState(t)
	scope := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(scope, "data"))
	enterpriseHooksPlatformPreflight = func() error {
		return fmt.Errorf("enterprise hooks require an elevated administrator or LocalSystem token on native Windows")
	}
	enterpriseHooksInstallRunE = func(*cobra.Command, []string) error {
		t.Fatal("install handler ran on native Windows")
		return nil
	}
	rootCmd.SetArgs([]string{"enterprise", "hooks", "install"})
	_, err := rootCmd.ExecuteC()
	if err == nil || !strings.Contains(err.Error(), "require an elevated administrator") {
		t.Fatalf("ExecuteC error = %v, want native Windows administrator failure", err)
	}
	if entries := snapshotEnterpriseHooksTree(t, scope); len(entries) != 1 {
		t.Fatalf("native Windows smoke tree changed: %#v", entries)
	}
}

func TestEnterpriseHooksManagedMutationPreflightPrecedesTokenMinting(t *testing.T) {
	for _, command := range []string{"install", "reconcile", "watch"} {
		t.Run(command, func(t *testing.T) {
			restoreEnterpriseHooksLifecycleTestState(t)
			previousJSON := enterpriseHookJSON
			previousManifest := enterpriseHookManifest
			previousInterval := enterpriseHookWatchInterval
			previousDebounce := enterpriseHookWatchDebounce
			t.Cleanup(func() {
				enterpriseHookJSON = previousJSON
				enterpriseHookManifest = previousManifest
				enterpriseHookWatchInterval = previousInterval
				enterpriseHookWatchDebounce = previousDebounce
			})
			cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
			enterpriseHookJSON = false
			enterpriseHookManifest = filepath.Join(t.TempDir(), "must-not-be-read.yaml")
			enterpriseHookWatchInterval = time.Minute
			enterpriseHookWatchDebounce = time.Second
			refusal := errors.New("elevated administrator is not the LocalSystem guardian")
			enterpriseHooksMutationIdentityPreflight = func() error { return refusal }
			tokenCalled := false
			enterpriseHookScopedTokenMinter = func(string, string) (string, error) {
				tokenCalled = true
				return "", nil
			}
			enterpriseHookScopedOTLPTokenMinter = func(string, string) (string, error) {
				tokenCalled = true
				return "", nil
			}
			cmd := &cobra.Command{}
			var err error
			switch command {
			case "install":
				err = runEnterpriseHooksInstall(cmd, nil)
			case "reconcile":
				err = runEnterpriseHooksReconcile(cmd, nil)
			case "watch":
				err = runEnterpriseHooksWatch(cmd, nil)
			}
			if !errors.Is(err, refusal) {
				t.Fatalf("%s error = %v, want LocalSystem preflight refusal", command, err)
			}
			if tokenCalled {
				t.Fatalf("%s minted or loaded a scoped token before LocalSystem preflight", command)
			}
		})
	}
}

func TestEnterpriseHooksMutationPreflightIsNoOpOutsideManagedMode(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	cfg = &config.Config{DeploymentMode: "local"}
	called := false
	enterpriseHooksMutationIdentityPreflight = func() error {
		called = true
		return errors.New("must not run")
	}
	if err := enterpriseHooksManagedMutationPreflight(); err != nil {
		t.Fatalf("non-managed mutation preflight = %v", err)
	}
	if called {
		t.Fatal("non-managed mode invoked the Windows managed-mutation identity gate")
	}
}

func TestEnterpriseHooksPluginRegistryBehaviorUnchangedOutsideManagedWindows(t *testing.T) {
	restoreEnterpriseHooksLifecycleTestState(t)
	originalPluginFactory := enterpriseHooksPluginRegistryFactory
	originalCertifiedFactory := enterpriseHooksCertifiedRegistryFactory
	t.Cleanup(func() {
		enterpriseHooksPluginRegistryFactory = originalPluginFactory
		enterpriseHooksCertifiedRegistryFactory = originalCertifiedFactory
	})
	pluginCalls := 0
	certifiedCalls := 0
	enterpriseHooksPluginRegistryFactory = func() *connector.Registry {
		pluginCalls++
		return connector.NewDefaultRegistry()
	}
	enterpriseHooksCertifiedRegistryFactory = func() *connector.Registry {
		certifiedCalls++
		return newWindowsEnterpriseCertifiedConnectorRegistry()
	}

	for _, tc := range []struct {
		goos string
		mode string
	}{
		{goos: "windows", mode: "unmanaged_byod"},
		{goos: "linux", mode: managed.DeploymentModeManagedEnterprise},
	} {
		enterpriseHooksRuntimeGOOS = func() string { return tc.goos }
		cfg = &config.Config{DeploymentMode: tc.mode}
		_ = newEnterpriseHooksConnectorRegistry()
	}
	if pluginCalls != 2 || certifiedCalls != 0 {
		t.Fatalf("registry calls outside managed Windows = plugin:%d certified:%d, want 2/0", pluginCalls, certifiedCalls)
	}
}

func restoreEnterpriseHooksLifecycleTestState(t *testing.T) {
	t.Helper()
	originalGOOS := enterpriseHooksRuntimeGOOS
	originalPlatformPreflight := enterpriseHooksPlatformPreflight
	originalMutationPreflight := enterpriseHooksMutationIdentityPreflight
	originalRootPreRun := enterpriseHooksRootPersistentPreRun
	originalFullRootPreRun := enterpriseHooksFullRootPersistentPreRun
	originalConfigOnlyPreRun := enterpriseHooksConfigOnlyPersistentPreRun
	originalInstall := enterpriseHooksInstallRunE
	originalUninstall := enterpriseHooksUninstallRunE
	originalReconcile := enterpriseHooksReconcileRunE
	originalWatch := enterpriseHooksWatchRunE
	originalStatus := enterpriseHooksStatusRunE
	originalVerify := enterpriseHooksVerifyRunE
	originalTokenMinter := enterpriseHookScopedTokenMinter
	originalOTLPTokenMinter := enterpriseHookScopedOTLPTokenMinter
	originalCfg, originalAuditStore, originalAuditLog := cfg, auditStore, auditLog
	originalOut, originalErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	t.Cleanup(func() {
		enterpriseHooksRuntimeGOOS = originalGOOS
		enterpriseHooksPlatformPreflight = originalPlatformPreflight
		enterpriseHooksMutationIdentityPreflight = originalMutationPreflight
		enterpriseHooksRootPersistentPreRun = originalRootPreRun
		enterpriseHooksFullRootPersistentPreRun = originalFullRootPreRun
		enterpriseHooksConfigOnlyPersistentPreRun = originalConfigOnlyPreRun
		enterpriseHooksInstallRunE = originalInstall
		enterpriseHooksUninstallRunE = originalUninstall
		enterpriseHooksReconcileRunE = originalReconcile
		enterpriseHooksWatchRunE = originalWatch
		enterpriseHooksStatusRunE = originalStatus
		enterpriseHooksVerifyRunE = originalVerify
		enterpriseHookScopedTokenMinter = originalTokenMinter
		enterpriseHookScopedOTLPTokenMinter = originalOTLPTokenMinter
		cfg, auditStore, auditLog = originalCfg, originalAuditStore, originalAuditLog
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(originalOut)
		rootCmd.SetErr(originalErr)
	})
	cfg, auditStore, auditLog = nil, nil, nil
}

func snapshotEnterpriseHooksTree(t *testing.T, root string) map[string]enterpriseHooksTreeEntry {
	t.Helper()
	entries := make(map[string]enterpriseHooksTreeEntry)
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		record := enterpriseHooksTreeEntry{
			Mode:      info.Mode(),
			Size:      info.Size(),
			ModTimeNS: info.ModTime().UnixNano(),
		}
		if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			record.LinkTarget = target
		}
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			record.Digest = sha256.Sum256(data)
		}
		entries[rel] = record
		return nil
	})
	if err != nil {
		t.Fatalf("snapshot %s: %v", root, err)
	}
	return entries
}
