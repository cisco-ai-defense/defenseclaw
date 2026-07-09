// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

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

func TestEnterpriseHooksWindowsGatePrecedesRootAndCommandLifecycle(t *testing.T) {
	for _, command := range []string{"install", "reconcile", "watch"} {
		t.Run(command, func(t *testing.T) {
			restoreEnterpriseHooksLifecycleTestState(t)

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
			enterpriseHooksReconcileRunE = blockedRun
			enterpriseHooksWatchRunE = blockedRun

			args := []string{"enterprise", "hooks", command}
			switch command {
			case "install":
				args = append(args, "--connector", "codex", "--user", "alice", "--user-home", userHome)
			case "reconcile", "watch":
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
			if !strings.Contains(diagnostic, "enterprise hooks are unsupported on native Windows") {
				t.Fatalf("diagnostic = %q, want native Windows unsupported message", diagnostic)
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
	for _, command := range []string{"install", "reconcile", "watch"} {
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
			case "reconcile":
				enterpriseHooksReconcileRunE = commandRun
			case "watch":
				enterpriseHooksWatchRunE = commandRun
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

func TestEnterpriseHooksNativeWindowsSmoke(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows smoke test")
	}
	restoreEnterpriseHooksLifecycleTestState(t)
	scope := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(scope, "data"))
	enterpriseHooksInstallRunE = func(*cobra.Command, []string) error {
		t.Fatal("install handler ran on native Windows")
		return nil
	}
	rootCmd.SetArgs([]string{"enterprise", "hooks", "install"})
	_, err := rootCmd.ExecuteC()
	if err == nil || !strings.Contains(err.Error(), "enterprise hooks are unsupported on native Windows") {
		t.Fatalf("ExecuteC error = %v, want native Windows unsupported failure", err)
	}
	if entries := snapshotEnterpriseHooksTree(t, scope); len(entries) != 1 {
		t.Fatalf("native Windows smoke tree changed: %#v", entries)
	}
}

func restoreEnterpriseHooksLifecycleTestState(t *testing.T) {
	t.Helper()
	originalGOOS := enterpriseHooksRuntimeGOOS
	originalRootPreRun := enterpriseHooksRootPersistentPreRun
	originalInstall := enterpriseHooksInstallRunE
	originalReconcile := enterpriseHooksReconcileRunE
	originalWatch := enterpriseHooksWatchRunE
	originalCfg, originalAuditStore, originalAuditLog, originalOTel := cfg, auditStore, auditLog, otelProvider
	originalOut, originalErr := rootCmd.OutOrStdout(), rootCmd.ErrOrStderr()
	t.Cleanup(func() {
		enterpriseHooksRuntimeGOOS = originalGOOS
		enterpriseHooksRootPersistentPreRun = originalRootPreRun
		enterpriseHooksInstallRunE = originalInstall
		enterpriseHooksReconcileRunE = originalReconcile
		enterpriseHooksWatchRunE = originalWatch
		cfg, auditStore, auditLog, otelProvider = originalCfg, originalAuditStore, originalAuditLog, originalOTel
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(originalOut)
		rootCmd.SetErr(originalErr)
	})
	cfg, auditStore, auditLog, otelProvider = nil, nil, nil, nil
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
