// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// A rejected installed runtime must stop the scan before a same-named PATH
// executable can provide a clean result.
func TestManagedScannerRuntimeRejectionStopsPathFallback(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	pathDir := t.TempDir()
	fallback := filepath.Join(pathDir, "skill-scanner.cmd")
	if err := os.WriteFile(fallback, []byte("@echo off\r\necho {\"findings\":[]}\r\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir+";"+os.Getenv("PATH"))

	oldPath, oldProblem := scannerRuntimePath, scannerRuntimeProblem
	scannerRuntimePath = func() string { return "" }
	scannerRuntimeProblem = func() error { return errors.New("admission failed") }
	t.Cleanup(func() { scannerRuntimePath, scannerRuntimeProblem = oldPath, oldProblem })

	scanner := NewSkillScannerFromLLM(config.SkillScannerConfig{}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	result, err := scanner.Scan(context.Background(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "admission failed") {
		t.Fatalf("Scan() = %+v, %v; want managed runtime refusal before PATH fallback", result, err)
	}
	// GAP-0975: a plugin scan must not run the managed CLI beside the
	// gateway, and the error lets the rescan loop retry soon.
	if result, err := NewPluginScanner("").Scan(context.Background(), t.TempDir()); result != nil ||
		!errors.Is(err, ErrScannerRuntimeUnavailable) || strings.Contains(err.Error(), "asset_policy") {
		t.Fatalf("plugin Scan() = %+v, %v; want the runtime-not-ready error", result, err)
	}
}

// GAP-1436: a machine-wide runtime root left behind (a standalone uninstall
// that could not remove it) is never used by a per-user install, while the
// standalone deployment still refuses the same unusable root.
func TestPerUserScannerIgnoresLeftoverRuntimeRoot(t *testing.T) {
	root := t.TempDir() // the leftover root, without its executable
	oldRoot := scannerRuntimeRoot
	scannerRuntimeRoot = func() (string, error) { return root, nil }
	t.Cleanup(func() { scannerRuntimeRoot = oldRoot })

	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if got := resolveScannerRuntime("skill-scanner", "skill-scanner", "skill-scanner.exe"); got != "skill-scanner" {
		t.Fatalf("per-user resolveScannerRuntime() = %q, want the configured command", got)
	}
	if err := scannerRuntimePreflight("skill-scanner", "skill-scanner", "skill-scanner.exe"); err != nil {
		t.Fatalf("per-user scannerRuntimePreflight() = %v, want nil", err)
	}
	if err := scannerRuntimeProblem(); err != nil {
		t.Fatalf("per-user scannerRuntimeProblem() = %v, want nil", err)
	}

	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	if err := scannerRuntimePreflight("skill-scanner", "skill-scanner", "skill-scanner.exe"); !errors.Is(err, ErrScannerRuntimeUnavailable) {
		t.Fatalf("standalone scannerRuntimePreflight() = %v, want the runtime-not-ready error", err)
	}
}
