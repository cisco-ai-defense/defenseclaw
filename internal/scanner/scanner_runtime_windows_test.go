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
}
