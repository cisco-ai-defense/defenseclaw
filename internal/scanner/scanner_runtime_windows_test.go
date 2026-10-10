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
	"golang.org/x/sys/windows"
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

// GAP-1317: a server folder the enumerator verified is used only when the
// gateway can open it, since the server process runs as the gateway; a
// folder its DACL closes to the gateway is refused with that reason instead
// of failing later as a missing package.json.
func TestMCPRuntimeVerifiedWorkDirNeedsGatewayAccess(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	entry := &config.MCPServerEntry{Name: "local", Command: "npx", Project: project, Home: home, WorkDir: project}
	if got := (&MCPScanner{ServerEntry: entry}).serverWorkDir(); got != project {
		t.Fatalf("readable verified folder: server starts in %q, want %q", got, project)
	}
	closed, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)")
	if err != nil {
		t.Fatal(err)
	}
	closedDACL, _, err := closed.DACL()
	if err != nil {
		t.Fatal(err)
	}
	open, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	openDACL, _, err := open.DACL()
	if err != nil {
		t.Fatal(err)
	}
	setDACL := func(acl *windows.ACL) error {
		return windows.SetNamedSecurityInfo(project, windows.SE_FILE_OBJECT,
			windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
	}
	if err := setDACL(closedDACL); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setDACL(openDACL) })
	if f, err := os.Open(project); err == nil {
		f.Close()
		t.Skip("this token can open a folder closed to it (backup privilege enabled)")
	}
	mcp := &MCPScanner{ServerEntry: entry}
	if got := mcp.serverWorkDir(); got != "" || !strings.Contains(mcp.workDirNote(), "gateway service cannot read") {
		t.Fatalf("closed verified folder: server starts in %q, note %q", got, mcp.workDirNote())
	}
}
