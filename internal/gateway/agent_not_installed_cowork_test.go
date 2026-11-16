// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// An account with Claude Desktop (whose bundled Claude Code engine runs
// Claude Cowork and its hooks) and no claude CLI still has the agent: the
// claudecode connector is never skipped as not installed (cowork-1-0-8
// GAP-0002).
func TestClaudeDesktopEngineKeepsClaudeCodeInstalled(t *testing.T) {
	home := t.TempDir()
	testenv.SetHome(t, home)
	t.Setenv("PATH", t.TempDir())
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"),
		[]byte(`{"agents":{"claudecode":{"installed":false}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := connector.SetupOpts{DataDir: dataDir}
	dirs := engineDirsFor(home)
	if len(dirs) == 0 {
		t.Skipf("no Claude Desktop layout on %s", runtime.GOOS)
	}
	if claudeDesktopEngineMayExist(home) {
		t.Fatal("an absent engine folder counted as an engine")
	}
	baseline := agentNotInstalledReason(opts, "claudecode")
	// An empty engine folder is no engine either.
	if err := os.MkdirAll(dirs[0], 0o700); err != nil {
		t.Fatal(err)
	}
	if claudeDesktopEngineMayExist(home) {
		t.Fatal("an empty engine folder counted as an engine")
	}
	if err := os.MkdirAll(filepath.Join(dirs[0], "2.1.309", "5af865b9901c"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !claudeDesktopEngineMayExist(home) {
		t.Fatal("the Claude Desktop engine was not found")
	}
	if why := agentNotInstalledReason(opts, "claudecode"); why != "" {
		t.Fatalf("claudecode skipped as not installed next to the Claude Desktop engine: %s", why)
	}
	if baseline == "" {
		t.Log("this host has a claude binary in a common folder; the skip without the engine is not checked here")
	}
	// The engine is evidence for claudecode only.
	if !agentBinaryMayExistNow("claudecode") {
		t.Fatal("agentBinaryMayExistNow(claudecode) = false next to the engine")
	}
}

// Every Claude Desktop data folder of this OS (first party, third-party
// inference and, on Windows, the MSIX package folders) keeps claudecode
// installed (cowork-1-0-8 GAP-0024: 3p users were never enrolled).
func TestClaudeDesktopEngineInEveryDataRootKeepsClaudeCodeInstalled(t *testing.T) {
	roots := claudedesktop.Roots(runtime.GOOS)
	if len(roots) == 0 {
		t.Skipf("no Claude Desktop layout on %s", runtime.GOOS)
	}
	for _, root := range roots {
		home := t.TempDir()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
		t.Setenv("XDG_CONFIG_HOME", "")
		f := claudedesktop.FoldersForHome(runtime.GOOS, home)
		if runtime.GOOS == "windows" {
			t.Setenv("APPDATA", f.AppData)
			t.Setenv("LOCALAPPDATA", f.LocalAppData)
		}
		data := strings.Replace(root.Pattern(f), "*", "pzs8sxrjxfjjc", 1)
		if claudeDesktopEngineMayExist(home) {
			t.Fatalf("%s: an absent engine folder counted as an engine", root.Path)
		}
		if err := os.MkdirAll(filepath.Join(data, "claude-code", "2.1.317", "a33aa5518497"), 0o700); err != nil {
			t.Fatal(err)
		}
		if !claudeDesktopEngineMayExist(home) {
			t.Fatalf("%s (%s): the Claude Desktop engine was not found in %q", root.Path, root.Deployment, engineDirsFor(home))
		}
	}
	if runtime.GOOS != "windows" {
		return
	}
	// More MSIX data folders than are read: one left out may hold the
	// engine, so the connector is not skipped.
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	f := claudedesktop.FoldersForHome(runtime.GOOS, home)
	t.Setenv("APPDATA", f.AppData)
	t.Setenv("LOCALAPPDATA", f.LocalAppData)
	for i := 0; i <= claudedesktop.MaxGlobMatches; i++ {
		if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Claude-Data", "claude_"+strconv.Itoa(i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if !claudeDesktopEngineMayExist(home) {
		t.Fatal("a Claude-Data glob that left folders out counted as no engine")
	}
}

// engineDirsFor is the engine folders claudeDesktopEngineMayExist reads.
func engineDirsFor(home string) []string {
	dirs, _ := claudedesktop.EngineDirs(runtime.GOOS, claudedesktop.FoldersFromEnv(runtime.GOOS, home, os.Getenv))
	var out []string
	for _, dir := range dirs {
		out = append(out, dir.Path)
	}
	return out
}
