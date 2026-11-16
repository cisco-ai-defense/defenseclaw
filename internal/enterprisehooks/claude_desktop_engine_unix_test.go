// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/codesig"
)

// engineVersionAs runs ClaudeDesktopEngineVersion with the desktop probes of
// goos and verify as the macOS signature check.
func engineVersionAs(t *testing.T, goos string, verify func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result, home string) (string, string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the per-user gateway never reads the engine as root")
	}
	origGOOS, origVerify := unixSurfaceGOOS, verifyUnixDesktopBundle
	unixSurfaceGOOS, verifyUnixDesktopBundle = goos, verify
	t.Cleanup(func() { unixSurfaceGOOS, verifyUnixDesktopBundle = origGOOS, origVerify })
	return ClaudeDesktopEngineVersion(context.Background(), home)
}

// GAP-0037: the per-user gateway's Claude Code version on a Desktop-only
// account is the newest signed engine build of every data folder.
func TestClaudeDesktopEngineVersionIsTheNewestSignedBuild(t *testing.T) {
	home := t.TempDir()
	desktopEngineBundleIn(t, home, "Claude", "2.1.309", "2.1.309")
	desktopEngineBundleIn(t, home, "Claude-3p", "2.1.317", "2.1.317")
	signed := func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
		return codesig.Result{Verified: true}
	}
	version, dir := engineVersionAs(t, "darwin", signed, home)
	if version != "2.1.317" || dir != filepath.Join(home, "Library", "Application Support", "Claude-3p", "claude-code") {
		t.Fatalf("engine = %q in %q, want 2.1.317 in Claude-3p", version, dir)
	}

	// One version in both folders: the 3p folder's, as Python discovery picks.
	tie := t.TempDir()
	desktopEngineBundleIn(t, tie, "Claude", "2.1.317", "2.1.317")
	desktopEngineBundleIn(t, tie, "Claude-3p", "2.1.317", "2.1.317")
	if _, dir := engineVersionAs(t, "darwin", signed, tie); !strings.Contains(dir, "Claude-3p") {
		t.Fatalf("tie picked %q, want the Claude-3p folder", dir)
	}

	// An unsigned newer build is never the version; the signed one is.
	desktopEngineBundleIn(t, home, "Claude-3p", "2.1.320", "2.1.320")
	onlyOld := func(_ context.Context, path string, _ codesig.Darwin, _ codesig.DarwinOptions) codesig.Result {
		if strings.Contains(path, "2.1.320") {
			return codesig.Result{Reason: "code object is not signed at all"}
		}
		return codesig.Result{Verified: true}
	}
	if version, _ := engineVersionAs(t, "darwin", onlyOld, home); version != "2.1.317" {
		t.Fatalf("with an unsigned 2.1.320 the engine = %q, want 2.1.317", version)
	}
	unsigned := func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
		return codesig.Result{Reason: "code object is not signed at all"}
	}
	if version, dir := engineVersionAs(t, "darwin", unsigned, home); version != "" || dir != "" {
		t.Fatalf("unsigned engines = %q in %q, want none", version, dir)
	}
}

func TestClaudeDesktopEngineVersionOnLinuxNeedsAnExecutable(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "Claude-3p", "claude-code", "2.1.320"), 0o755); err != nil {
		t.Fatal(err)
	}
	linuxDesktopEngine(t, home, "Claude-3p", "2.1.317")
	if version, _ := engineVersionAs(t, "linux", noLinuxSignatureCheck(t), home); version != "2.1.317" {
		t.Fatalf("Linux engine = %q, want 2.1.317 (2.1.320 has no executable)", version)
	}
	if version, _ := engineVersionAs(t, "linux", noLinuxSignatureCheck(t), t.TempDir()); version != "" {
		t.Fatalf("no Claude Desktop: engine = %q", version)
	}
}
