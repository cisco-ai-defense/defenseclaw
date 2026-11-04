// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
)

// GAP-0037/GAP-0039: the per-user gateway and Windows setup read the
// newest Authenticode-verified engine of every data folder (3P and the MSIX
// Claude-Data folder measured on Claude Desktop 4.16336.0) with the
// claude.exe that verified.
func TestClaudeDesktopEngineIsTheNewestSignedBuildOnWindows(t *testing.T) {
	home := t.TempDir()
	f := claudedesktop.FoldersForHome("windows", home)
	windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc"), "2.1.309")
	third := windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-3p"), "2.1.317")
	stubWindowsEngineSignature(t, signedAsFolder)

	build := ClaudeDesktopEngine(context.Background(), home)
	if build.Version != "2.1.317" || build.Executable != third || build.EngineDir != filepath.Join(f.LocalAppData, "Claude-3p", "claude-code") {
		t.Fatalf("engine = %+v, want 2.1.317 %s", build, third)
	}
	if version, dir := ClaudeDesktopEngineVersion(context.Background(), home); version != "2.1.317" || dir != build.EngineDir {
		t.Fatalf("version = %q %q", version, dir)
	}

	// Same version in the MSIX 1p folder and Claude-3p: the later folder (3p).
	tie := t.TempDir()
	tf := claudedesktop.FoldersForHome("windows", tie)
	windowsDesktopEngine(t, filepath.Join(tf.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc"), "2.1.317")
	tieThird := windowsDesktopEngine(t, filepath.Join(tf.LocalAppData, "Claude-3p"), "2.1.317")
	if got := ClaudeDesktopEngine(context.Background(), tie); got.Executable != tieThird {
		t.Fatalf("tie = %+v, want %s", got, tieThird)
	}

	// A newer build signed as another version is never the version.
	windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-3p"), "2.1.320")
	stubWindowsEngineSignature(t, func(path string) codesig.Result {
		if strings.Contains(path, "2.1.320") {
			return codesig.Result{Verified: true, Version: "2.1.200.0"}
		}
		return signedAsFolder(path)
	})
	if got := ClaudeDesktopEngine(context.Background(), home); got.Version != "2.1.317" {
		t.Fatalf("with a mislabelled 2.1.320: %+v", got)
	}

	// Nothing signed: no version, and the reason.
	stubWindowsEngineSignature(t, func(string) codesig.Result {
		return codesig.Result{Reason: "claude.exe is not signed", Unsigned: true}
	})
	got := ClaudeDesktopEngine(context.Background(), home)
	if got.Version != "" || got.Executable != "" || !strings.Contains(got.Unverified, "claude.exe is not signed") {
		t.Fatalf("unsigned = %+v", got)
	}
}

// GAP-0039: setup's lookup reports the digest its last signature check took
// over the verified handle; the gateway's lookup hashes nothing.
func TestClaudeDesktopEngineWithDigestReportsTheVerifiedHash(t *testing.T) {
	home := t.TempDir()
	f := claudedesktop.FoldersForHome("windows", home)
	exe := windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-3p"), "2.1.317")
	stubWindowsEngineSignature(t, signedAsFolder)
	previous := verifyWindowsClaudeDesktopEngineDigest
	t.Cleanup(func() { verifyWindowsClaudeDesktopEngineDigest = previous })
	var hashed []string
	verifyWindowsClaudeDesktopEngineDigest = func(path string, publishers []string) codesig.Result {
		hashed = append(hashed, path)
		result := signedAsFolder(path)
		result.SHA256 = "5f84a2a8"
		return result
	}

	if got := ClaudeDesktopEngine(context.Background(), home); got.Executable != exe || got.SHA256 != "" || len(hashed) != 0 {
		t.Fatalf("gateway lookup = %+v (hashed %q), want no digest", got, hashed)
	}
	got := ClaudeDesktopEngineWithDigest(context.Background(), home)
	if got.Executable != exe || got.Version != "2.1.317" || got.SHA256 != "5f84a2a8" || len(hashed) != 1 || hashed[0] != exe {
		t.Fatalf("setup lookup = %+v (hashed %q)", got, hashed)
	}

	// The last check refuses (the file changed after discovery): nothing.
	verifyWindowsClaudeDesktopEngineDigest = func(string, []string) codesig.Result {
		return codesig.Result{Reason: "claude.exe changed"}
	}
	if got := ClaudeDesktopEngineWithDigest(context.Background(), home); got.Executable != "" || got.SHA256 != "" || !strings.Contains(got.Unverified, "changed") {
		t.Fatalf("refused last check = %+v", got)
	}
}
