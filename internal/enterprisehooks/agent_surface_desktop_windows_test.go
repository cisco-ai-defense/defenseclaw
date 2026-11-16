// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsDesktopEngine writes <data>\claude-code\<version>\<build>\claude.exe.
func windowsDesktopEngine(t *testing.T, data, version string) string {
	t.Helper()
	exe := filepath.Join(data, "claude-code", version, "a33aa5518497", "claude.exe")
	if err := os.MkdirAll(filepath.Dir(exe), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	return exe
}

// stubWindowsEngineSignature replaces the Authenticode check: verify gets
// each checked claude.exe.
func stubWindowsEngineSignature(t *testing.T, verify func(path string) codesig.Result) {
	t.Helper()
	previous := verifyWindowsClaudeDesktopEngine
	t.Cleanup(func() { verifyWindowsClaudeDesktopEngine = previous })
	verifyWindowsClaudeDesktopEngine = func(path string, publishers []string) codesig.Result {
		if strings.Join(publishers, "|") != "Anthropic PBC|Anthropic, PBC" {
			t.Fatalf("publishers = %q", publishers)
		}
		return verify(path)
	}
}

// signedAsFolder signs every claude.exe as its version folder's version.
func signedAsFolder(path string) codesig.Result {
	return codesig.Result{Verified: true, Version: filepath.Base(filepath.Dir(filepath.Dir(path))) + ".0"}
}

func windowsDesktopSurfaces(t *testing.T, home string) ([]connector.AgentSurface, []bool, error) {
	t.Helper()
	found, err := discoverWindowsClaudeDesktop(home)
	var surfaces []connector.AgentSurface
	var complete []bool
	for _, desktop := range found {
		surfaces, complete = append(surfaces, desktop.surface), append(complete, desktop.complete)
	}
	return surfaces, complete, err
}

func TestDiscoverWindowsClaudeDesktopTrustsTheSignature(t *testing.T) {
	home := t.TempDir()
	version := filepath.Join(home, "AppData", "Roaming", "Claude", "claude-code", "2.1.309")
	if err := os.MkdirAll(version, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := filepath.Join(version, "claude.exe")
	if err := os.WriteFile(exe, []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	var checked string
	stubWindowsEngineSignature(t, func(path string) codesig.Result {
		checked = path
		return codesig.Result{Verified: true, Version: "2.1.309.0"}
	})
	got, complete, err := windowsDesktopSurfaces(t, home)
	if err != nil || len(got) != 1 || !complete[0] || got[0].EngineVersion != "2.1.309" || got[0].EngineUnverified != "" || checked != exe {
		t.Fatalf("signed engine = %+v complete=%v err=%v checked=%s", got, complete, err, checked)
	}
	stubWindowsEngineSignature(t, func(string) codesig.Result {
		return codesig.Result{Reason: `claude.exe is signed by "Mallory Inc", not by Anthropic PBC or Anthropic, PBC`}
	})
	got, _, err = windowsDesktopSurfaces(t, home)
	if err != nil || len(got) != 1 || got[0].EngineVersion != "" || !strings.Contains(got[0].EngineUnverified, "Mallory Inc") ||
		!strings.Contains(got[0].EngineUnverified, "2.1.309") {
		t.Fatalf("wrong signer = %+v err=%v", got, err)
	}
	if err := os.Remove(exe); err != nil {
		t.Fatal(err)
	}
	got, _, _ = windowsDesktopSurfaces(t, home)
	if len(got) != 1 || got[0].EngineVersion != "" || !strings.Contains(got[0].EngineUnverified, "no claude.exe") {
		t.Fatalf("missing engine = %+v", got)
	}
}

// An older signed claude.exe copied into a newer version folder does not
// select the newer contract: the signed file version must be the folder's.
func TestDiscoverWindowsClaudeDesktopBindsTheSignedFileVersion(t *testing.T) {
	home := t.TempDir()
	version := filepath.Join(home, "AppData", "Roaming", "Claude", "claude-code", "2.1.309")
	if err := os.MkdirAll(version, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(version, "claude.exe"), []byte("MZ"), 0o644); err != nil {
		t.Fatal(err)
	}
	for fileVersion, want := range map[string]string{
		"2.1.295.0": "signed as version 2.1.295.0, not 2.1.309",
		"":          "has no file version",
		"2.1.309.1": "signed as version 2.1.309.1, not 2.1.309",
		"2.1.309.0": "",
	} {
		stubWindowsEngineSignature(t, func(string) codesig.Result {
			return codesig.Result{Verified: true, Version: fileVersion}
		})
		got, _, _ := windowsDesktopSurfaces(t, home)
		if len(got) != 1 || (want == "") != (got[0].EngineVersion == "2.1.309") || !strings.Contains(got[0].EngineUnverified, want) {
			t.Fatalf("file version %q: surfaces = %+v", fileVersion, got)
		}
	}
}

func TestWindowsSignedVersionIs(t *testing.T) {
	for _, tc := range []struct {
		file, folder string
		want         bool
	}{
		{"2.1.309.0", "2.1.309", true}, {"2.1.309", "2.1.309", true}, {"2.1.309.0.0", "2.1.309", true},
		{"2.1.30.9", "2.1.309", false}, {"2.1.309.2", "2.1.309", false}, {"2.1", "2.1.309", false}, {"", "2.1.309", false},
	} {
		if got := windowsSignedVersionIs(tc.file, tc.folder); got != tc.want {
			t.Fatalf("windowsSignedVersionIs(%q, %q) = %v", tc.file, tc.folder, got)
		}
	}
}

// Every Windows data folder of Claude Desktop (the installer's roaming
// folder, the MSIX package's Claude-Data and LocalCache folders, and
// Claude-3p for third-party inference, measured on 4.16336.0) is searched
// and its build trusted by its Authenticode signer. Each folder is a
// surface of its own, so with 1p and 3p side by side the row follows the
// older build (cowork-1-0-8 GAP-0024).
func TestDiscoverWindowsClaudeDesktopInEveryDataRoot(t *testing.T) {
	for _, root := range claudedesktop.Roots("windows") {
		home := t.TempDir()
		data := strings.Replace(root.Pattern(claudedesktop.FoldersForHome("windows", home)), "*", "pzs8sxrjxfjjc", 1)
		exe := windowsDesktopEngine(t, data, "2.1.317")
		var checked string
		stubWindowsEngineSignature(t, func(path string) codesig.Result {
			checked = path
			return signedAsFolder(path)
		})
		got, complete, err := windowsDesktopSurfaces(t, home)
		if err != nil || len(got) != 1 || !complete[0] || got[0].EngineVersion != "2.1.317" || checked != exe {
			t.Fatalf("%s (%s): surfaces = %+v complete=%v err=%v checked=%s", root.Path, root.Deployment, got, complete, err, checked)
		}
	}
	home := t.TempDir()
	f := claudedesktop.FoldersForHome("windows", home)
	windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc"), "2.1.309")
	windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-3p"), "2.1.317")
	stubWindowsEngineSignature(t, signedAsFolder)
	got, _, _ := windowsDesktopSurfaces(t, home)
	admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, got)
	if len(got) != 2 || len(admission.admitted) != 2 || admission.rowVersion("") != "2.1.309" {
		t.Fatalf("1p and 3p side by side: surfaces = %+v, row version %q", got, admission.rowVersion(""))
	}
}

// A newer unsigned build in another data folder does not hide a signed one:
// the signed 1p build is admitted, the unsigned 3p build is reported.
func TestDiscoverWindowsClaudeDesktopUnsignedBuildDoesNotHideASignedOne(t *testing.T) {
	home := t.TempDir()
	f := claudedesktop.FoldersForHome("windows", home)
	signed := windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc"), "2.1.309")
	windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-3p"), "2.1.330")
	stubWindowsEngineSignature(t, func(path string) codesig.Result {
		if path == signed {
			return signedAsFolder(path)
		}
		return codesig.Result{Reason: "claude.exe is not signed", Unsigned: true}
	})
	got, _, err := windowsDesktopSurfaces(t, home)
	admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, got)
	if err != nil || len(admission.admitted) != 1 || admission.admitted[0].EngineVersion != "2.1.309" || len(admission.rejected) != 1 ||
		!strings.HasPrefix(admission.rejected[0].surface.EngineUnverified, "Claude Desktop engine 2.1.330: claude.exe is not signed") {
		t.Fatalf("surfaces = %+v, admission = %+v, err = %v", got, admission, err)
	}
}

// Folders the user made in Claude-Data cannot hide the installed MSIX
// package's folder: its publisher id (Packages\Claude_<id>) is read first,
// and the overflow leaves that data root incomplete (a warning, no row
// version) while the scan reports the coverage as incomplete. Other data
// roots stay complete.
func TestDiscoverWindowsClaudeDesktopGlobOverflowIsIncomplete(t *testing.T) {
	home := t.TempDir()
	f := claudedesktop.FoldersForHome("windows", home)
	for i := 0; i < claudedesktop.MaxGlobMatches; i++ {
		if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Claude-Data", "claude_"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	genuine := windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-Data", "claude_pzs8sxrjxfjjc"), "2.1.317")
	windowsDesktopEngine(t, filepath.Join(f.LocalAppData, "Claude-3p"), "2.1.317")
	stubWindowsEngineSignature(t, signedAsFolder)
	got, complete, err := windowsDesktopSurfaces(t, home)
	if err == nil || !strings.Contains(err.Error(), "more Claude Desktop data folders match") || len(got) != 1 ||
		!strings.Contains(got[0].Path, "Claude-3p") || !complete[0] {
		t.Fatalf("without the package folder: surfaces = %+v complete=%v err=%v", got, complete, err)
	}
	if err := os.MkdirAll(filepath.Join(f.LocalAppData, "Packages", "Claude_pzs8sxrjxfjjc"), 0o755); err != nil {
		t.Fatal(err)
	}
	got, complete, err = windowsDesktopSurfaces(t, home)
	if err == nil || len(got) != 2 || got[0].Path != filepath.Dir(filepath.Dir(filepath.Dir(genuine))) || complete[0] ||
		!strings.Contains(got[1].Path, "Claude-3p") || !complete[1] {
		t.Fatalf("with the package folder: surfaces = %+v complete=%v err=%v", got, complete, err)
	}
}
