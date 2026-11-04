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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// desktopEngineBundle lays out Claude Desktop's macOS engine build under
// home: claude-code/<version>/<build>/claude.app with an XML Info.plist.
func desktopEngineBundle(t *testing.T, home, version, plistVersion string) string {
	t.Helper()
	return desktopEngineBundleIn(t, home, "Claude", version, plistVersion)
}

// desktopEngineBundleIn is desktopEngineBundle in the data folder named
// folder (Claude, Claude-3p).
func desktopEngineBundleIn(t *testing.T, home, folder, version, plistVersion string) string {
	t.Helper()
	bundle := filepath.Join(home, "Library", "Application Support", folder, "claude-code", version, "5af865b9901c", "claude.app")
	if err := os.MkdirAll(filepath.Join(bundle, "Contents", "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "Contents", "MacOS", "claude"), []byte("engine"), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleShortVersionString</key><string>` + plistVersion + `</string></dict></plist>`
	if err := os.WriteFile(filepath.Join(bundle, "Contents", "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	return bundle
}

func discoverDesktopAs(t *testing.T, goos string, verify func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result, home string) []connector.AgentSurface {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("surface discovery runs only in the per-user worker, never as root")
	}
	origGOOS, origVerify := unixSurfaceGOOS, verifyUnixDesktopBundle
	unixSurfaceGOOS, verifyUnixDesktopBundle = goos, verify
	t.Cleanup(func() { unixSurfaceGOOS, verifyUnixDesktopBundle = origGOOS, origVerify })
	surfaces, _ := DiscoverUnixAgentSurfaces(context.Background(), home, "claudecode", false)
	var desktop []connector.AgentSurface
	for _, surface := range surfaces {
		if surface.Host == "claude-desktop" {
			desktop = append(desktop, surface)
		}
	}
	return desktop
}

func TestDiscoverClaudeDesktopEngineTrustsTheSignature(t *testing.T) {
	home := t.TempDir()
	bundle := desktopEngineBundle(t, home, "2.1.309", "2.1.309")
	desktopEngineBundle(t, home, "2.1.295", "2.1.295")
	var checked []string
	var pins []string
	signed := func(_ context.Context, path string, want codesig.Darwin, opts codesig.DarwinOptions) codesig.Result {
		checked, pins = append(checked, path), opts.Pin
		if want != codesig.ClaudeCodeDarwin {
			t.Fatalf("checked for %+v", want)
		}
		return codesig.Result{Verified: true}
	}
	got := discoverDesktopAs(t, "darwin", signed, home)
	if len(got) != 1 || got[0].EngineVersion != "2.1.309" || got[0].EngineUnverified != "" || got[0].Surface != connector.HostSurfaceDesktop {
		t.Fatalf("signed engine surfaces = %+v", got)
	}
	if len(checked) != 1 || checked[0] != bundle || len(pins) != 2 || !strings.HasSuffix(pins[0], "/Contents/MacOS/claude") {
		t.Fatalf("signature checks = %q pins %q, want only the newest build %s", checked, pins, bundle)
	}
	unsigned := func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
		return codesig.Result{Reason: "code object is not signed at all"}
	}
	got = discoverDesktopAs(t, "darwin", unsigned, home)
	if len(got) != 1 || got[0].EngineVersion != "" || got[0].EngineUnverified != "Claude Desktop engine 2.1.309: code object is not signed at all" {
		t.Fatalf("unsigned engine surfaces = %+v", got)
	}
	admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, got)
	if len(admission.admitted) != 0 || len(admission.rejected) != 1 ||
		admission.rejected[0].reason != "the engine build was not identified: Claude Desktop engine 2.1.309: code object is not signed at all" {
		t.Fatalf("unsigned engine admission = %+v", admission)
	}
}

func TestDiscoverClaudeDesktopEngineRefusesARenamedVersionFolder(t *testing.T) {
	home := t.TempDir()
	desktopEngineBundle(t, home, "2.1.309", "2.0.77")
	calls := 0
	got := discoverDesktopAs(t, "darwin", func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
		calls++
		return codesig.Result{Verified: true}
	}, home)
	if len(got) != 1 || got[0].EngineVersion != "" || !strings.Contains(got[0].EngineUnverified, `Info.plist names "2.0.77"`) || calls != 0 {
		t.Fatalf("renamed folder surfaces = %+v (signature checks %d)", got, calls)
	}
	empty := t.TempDir()
	if err := os.MkdirAll(filepath.Join(empty, "Library", "Application Support", "Claude", "claude-code", "2.1.309"), 0o755); err != nil {
		t.Fatal(err)
	}
	got = discoverDesktopAs(t, "darwin", func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
		return codesig.Result{Verified: true}
	}, empty)
	if len(got) != 1 || got[0].EngineVersion != "" || !strings.Contains(got[0].EngineUnverified, "no claude.app engine bundle") {
		t.Fatalf("empty version folder surfaces = %+v", got)
	}
}

// linuxDesktopEngine lays out a Linux engine build:
// <data>/claude-code/<version>/<build>/claude, executable.
func linuxDesktopEngine(t *testing.T, home, folder, version string) {
	t.Helper()
	dir := filepath.Join(home, ".config", folder, "claude-code", version, "a33aa5518497")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "claude"), []byte("ELF"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func noLinuxSignatureCheck(t *testing.T) func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
	return func(context.Context, string, codesig.Darwin, codesig.DarwinOptions) codesig.Result {
		t.Fatal("a Linux engine was signature-checked")
		return codesig.Result{}
	}
}

// Linux builds carry no vendor signature: a version folder alone is no
// engine build; with an executable engine its folder name is the version
// (the build is still unsigned: status says so).
func TestDiscoverClaudeDesktopLinuxEngineNeedsAnExecutable(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "Claude", "claude-code", "2.1.309"), 0o755); err != nil {
		t.Fatal(err)
	}
	got := discoverDesktopAs(t, "linux", noLinuxSignatureCheck(t), home)
	if len(got) != 1 || got[0].EngineVersion != "" || !strings.Contains(got[0].EngineUnverified, "no executable claude engine") {
		t.Fatalf("Linux version folder without an engine = %+v", got)
	}
	linuxDesktopEngine(t, home, "Claude", "2.1.309")
	got = discoverDesktopAs(t, "linux", noLinuxSignatureCheck(t), home)
	if len(got) != 1 || got[0].EngineVersion != "2.1.309" || got[0].EngineUnverified != "" {
		t.Fatalf("Linux engine surfaces = %+v", got)
	}
}

// The desktop surface of Claude Code follows the engine version Claude
// Desktop ships: 2.1.309 resolves a known contract and is admitted under
// report; it is not on the live-verified list yet (the real
// defenseclaw-hook in Cowork is a live cell of the 1.0.8 round), so
// unverified_versions: refuse still refuses it.
func TestClaudeDesktopSurfaceFollowsTheShippedEngine(t *testing.T) {
	surface := connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", EngineVersion: "2.1.309"}
	if admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, []connector.AgentSurface{surface}); len(admission.admitted) != 1 || admission.version != "2.1.309" {
		t.Fatalf("report admission = %+v", admission)
	}
	if admission := admitSurfaces("claudecode", connector.UnverifiedVersionsRefuse, []connector.AgentSurface{surface}); len(admission.admitted) != 0 {
		t.Fatalf("refuse admission = %+v", admission)
	}
	newer := surface
	newer.EngineVersion = "2.9.0"
	if admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, []connector.AgentSurface{newer}); len(admission.admitted) != 1 {
		t.Fatalf("a newer engine was not followed: %+v", admission)
	}
}

func TestValidUnixAgentSurfaceBoundsTheUnverifiedReason(t *testing.T) {
	base := connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", Path: "/Users/alice/Library/Application Support/Claude/claude-code"}
	ok := base
	ok.EngineUnverified = "code object is not signed at all"
	if _, valid := ValidUnixAgentSurface(ok); !valid {
		t.Fatal("a plain reason was refused")
	}
	for _, reason := range []string{"line\nbreak", strings.Repeat("x", engineUnverifiedReasonMax+1)} {
		bad := base
		bad.EngineUnverified = reason
		if _, valid := ValidUnixAgentSurface(bad); valid {
			t.Fatalf("reason %q accepted", reason)
		}
	}
	both := ok
	both.EngineVersion = "2.1.309"
	if _, valid := ValidUnixAgentSurface(both); valid {
		t.Fatal("a version next to an unverified reason was accepted")
	}
}

// Each data folder (Claude, and Claude-3p on third-party inference) is a
// surface of its own, with its newest build that verifies: both signed
// builds are admitted and the row follows the older, so its hooks work for
// both (cowork-1-0-8 GAP-0024).
func TestDiscoverClaudeDesktopEngineInEveryDataRoot(t *testing.T) {
	home := t.TempDir()
	firstParty := desktopEngineBundleIn(t, home, "Claude", "2.1.309", "2.1.309")
	thirdParty := desktopEngineBundleIn(t, home, "Claude-3p", "2.1.317", "2.1.317")
	var checked []string
	got := discoverDesktopAs(t, "darwin", func(_ context.Context, path string, _ codesig.Darwin, _ codesig.DarwinOptions) codesig.Result {
		checked = append(checked, path)
		return codesig.Result{Verified: true}
	}, home)
	if len(got) != 2 || got[0].EngineVersion != "2.1.309" || strings.Contains(got[0].Path, "Claude-3p") ||
		got[1].EngineVersion != "2.1.317" || !strings.Contains(got[1].Path, "Claude-3p") ||
		strings.Join(checked, "|") != firstParty+"|"+thirdParty {
		t.Fatalf("surfaces = %+v, signature checks %q", got, checked)
	}
	admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, got)
	if len(admission.admitted) != 2 || admission.rowVersion("") != "2.1.309" {
		t.Fatalf("admission = %+v, row version %q", admission, admission.rowVersion(""))
	}
	// Only a 3p install: no first-party folder at all.
	only := t.TempDir()
	linuxDesktopEngine(t, only, "Claude-3p", "2.1.317")
	got = discoverDesktopAs(t, "linux", noLinuxSignatureCheck(t), only)
	if len(got) != 1 || got[0].EngineVersion != "2.1.317" || !strings.Contains(got[0].Path, "Claude-3p") {
		t.Fatalf("Linux 3p surfaces = %+v", got)
	}
}

// A newer unsigned or half-written build, in another data folder or in the
// same one, does not hide a signed build: the signed build is admitted, and
// the unsigned one is reported as a rejected surface of its own.
func TestDiscoverClaudeDesktopUnsignedBuildDoesNotHideASignedOne(t *testing.T) {
	home := t.TempDir()
	signed := desktopEngineBundleIn(t, home, "Claude", "2.1.309", "2.1.309")
	unsigned := desktopEngineBundleIn(t, home, "Claude-3p", "2.1.330", "2.1.330")
	// A half-downloaded folder above the signed build in the same folder.
	if err := os.MkdirAll(filepath.Join(home, "Library", "Application Support", "Claude", "claude-code", "2.1.320"), 0o755); err != nil {
		t.Fatal(err)
	}
	verify := func(_ context.Context, path string, _ codesig.Darwin, _ codesig.DarwinOptions) codesig.Result {
		if path == signed {
			return codesig.Result{Verified: true}
		}
		return codesig.Result{Reason: "code object is not signed at all", Unsigned: true}
	}
	got := discoverDesktopAs(t, "darwin", verify, home)
	admission := admitSurfaces("claudecode", connector.UnverifiedVersionsReport, got)
	if len(admission.admitted) != 1 || admission.admitted[0].EngineVersion != "2.1.309" || admission.rowVersion("") != "2.1.309" {
		t.Fatalf("surfaces = %+v, admission = %+v", got, admission)
	}
	var reasons []string
	for _, rejected := range admission.rejected {
		reasons = append(reasons, rejected.surface.EngineUnverified)
	}
	if len(reasons) != 2 || !strings.HasPrefix(reasons[0], "Claude Desktop engine 2.1.320: no claude.app engine bundle") ||
		reasons[1] != "Claude Desktop engine 2.1.330: code object is not signed at all" || !strings.HasPrefix(unsigned, home) {
		t.Fatalf("rejected = %q", reasons)
	}
}
