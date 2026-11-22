// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0751: machine policy written now names the launch image on Windows;
// the pure HookBinaryPath (read-only and ownership checks, the hook process)
// stays the transition image and reads no image.
func TestStandaloneOptionsNameTheLaunchImageOnWindows(t *testing.T) {
	layout, err := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if err != nil {
		t.Fatal(err)
	}
	launch := layout.BinDir + `\hooks\0123456789abcdef\defenseclaw-hook.exe`
	var asked []string
	previous := windowsHookLaunchPath
	windowsHookLaunchPath = func(bin string) string {
		asked = append(asked, bin)
		return launch
	}
	t.Cleanup(func() { windowsHookLaunchPath = previous })

	fixed := HookBinaryPath(layout)
	if fixed != layout.BinDir+`\defenseclaw-hook.exe` {
		t.Fatalf("HookBinaryPath = %q", fixed)
	}
	if got := LayoutOptions(layout, `C:\Program Files`, `C:\ProgramData`).HookBinary; got != fixed {
		t.Fatalf("LayoutOptions.HookBinary = %q; read-only options keep the transition image", got)
	}
	if len(asked) != 0 {
		t.Fatalf("pure paths resolved the launch image %v", asked)
	}
	if got := HookLaunchBinaryPath(layout); got != launch {
		t.Fatalf("HookLaunchBinaryPath = %q", got)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	opts, err := StandaloneOptions(layout, `C:\Program Files`, `C:\ProgramData`, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if opts.HookBinary != launch {
		t.Fatalf("StandaloneOptions.HookBinary = %q, want the launch image", opts.HookBinary)
	}
}

func TestHookLaunchBinaryPathIsHookBinaryPathOffWindows(t *testing.T) {
	previous := windowsHookLaunchPath
	windowsHookLaunchPath = func(string) string { t.Fatal("resolved a Windows image for a Unix layout"); return "" }
	t.Cleanup(func() { windowsHookLaunchPath = previous })
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatal(err)
		}
		if got := HookLaunchBinaryPath(layout); got != HookBinaryPath(layout) {
			t.Fatalf("%s: HookLaunchBinaryPath = %q, want %q", goos, got, HookBinaryPath(layout))
		}
	}
}
