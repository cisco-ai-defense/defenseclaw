// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestGAP0694GatewayExecutableNameNamesWindowsGateway(t *testing.T) {
	for _, tc := range []struct {
		path, goos string
		want       bool
	}{
		{"C:/Users/account/.local/bin/defenseclaw-gateway.exe", "windows", true},
		{"C:/Users/account/.local/bin/DefenseClaw-Gateway.EXE", "windows", true},
		{"C:/Users/account/.local/bin/defenseclaw-gateway", "windows", false},
		{"C:/Users/account/.local/bin/defenseclaw.exe", "windows", false},
		{"/home/account/.local/bin/defenseclaw-gateway", "linux", true},
		{"/home/account/.local/bin/defenseclaw-gateway.exe", "linux", false},
		{"/Users/account/.local/bin/Defenseclaw-Gateway", "darwin", false},
	} {
		if got := gatewayExecutableName(tc.path, tc.goos); got != tc.want {
			t.Errorf("gatewayExecutableName(%q, %s) = %v, want %v", tc.path, tc.goos, got, tc.want)
		}
	}
}

func TestGAP0705ForegroundLaunchHomeFollowsDefaultDataPath(t *testing.T) {
	// An absolute path is OS-specific: /home/account is relative on Windows.
	// The fixture is rooted in the temp dir, which is absolute on every OS.
	account := filepath.Join(t.TempDir(), "account")
	gatewayHome := filepath.Join(account, "gateway home")
	other := filepath.Join(t.TempDir(), "other")
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"explicit", []string{"HOME=" + account, "DEFENSECLAW_HOME=" + gatewayHome}, gatewayHome},
		{"default", []string{"PATH=/usr/bin", "HOME=" + account}, filepath.Join(account, config.DefaultDataDirName)},
		{"empty override", []string{"DEFENSECLAW_HOME=", "HOME=" + account}, filepath.Join(account, config.DefaultDataDirName)},
		{"duplicate home", []string{"HOME=" + account, "HOME=" + other}, ""},
		{"duplicate override", []string{"DEFENSECLAW_HOME=" + other, "DEFENSECLAW_HOME=" + other}, ""},
		{"relative override", []string{"DEFENSECLAW_HOME=relative", "HOME=" + account}, ""},
		{"relative home", []string{"HOME=relative"}, ""},
		{"no home", []string{"PATH=/usr/bin"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := foregroundLaunchHome(tc.env)
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("launch home = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
}

func TestGAP0694ForegroundLaunchHomeUsesTheWindowsProfile(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"default", []string{"USERPROFILE=" + profile, "HOME=/ignored"}, filepath.Join(profile, config.DefaultDataDirName)},
		{"explicit", []string{"USERPROFILE=" + profile, "DEFENSECLAW_HOME=" + profile}, profile},
		{"duplicate profile", []string{"USERPROFILE=" + profile, "USERPROFILE=" + profile}, ""},
		{"relative profile", []string{"USERPROFILE=relative"}, ""},
		{"only HOME", []string{"HOME=" + profile}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := foregroundLaunchHomeFrom(tc.env, "USERPROFILE")
			if got != tc.want || ok != (tc.want != "") {
				t.Fatalf("launch home = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
}
