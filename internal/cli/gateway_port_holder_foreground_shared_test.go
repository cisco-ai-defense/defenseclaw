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
	for _, tc := range []struct {
		name string
		env  []string
		want string
	}{
		{"explicit", []string{"HOME=/home/account", "DEFENSECLAW_HOME=/home/account/gateway home"}, "/home/account/gateway home"},
		{"default", []string{"PATH=/usr/bin", "HOME=/home/account"}, filepath.Join("/home/account", config.DefaultDataDirName)},
		{"empty override", []string{"DEFENSECLAW_HOME=", "HOME=/home/account"}, filepath.Join("/home/account", config.DefaultDataDirName)},
		{"duplicate home", []string{"HOME=/home/account", "HOME=/home/other"}, ""},
		{"duplicate override", []string{"DEFENSECLAW_HOME=/a", "DEFENSECLAW_HOME=/a"}, ""},
		{"relative override", []string{"DEFENSECLAW_HOME=relative", "HOME=/home/account"}, ""},
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
