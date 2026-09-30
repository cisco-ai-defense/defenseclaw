// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"runtime"
	"strings"
	"testing"
)

func TestResolveEnterpriseProfile(t *testing.T) {
	cases := []struct {
		name, goos, mode, pinned, configured string
		want                                 string
		wantErr                              string
	}{
		{name: "unmanaged has no profile", goos: "linux", mode: "", want: ""},
		{name: "unmanaged rejects pin", goos: "linux", mode: "", pinned: "standalone", wantErr: "requires deployment_mode"},
		{name: "unmanaged rejects config", goos: "darwin", mode: "unmanaged_byod", configured: "standalone", wantErr: "requires deployment_mode"},
		{name: "windows defaults to secure client", goos: "windows", mode: "managed_enterprise", want: ProfileSecureClient},
		{name: "darwin defaults to secure client", goos: "darwin", mode: "managed_enterprise", want: ProfileSecureClient},
		{name: "linux defaults to standalone", goos: "linux", mode: "managed_enterprise", want: ProfileStandalone},
		{name: "linux rejects secure client", goos: "linux", mode: "managed_enterprise", configured: "secure_client", wantErr: "not available on Linux"},
		{name: "config selects standalone", goos: "windows", mode: "MANAGED_ENTERPRISE", configured: " Standalone ", want: ProfileStandalone},
		{name: "pin selects standalone", goos: "darwin", mode: "managed_enterprise", pinned: "standalone", want: ProfileStandalone},
		{name: "pin and config agree", goos: "windows", mode: "managed_enterprise", pinned: "standalone", configured: "standalone", want: ProfileStandalone},
		{name: "pin and config conflict", goos: "windows", mode: "managed_enterprise", pinned: "secure_client", configured: "standalone", wantErr: "conflicts with immutable"},
		{name: "unknown value", goos: "windows", mode: "managed_enterprise", configured: "saas", wantErr: "not a supported enterprise profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveEnterpriseProfile(tc.goos, tc.mode, tc.pinned, tc.configured)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("ResolveEnterpriseProfile() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEnterpriseProfile() unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("ResolveEnterpriseProfile() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStandaloneLayouts(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		layout, err := StandaloneLayoutFor(goos)
		if err != nil {
			t.Fatalf("StandaloneLayoutFor(%s): %v", goos, err)
		}
		if err := layout.Validate(); err != nil {
			t.Fatalf("%s layout invalid: %v", goos, err)
		}
		if strings.Contains(layout.InstallRoot, "secureclient") || strings.Contains(layout.LogDir, "SecureClient") {
			t.Fatalf("%s standalone layout must not live under Secure Client paths: %+v", goos, layout)
		}
		if layout.APIAddr != StandaloneAPIAddr {
			t.Fatalf("%s api addr = %q", goos, layout.APIAddr)
		}
	}
	if _, err := StandaloneLayoutFor("windows"); err == nil {
		t.Fatal("unix layout lookup must refuse windows")
	}
	win, err := StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData\`)
	if err != nil {
		t.Fatal(err)
	}
	if win.InstallRoot != `C:\Program Files\Cisco\DefenseClaw` || win.ConfigPath != `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml` {
		t.Fatalf("unexpected windows layout: %+v", win)
	}
	if err := win.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][2]string{{`Program Files`, `C:\ProgramData`}, {`C:/Program Files`, `C:\ProgramData`}, {`C:\Program Files`, ``}} {
		if _, err := StandaloneWindowsLayoutForRoots(bad[0], bad[1]); err == nil {
			t.Fatalf("expected rejection for %q", bad)
		}
	}
}

func TestRuntimeDescriptorRoundTrip(t *testing.T) {
	d := &RuntimeDescriptor{
		SchemaVersion:           RuntimeDescriptorSchemaVersion,
		Profile:                 ProfileStandalone,
		ProductVersion:          "1.0.0",
		ServiceUser:             "defenseclaw",
		ServiceUID:              995,
		ServiceGID:              985,
		APIAddr:                 StandaloneAPIAddr,
		HookSocket:              "/run/defenseclaw-hook/hook.sock",
		MachinePolicyConnectors: []string{"cursor", "codex", "claudecode"},
		DisableSelfUpdate:       true,
		InstalledAt:             "2026-09-26T00:00:00Z",
	}
	if runtime.GOOS == "windows" {
		// Only Linux and macOS have a hook socket, and this path is not
		// absolute on Windows.
		d.HookSocket = ""
	}
	data, err := MarshalRuntimeDescriptor(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"claudecode",`) || !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("descriptor not canonical: %s", data)
	}
	parsed, err := ParseRuntimeDescriptor(data)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.HasMachinePolicyConnector("Codex") || parsed.HasMachinePolicyConnector("copilot") {
		t.Fatalf("unexpected connector membership: %+v", parsed.MachinePolicyConnectors)
	}
	for name, raw := range map[string]string{
		"unknown field":  `{"schema_version":1,"profile":"standalone","service_user":"defenseclaw","api_addr":"127.0.0.1:18970","machine_policy_connectors":[],"token":"x"}`,
		"secure client":  `{"schema_version":1,"profile":"secure_client","service_user":"defenseclaw","api_addr":"127.0.0.1:18970","machine_policy_connectors":[]}`,
		"wrong address":  `{"schema_version":1,"profile":"standalone","service_user":"defenseclaw","api_addr":"0.0.0.0:18970","machine_policy_connectors":[]}`,
		"schema version": `{"schema_version":2,"profile":"standalone","service_user":"defenseclaw","api_addr":"127.0.0.1:18970","machine_policy_connectors":[]}`,
		"duplicate":      `{"schema_version":1,"profile":"standalone","service_user":"defenseclaw","api_addr":"127.0.0.1:18970","machine_policy_connectors":["codex","codex"]}`,
		"trailing data":  `{"schema_version":1,"profile":"standalone","service_user":"defenseclaw","api_addr":"127.0.0.1:18970","machine_policy_connectors":[]} {}`,
	} {
		if _, err := ParseRuntimeDescriptor([]byte(raw)); err == nil {
			t.Errorf("%s: expected ParseRuntimeDescriptor to fail", name)
		}
	}
}

func TestLoadRuntimeDescriptorMissingAndUntrusted(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadRuntimeDescriptor(dir + "/absent.json"); err != ErrNoRuntimeDescriptor {
		t.Fatalf("missing descriptor error = %v, want ErrNoRuntimeDescriptor", err)
	}
}
