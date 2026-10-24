// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func probeOK() VMProbeResult         { return VMProbeResult{OK: true} }
func probeNoKVM() VMProbeResult      { return VMProbeResult{Reason: DriverReasonKVMMissing} }
func probeKVMAccess() VMProbeResult  { return VMProbeResult{Reason: DriverReasonKVMAccess} }
func probeMustNotRun() VMProbeResult { panic("the probe must not run") }

func TestSelectDriver(t *testing.T) {
	for _, tc := range []struct {
		name, goos, driver, fallback string
		probe                        func() VMProbeResult
		want                         DriverChoice
		refused                      string
	}{
		{name: "auto with KVM is vm", goos: "linux", driver: "auto", fallback: "docker", probe: probeOK,
			want: DriverChoice{Driver: DriverVM, Reason: DriverReasonKVMAvailable}},
		{name: "auto without KVM is docker with the reason", goos: "linux", driver: "auto", fallback: "docker", probe: probeNoKVM,
			want: DriverChoice{Driver: DriverDocker, Reason: DriverReasonKVMMissing}},
		{name: "vm without KVM access falls back", goos: "linux", driver: "vm", fallback: "docker", probe: probeKVMAccess,
			want: DriverChoice{Driver: DriverDocker, Reason: DriverReasonKVMAccess}},
		{name: "vm with KVM is vm as configured", goos: "linux", driver: "vm", fallback: "docker", probe: probeOK,
			want: DriverChoice{Driver: DriverVM, Reason: DriverReasonConfigured}},
		{name: "vm and fallback none without KVM is refused", goos: "linux", driver: "vm", fallback: "none", probe: probeNoKVM,
			refused: DriverReasonKVMMissing},
		{name: "auto and a profile's none without KVM is refused", goos: "linux", driver: "auto", fallback: "none", probe: probeKVMAccess,
			refused: DriverReasonKVMAccess},
		{name: "docker never probes", goos: "linux", driver: "docker", fallback: "none", probe: probeMustNotRun,
			want: DriverChoice{Driver: DriverDocker, Reason: DriverReasonConfigured}},
		{name: "linux default is docker", goos: "linux", probe: probeMustNotRun,
			want: DriverChoice{Driver: DriverDocker, Reason: DriverReasonConfigured}},
		{name: "macOS is MicroVM only", goos: "darwin", driver: "auto", fallback: "docker", probe: probeMustNotRun,
			want: DriverChoice{Driver: DriverVM, Reason: DriverReasonConfigured}},
		{name: "macOS default is vm", goos: "darwin", probe: probeMustNotRun,
			want: DriverChoice{Driver: DriverVM, Reason: DriverReasonConfigured}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SelectDriver(tc.goos, tc.driver, tc.fallback, tc.probe)
			if tc.refused != "" {
				var refusal *DriverUnavailableError
				if !errors.As(err, &refusal) || refusal.Reason != tc.refused || !errors.Is(err, ErrDriverUnavailable) {
					t.Fatalf("err = %v, want a refusal for %s", err, tc.refused)
				}
				if want := "your organization requires MicroVM sandboxes, and " + DriverReasonText(tc.refused); err.Error() != want {
					t.Fatalf("refusal text %q, want %q", err.Error(), want)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("SelectDriver = %+v, %v; want %+v", got, err, tc.want)
			}
			if got.Fallback() != IsFallbackReason(tc.want.Reason) {
				t.Fatalf("Fallback() = %t", got.Fallback())
			}
		})
	}
	if _, err := SelectDriver("linux", "podman", "", probeOK); err == nil {
		t.Fatal("an unknown driver was accepted")
	}
}

func TestDriverChoiceText(t *testing.T) {
	for _, tc := range []struct{ driver, reason, want string }{
		{"docker", DriverReasonKVMMissing, "docker (fallback: KVM not available on this computer)"},
		{"docker", DriverReasonKVMAccess, "docker (fallback: KVM not available for your account on this computer: /dev/kvm must be readable and writable for your account)"},
		{"vm", DriverReasonKVMAvailable, "vm (KVM is available on this computer)"},
		{"vm", DriverReasonConfigured, "vm"},
		{"docker", "", "docker"},
		{"", DriverReasonKVMMissing, ""},
	} {
		if got := DriverChoiceText(tc.driver, tc.reason); got != tc.want {
			t.Errorf("DriverChoiceText(%q, %q) = %q, want %q", tc.driver, tc.reason, got, tc.want)
		}
	}
	for _, r := range DriverReasons {
		if DriverReasonText(r) == "" || !ValidDriverReason(r) {
			t.Errorf("reason %q has no text", r)
		}
	}
}

func TestVMProbe(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the VM driver runs on Linux and macOS only; its probe reads POSIX host paths")
	}
	dir := t.TempDir()
	withFlags := filepath.Join(dir, "cpuinfo-vmx")
	noFlags := filepath.Join(dir, "cpuinfo-none")
	if err := os.WriteFile(withFlags, []byte("processor\t: 0\nflags\t\t: fpu vme vmx sse\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(noFlags, []byte("processor\t: 0\nflags\t\t: fpu vme sse\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	drivers := filepath.Join(dir, "libexec")
	if err := os.MkdirAll(drivers, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(drivers, vmDriverBinary), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	access := func(exists, ok bool) func(string) (bool, bool) {
		return func(string) (bool, bool) { return exists, ok }
	}
	for _, tc := range []struct {
		name string
		p    VMProbe
		want VMProbeResult
	}{
		{"all there", VMProbe{GOARCH: "amd64", CPUInfoPath: withFlags, Access: access(true, true), DriverDirs: []string{drivers}}, VMProbeResult{OK: true}},
		{"no CPU virtualization", VMProbe{GOARCH: "amd64", CPUInfoPath: noFlags, Access: access(true, true)}, VMProbeResult{Reason: DriverReasonCPUVirtualization}},
		{"arm64 reads no x86 flags", VMProbe{GOARCH: "arm64", CPUInfoPath: noFlags, Access: access(true, true)}, VMProbeResult{OK: true}},
		{"no device", VMProbe{GOARCH: "amd64", CPUInfoPath: withFlags, Access: access(false, false)}, VMProbeResult{Reason: DriverReasonKVMMissing}},
		{"device not read-write", VMProbe{GOARCH: "amd64", CPUInfoPath: withFlags, Access: access(true, false)}, VMProbeResult{Reason: DriverReasonKVMAccess}},
		{"no driver binary", VMProbe{GOARCH: "amd64", CPUInfoPath: withFlags, Access: access(true, true), DriverDirs: []string{dir}}, VMProbeResult{Reason: DriverReasonVMDriverMissing}},
		{"real open of a missing device", VMProbe{GOARCH: "amd64", CPUInfoPath: withFlags, DevicePath: filepath.Join(dir, "kvm")}, VMProbeResult{Reason: DriverReasonKVMMissing}},
	} {
		if got := tc.p.Run(); got != tc.want {
			t.Errorf("%s: %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestUserVMDriverDirsRespectsExplicitDriverDir(t *testing.T) {
	home := t.TempDir()
	defaultDriver := filepath.Join(home, ".local", "libexec", "openshell", vmDriverBinary)
	if err := os.MkdirAll(filepath.Dir(defaultDriver), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(defaultDriver, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	configured := filepath.Join(home, "configured")
	dirs := UserVMDriverDirs(home, configured)
	if len(dirs) != 1 || dirs[0] != configured || FindVMDriverIn(dirs) != "" {
		t.Fatalf("explicit driver_dir lacks a driver but probe searches %v", dirs)
	}
}
