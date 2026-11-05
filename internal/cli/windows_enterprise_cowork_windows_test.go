// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestWindowsCoworkNativeArchitecture(t *testing.T) {
	original := windowsEnterpriseNativeMachine
	t.Cleanup(func() { windowsEnterpriseNativeMachine = original })
	// Windows standalone is native x64 only: ARM64 has no Cowork package.
	for machine, want := range map[uint16]string{0x8664: "amd64", 0xaa64: "", 0x14c: ""} {
		windowsEnterpriseNativeMachine = func() (uint16, error) { return machine, nil }
		got, err := windowsCoworkArchitecture()
		if got != want || (err != nil) != (want == "") {
			t.Fatalf("machine=%x got=%q err=%v", machine, got, err)
		}
	}
	windowsEnterpriseNativeMachine = func() (uint16, error) { return 0, errors.New("probe failed") }
	if _, err := windowsCoworkArchitecture(); err == nil {
		t.Fatal("architecture probe failure accepted")
	}
}

func TestWindowsCoworkDeliveryPlanPinsAndArchitecture(t *testing.T) {
	const dir = `C:\Program Files\Claude\edr-integration`
	const record = `C:\ProgramData\Cisco\DefenseClaw\install\cowork-host.json`
	cache := filepath.Join(filepath.Dir(record), "cowork-cache")
	pin := strings.Repeat("a", 64)
	sigPin := strings.Repeat("b", 64)
	for _, tc := range []struct {
		name, arch, input, sigInput, pkgDigest, sigDigest, errorText string
		signed, missingSig, staleSignature                           bool
	}{
		{name: "amd64 selects x64 VM package", arch: "amd64", pkgDigest: pin},
		{name: "package mismatch refused", arch: "amd64", pkgDigest: strings.Repeat("c", 64), errorText: "package_sha256"},
		{name: "signature mismatch refused", arch: "amd64", pkgDigest: pin, signed: true, sigDigest: strings.Repeat("c", 64), errorText: "signature_sha256"},
		{name: "pinned signature missing refused", arch: "amd64", pkgDigest: pin, signed: true, missingSig: true, errorText: "pinned but missing"},
		{name: "canonical explicit package cached", arch: "amd64", input: `C:\Stage\defenseclaw-cowork-amd64.tar.gz`, pkgDigest: pin},
		{name: "unsigned explicit input refuses unowned stale cache signature", arch: "amd64", input: `C:\Stage\defenseclaw-cowork-amd64.tar.gz`, pkgDigest: pin, staleSignature: true, errorText: "unowned or changed cache signature"},
		{name: "wrong architecture cannot be relabeled", arch: "amd64", input: `C:\Stage\defenseclaw-cowork-arm64.tar.gz`, pkgDigest: pin, errorText: "must be named defenseclaw-cowork-amd64"},
		{name: "signature only uses cached package", arch: "amd64", sigInput: `C:\Stage\release.sig`, pkgDigest: pin, signed: true, sigDigest: sigPin},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone, CoworkVMSensor: config.EnterpriseCoworkVMSensorConfig{Mode: "on", Tenant: "tenant", Device: "device", Collector: "collector.example:443", Vendor: "cisco", SourceDir: cache, PackageSHA256: pin}}}
			if tc.signed {
				c.Enterprise.CoworkVMSensor.SignatureSHA256 = sigPin
			}
			var inspected []string
			ops := windowsCoworkPlanOps{
				paths:        func() (string, string, error) { return dir, record, nil },
				architecture: func() (string, error) { return tc.arch, nil },
				ownership:    func(string, string) (windowsCoworkOwnership, error) { return windowsCoworkOwnership{}, nil },
				settings: func(enterprisepolicy.Options, string, string, []enterprisepolicy.RegValue) (bool, string, error) {
					return false, "", nil
				},
				digest: func(path string, _ int64) (string, error) {
					inspected = append(inspected, path)
					if strings.HasSuffix(path, ".sig") {
						return tc.sigDigest, nil
					}
					return tc.pkgDigest, nil
				},
				stat: func(string) (os.FileInfo, error) {
					if tc.missingSig || (!tc.signed && !tc.staleSignature) {
						return nil, os.ErrNotExist
					}
					return nil, nil
				},
				device: func() (string, error) { t.Fatal("explicit device must not probe MachineGuid"); return "", nil },
			}
			plan, err := buildWindowsCoworkPlanWith(c, true, ops, tc.input, tc.sigInput)
			if tc.errorText != "" {
				if err == nil || !strings.Contains(err.Error(), tc.errorText) {
					t.Fatalf("plan=%+v err=%v", plan, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.PackagePath != filepath.Join(dir, "defenseclaw-cowork-"+tc.arch+".tar.gz") || plan.ArgumentsPath != filepath.Join(dir, "install.args") || plan.Arguments != "tenant=tenant,device=device,collector=collector.example:443" {
				t.Fatalf("plan=%+v", plan)
			}
			if tc.input != "" || tc.sigInput != "" {
				if plan.CacheDirectory != cache {
					t.Fatalf("cache=%q", plan.CacheDirectory)
				}
			}
			if tc.sigInput != "" && inspected[0] != filepath.Join(cache, "defenseclaw-cowork-amd64.tar.gz") {
				t.Fatalf("signature-only package source=%q", inspected[0])
			}
		})
	}
}

func TestWindowsCoworkOffHasNoHostProbes(t *testing.T) {
	c := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	// Nil ops panic if the off path touches assets, registry or the host.
	if plan, err := buildWindowsCoworkPlanWith(c, true, windowsCoworkPlanOps{}); err != nil || plan.Enabled {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	if _, err := buildWindowsCoworkPlanWith(c, true, windowsCoworkPlanOps{}, `C:\Stage\defenseclaw-cowork-amd64.tar.gz`); err == nil {
		t.Fatal("off ignored an explicit artifact")
	}
	for _, path := range []string{`C:\Program Files\Claude\edr-integration\defenseclaw-cowork-arm64.tar.gz`, `C:\Program Files\Claude\edr-integration\other.txt`, `C:\Program Files\Claude\edr-integration\sub\install.args`, `C:\Users\dcadmin\install.args`} {
		if windowsCoworkOwnedPath(path, `C:\Program Files\Claude\edr-integration`) {
			t.Fatalf("foreign path accepted: %s", path)
		}
	}
}

// A compliant ensure repairs Cowork VM delivery drift, except the states
// repair cannot change: an unpinned signature, an HKLM refusal (merge mode
// or an administrator-owned value) and a host that could not be inspected.
func TestWindowsCoworkEnsureDriftChoosesRepairOnlyWhenRepairCanFix(t *testing.T) {
	pinned := windowsCoworkPlan{Enabled: true, PackagePath: `C:\Program Files\Claude\edr-integration\defenseclaw-cowork-amd64.tar.gz`,
		PackageSHA256: strings.Repeat("a", 64), SignatureSHA256: strings.Repeat("b", 64)}
	state := func(host, settings bool, codes ...string) *enterprisestatus.CoworkVMSensorState {
		return &enterprisestatus.CoworkVMSensorState{Enabled: true, HostReady: host, SettingsReady: settings, ReasonCodes: codes}
	}
	for _, tc := range []struct {
		name  string
		state *enterprisestatus.CoworkVMSensorState
		plan  func(windowsCoworkPlan) windowsCoworkPlan
		want  string
	}{
		{name: "secure client or no config", state: nil},
		{name: "off", state: &enterprisestatus.CoworkVMSensorState{}},
		{name: "ready", state: state(true, true)},
		{name: "deleted package", state: state(false, true, "package_or_signature_not_ready"), want: "drift:cowork_vm_sensor"},
		{name: "changed install.args", state: state(false, true, "arguments_not_ready"), want: "drift:cowork_vm_sensor"},
		{name: "removed HKLM values", state: state(true, false, "machine_settings_not_ready"), want: "drift:cowork_vm_sensor"},
		{name: "unpinned signature", state: state(false, true, "package_or_signature_not_ready"),
			plan: func(p windowsCoworkPlan) windowsCoworkPlan { p.SignatureSHA256 = ""; return p }},
		{name: "HKLM refusal", state: state(true, false, "machine_settings_not_ready"),
			plan: func(p windowsCoworkPlan) windowsCoworkPlan {
				p.RegistryRefusal = "HKLM\\SOFTWARE\\Policies\\Claude\\coworkEDRIntegration is administrator-owned"
				return p
			}},
		{name: "folder ACL drift", state: state(false, true, "destination_permissions_not_ready"), want: "drift:cowork_vm_sensor"},
		{name: "untrusted destination", state: state(false, true, "destination_permissions_not_ready", "destination_untrusted")},
		{name: "host inspection failed", state: state(false, false, "host_inspection_failed"),
			plan: func(windowsCoworkPlan) windowsCoworkPlan { return windowsCoworkPlan{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := pinned
			if tc.plan != nil {
				p = tc.plan(p)
			}
			reason, detail := windowsCoworkDriftReason(tc.state, p)
			if reason != tc.want || (reason != "" && !strings.Contains(detail, tc.state.ReasonCodes[0])) {
				t.Fatalf("reason=%q detail=%q, want %q", reason, detail, tc.want)
			}
		})
	}
}

// A fleet-wide config without device gives each host its MachineGuid; a
// host whose ID cannot be read refuses delivery.
func TestWindowsCoworkDeviceDerivedFromMachineGUID(t *testing.T) {
	pin := strings.Repeat("a", 64)
	c := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone, CoworkVMSensor: config.EnterpriseCoworkVMSensorConfig{Mode: "on", Tenant: "tenant", Collector: "collector.example:443", Vendor: "cisco", SourceDir: `C:\Stage`, PackageSHA256: pin}}}
	device := func() (string, error) { return config.NormalizeCoworkDeviceID("6f1c2a9e-3b7d-4e1f-9a2b-0c8d7e6f5a4b") }
	ops := windowsCoworkPlanOps{
		paths: func() (string, string, error) {
			return `C:\Program Files\Claude\edr-integration`, `C:\ProgramData\Cisco\DefenseClaw\install\cowork-host.json`, nil
		},
		architecture: func() (string, error) { return "amd64", nil },
		ownership:    func(string, string) (windowsCoworkOwnership, error) { return windowsCoworkOwnership{}, nil },
		settings: func(enterprisepolicy.Options, string, string, []enterprisepolicy.RegValue) (bool, string, error) {
			return false, "", nil
		},
		digest: func(string, int64) (string, error) { return pin, nil },
		stat:   func(string) (os.FileInfo, error) { return nil, os.ErrNotExist },
		device: func() (string, error) { return device() },
	}
	plan, err := buildWindowsCoworkPlanWith(c, true, ops)
	if err != nil || plan.Arguments != "tenant=tenant,device=6f1c2a9e-3b7d-4e1f-9a2b-0c8d7e6f5a4b,collector=collector.example:443" {
		t.Fatalf("plan=%+v err=%v", plan, err)
	}
	device = func() (string, error) { return "", errors.New("no MachineGuid") }
	if _, err := buildWindowsCoworkPlanWith(c, true, ops); err == nil {
		t.Fatal("delivery without a device ID was accepted")
	}
	c.Enterprise.CoworkVMSensor.Device = "override-1"
	if plan, err := buildWindowsCoworkPlanWith(c, true, ops); err != nil || !strings.Contains(plan.Arguments, "device=override-1,") {
		t.Fatalf("explicit device did not override: %+v %v", plan, err)
	}
}

// The real MachineGuid read (64-bit view) gives a usable device ID on this
// host; the injected-device test above covers the plan.
func TestWindowsCoworkMachineGUIDReadsTheHost(t *testing.T) {
	id, err := windowsCoworkMachineGUID()
	if err != nil {
		t.Fatalf("MachineGuid: %v", err)
	}
	if normalized, err := config.NormalizeCoworkDeviceID(id); err != nil || normalized != id || len(id) < 32 {
		t.Fatalf("MachineGuid device ID %q (normalized %q, %v)", id, normalized, err)
	}
}
