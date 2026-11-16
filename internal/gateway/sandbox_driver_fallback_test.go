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

//go:build !windows

package gateway

import (
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// devices answers the probe's file access: kvm and docker are each
// missing, denied or usable for the account.
func devices(kvm, docker string) func(string, int) sandboxDeviceAccess {
	state := func(s string) sandboxDeviceAccess {
		switch s {
		case "ok":
			return sandboxDeviceAccess{State: sandboxDeviceUsable}
		case "denied":
			return sandboxDeviceAccess{State: sandboxDeviceDenied}
		case "kvm group", "docker group":
			return sandboxDeviceAccess{State: sandboxDeviceNotMember, Group: strings.TrimSuffix(s, " group")}
		case "unknown":
			return sandboxDeviceAccess{State: sandboxDeviceGroupsUnknown}
		}
		return sandboxDeviceAccess{State: sandboxDeviceMissing}
	}
	return func(path string, _ int) sandboxDeviceAccess {
		if path == sandboxKVMDevicePath {
			return state(kvm)
		}
		return state(docker)
	}
}

// The Linux docker fallback (owner decision 2026-10-10): auto and vm fall
// back to docker where KVM does not work for the account, with the same
// docker checks; driver_fallback: none, on the host or in the account's
// profile, refuses instead.
func TestSandboxAvailabilityDriverFallback(t *testing.T) {
	cpu := filepath.Join(t.TempDir(), "cpuinfo")
	if err := os.WriteFile(cpu, []byte("flags\t: fpu vmx sse\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	noVirt := filepath.Join(t.TempDir(), "cpuinfo")
	if err := os.WriteFile(noVirt, []byte("flags\t: fpu sse\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := func(driver, fallback string) *config.Config {
		cfg := &config.Config{}
		cfg.OpenShell.Enabled = true
		cfg.Enterprise.OpenShell.Driver, cfg.Enterprise.OpenShell.DriverFallback = driver, fallback
		return cfg
	}
	none := config.OpenShellAdminConfig{DriverFallback: "none"}
	for name, tc := range map[string]struct {
		cfg         *config.Config
		floor       config.OpenShellAdminConfig
		kvm, docker string
		cpuinfo     string
		want        sandboxAvailability
	}{
		"auto with KVM is vm": {host("auto", ""), config.OpenShellAdminConfig{}, "ok", "ok", cpu,
			sandboxAvailability{Available: true, Driver: "vm", DriverReason: "kvm_available"}},
		"auto without KVM is docker with the reason": {host("auto", ""), config.OpenShellAdminConfig{}, "missing", "ok", cpu,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "kvm_missing"}},
		"vm without KVM access falls back": {host("vm", "docker"), config.OpenShellAdminConfig{}, "denied", "ok", cpu,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "kvm_access"}},
		"a CPU without virtualization falls back": {host("vm", ""), config.OpenShellAdminConfig{}, "ok", "ok", noVirt,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "cpu_virtualization"}},
		// GAP-0462: where neither driver runs, both causes are named.
		"the fallback needs docker access": {host("auto", ""), config.OpenShellAdminConfig{}, "missing", "denied", cpu,
			sandboxAvailability{Code: "no_docker_access",
				Why: "KVM not available on this computer; and the Docker fallback can't run either: the Docker socket isn't read-write for your account"}},
		"unusable KVM and no docker group": {host("vm", "docker"), config.OpenShellAdminConfig{}, "denied", "docker group", cpu,
			sandboxAvailability{Code: "no_docker_group",
				Why: "KVM not available for your account on this computer: /dev/kvm must be readable and writable for your account; and the Docker fallback can't run either: your account isn't in the docker group that can use Docker"}},
		"no kvm group and no docker group": {host("auto", ""), config.OpenShellAdminConfig{}, "kvm group", "docker group", cpu,
			sandboxAvailability{Code: "no_docker_group",
				Why: "your account isn't in the kvm group that can use /dev/kvm; and the Docker fallback can't run either: your account isn't in the docker group that can use Docker"}},
		// GAP-0507: groups that can't be looked up start a run provisionally.
		"unknown groups on the fallback": {host("auto", ""), config.OpenShellAdminConfig{}, "missing", "unknown", cpu,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "kvm_missing", Provisional: true}},
		"unknown groups on KVM": {host("vm", "none"), config.OpenShellAdminConfig{}, "unknown", "ok", cpu,
			sandboxAvailability{Available: true, Driver: "vm", DriverReason: "configured", Provisional: true}},
		"unknown groups on the MicroVM image docker": {host("vm", "none"), config.OpenShellAdminConfig{}, "ok", "unknown", cpu,
			sandboxAvailability{Available: true, Driver: "vm", DriverReason: "configured", Provisional: true}},
		"vm and fallback none without KVM is refused": {host("vm", "none"), config.OpenShellAdminConfig{}, "missing", "ok", cpu,
			sandboxVMRequired("kvm_missing")},
		"a profile tightens the fallback to none": {host("auto", "docker"), none, "denied", "ok", cpu,
			sandboxVMRequired("kvm_access")},
		"a profile's none needs no KVM where it works": {host("auto", "docker"), none, "ok", "ok", cpu,
			sandboxAvailability{Available: true, Driver: "vm", DriverReason: "kvm_available"}},
		"docker never looks at KVM": {host("docker", "none"), none, "missing", "ok", cpu,
			sandboxAvailability{Available: true, Driver: "docker", DriverReason: "configured"}},
	} {
		p := newSandboxAvailabilityProbe()
		p.goos, p.goarch, p.access, p.prerequisite, p.cpuInfoPath = "linux", "amd64", devices(tc.kvm, tc.docker), nil, tc.cpuinfo
		if got := p.check(tc.cfg, 1001, true, tc.floor); got != tc.want {
			t.Errorf("%s: %+v, want %+v", name, got, tc.want)
		}
	}
	if got := sandboxVMRequired("kvm_missing"); got.Code != "no_kvm" ||
		got.Why != "your organization requires MicroVM sandboxes, and KVM not available on this computer" {
		t.Errorf("vm required: %+v", got)
	}
	// GAP-0499: a mode that denies the account names what /dev/kvm needs.
	if got := sandboxVMRequired("kvm_access"); got.Code != "no_kvm_access" ||
		got.Why != "your organization requires MicroVM sandboxes, and KVM not available for your account on this computer: /dev/kvm must be readable and writable for your account" {
		t.Errorf("vm required, KVM access: %+v", got)
	}

	// The lifecycle's record: MicroVM prerequisites missing while the
	// fallback's are met is a fallback with its own reason; under none it
	// is the missing prerequisite.
	vmMissing := func(_ *config.Config, _ int, driver string) string {
		if driver == "vm" {
			return sandboxUnavailablePrerequisiteOther
		}
		return ""
	}
	for name, tc := range map[string]struct {
		cfg  *config.Config
		want sandboxAvailability
	}{
		"fallback":  {host("vm", ""), sandboxAvailability{Available: true, Driver: "docker", DriverReason: "vm_prerequisite_missing"}},
		"no docker": {host("vm", "none"), sandboxUnavailable(sandboxUnavailablePrerequisiteOther)},
	} {
		p := newSandboxAvailabilityProbe()
		p.goos, p.goarch, p.access, p.prerequisite, p.cpuInfoPath = "linux", "amd64", devices("ok", "ok"), vmMissing, cpu
		if got := p.check(tc.cfg, 1001, true, config.OpenShellAdminConfig{}); got != tc.want {
			t.Errorf("prerequisites %s: %+v, want %+v", name, got, tc.want)
		}
	}
}

// sandboxDriverClaim judges the daemon's own choice at sandbox start.
func TestSandboxDriverClaim(t *testing.T) {
	host := func(driver, fallback string) *config.Config {
		cfg := &config.Config{}
		cfg.Enterprise.OpenShell.Driver, cfg.Enterprise.OpenShell.DriverFallback = driver, fallback
		return cfg
	}
	gw := sandboxAvailability{Available: true, Driver: "docker", DriverReason: "kvm_missing"}
	for name, tc := range map[string]struct {
		cfg                    *config.Config
		goos                   string
		floor                  config.OpenShellAdminConfig
		driver, reason         string
		wantDriver, wantReason string
		wantRefusal            string
	}{
		"auto vm":                 {cfg: host("auto", ""), goos: "linux", driver: "vm", reason: "kvm_available", wantDriver: "vm", wantReason: "kvm_available"},
		"vm configured":           {cfg: host("vm", ""), goos: "linux", driver: "vm", reason: "configured", wantDriver: "vm", wantReason: "configured"},
		"auto fallback":           {cfg: host("auto", ""), goos: "linux", driver: "docker", reason: "kvm_access", wantDriver: "docker", wantReason: "kvm_access"},
		"no claim takes ours":     {cfg: host("auto", ""), goos: "linux", wantDriver: "docker", wantReason: "kvm_missing"},
		"fallback none":           {cfg: host("vm", "none"), goos: "linux", driver: "docker", reason: "kvm_missing", wantRefusal: "requires MicroVM sandboxes"},
		"profile none":            {cfg: host("auto", ""), goos: "linux", floor: config.OpenShellAdminConfig{DriverFallback: "none"}, driver: "docker", reason: "kvm_missing", wantRefusal: "requires MicroVM sandboxes"},
		"stale configured docker": {cfg: host("auto", ""), goos: "linux", driver: "docker", reason: "configured", wantRefusal: "configuration selects auto"},
		"unknown docker reason":   {cfg: host("auto", ""), goos: "linux", driver: "docker", reason: "unknown", wantRefusal: "malformed"},
		"docker on a vm host":     {cfg: host("vm", "none"), goos: "linux", driver: "docker", reason: "configured", wantRefusal: "configuration selects vm"},
		"docker host":             {cfg: host("docker", ""), goos: "linux", driver: "docker", reason: "configured", wantDriver: "docker", wantReason: "configured"},
		"vm on a docker host":     {cfg: host("docker", ""), goos: "linux", driver: "vm", reason: "configured", wantRefusal: "configuration selects docker"},
		"mac is MicroVM only":     {cfg: host("auto", ""), goos: "darwin", driver: "docker", reason: "kvm_missing", wantRefusal: "configuration selects vm"},
		"mac vm":                  {cfg: host("", ""), goos: "darwin", driver: "vm", reason: "configured", wantDriver: "vm", wantReason: "configured"},
	} {
		driver, reason, refusal := sandboxDriverClaim(tc.cfg, tc.goos, tc.floor, tc.driver, tc.reason, gw)
		switch {
		case tc.wantRefusal != "" && (refusal == nil || !strings.Contains(refusal.Message, tc.wantRefusal)):
			t.Errorf("%s: refusal %+v, want %q", name, refusal, tc.wantRefusal)
		case tc.wantRefusal == "" && (refusal != nil || driver != tc.wantDriver || reason != tc.wantReason):
			t.Errorf("%s: %q %q %+v, want %q %q", name, driver, reason, refusal, tc.wantDriver, tc.wantReason)
		}
	}
}

// Through the routes: settings name the caller's fallback and the
// gateway's view; a resolve registers the daemon's driver and reason; a
// profile's driver_fallback: none refuses the fallback; a bind on another
// driver is refused.
func TestSandboxAuthorityDriverFallback(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the docker fallback is Linux only")
	}
	f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
	for _, cfg := range []*config.Config{f.cfg, f.api.scannerCfg} {
		cfg.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverAuto
		cfg.Guardrail.Profiles["engineering"] = config.GuardrailProfile{Description: "Engineering",
			Sandbox: &config.OpenShellAdminConfig{DriverFallback: config.EnterpriseOpenShellFallbackNone}}
	}
	sandboxHostAvailability = func(cfg *config.Config, _ managedHookPeer, floor config.OpenShellAdminConfig) sandboxAvailability {
		if sandboxDriverFallbackFor(cfg, "linux", floor) == config.EnterpriseOpenShellFallbackNone {
			return sandboxVMRequired("kvm_missing")
		}
		return sandboxAvailability{Available: true, Driver: "docker", DriverReason: "kvm_missing"}
	}
	f.setGroups(sbxAlice, "dc-sbx-contractors")
	f.setGroups(sbxBob, "dc-sbx-devs")

	rec := f.do(sbxAlice, http.MethodGet, sandboxrelay.PathSettings, nil, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"driver":"auto","driver_fallback":"docker"`) ||
		!strings.Contains(rec.Body.String(), `"selected_driver":"docker","driver_reason":"kvm_missing"`) {
		t.Fatalf("settings: %d %s", rec.Code, rec.Body.String())
	}

	req := claudeResolve()
	req.Driver, req.DriverReason = "docker", "kvm_missing"
	resp := f.resolve(sbxAlice, req)
	auth, _ := f.api.sandboxAuth()
	reg, _, _ := auth.store.Get(sbxAlice.UID, resp.Registration.ID)
	if reg.Driver != "docker" || reg.DriverReason != "kvm_missing" {
		t.Fatalf("registration driver %q reason %q", reg.Driver, reg.DriverReason)
	}
	wrong := sandboxrelay.BindRequest{V: 1, SandboxName: "dc-claude-1", SandboxID: "sbx-1", BindingID: "sb_" + strings.Repeat("1", 32), Driver: "vm"}
	if rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathRegistrations+resp.Registration.ID+sandboxrelay.RegistrationBindSub, wrong, nil); rec.Code != http.StatusForbidden ||
		!strings.Contains(rec.Body.String(), "another compute driver") {
		t.Fatalf("bind on another driver: %d %s", rec.Code, rec.Body.String())
	}

	// bob's profile refuses the docker fallback.
	bob := claudeResolve()
	bob.ProjectReal = "/home/ent-bob/project"
	bob.Driver, bob.DriverReason = "docker", "kvm_missing"
	rec = f.do(sbxBob, http.MethodPost, sandboxrelay.PathPolicyResolve, bob, map[string]string{sandboxrelay.ConnectorHeader: "claudecode"})
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "requires MicroVM sandboxes") ||
		!strings.Contains(rec.Body.String(), `"request_access"`) {
		t.Fatalf("profile none: %d %s", rec.Code, rec.Body.String())
	}
}
