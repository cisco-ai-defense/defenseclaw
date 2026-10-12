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

package config

import (
	"strings"
	"testing"
)

// enterprise.openshell.driver takes auto, and driver_fallback docker or none.
func TestEnterpriseOpenShellDriverFallbackValidation(t *testing.T) {
	for _, tc := range []struct {
		driver, fallback string
		wantErr          string
	}{
		{driver: "auto"},
		{driver: "vm", fallback: "none"},
		{driver: "auto", fallback: "docker"},
		{driver: "docker", fallback: "none"},
		{driver: "kvm", wantErr: `enterprise.openshell.driver="kvm" is not one of docker, vm, auto`},
		{driver: "vm", fallback: "podman", wantErr: `enterprise.openshell.driver_fallback="podman" is not one of docker, none`},
	} {
		cfg := &Config{}
		cfg.Enterprise.OpenShell = EnterpriseOpenShellConfig{Driver: tc.driver, DriverFallback: tc.fallback}
		err := validateEnterpriseOpenShell(cfg, "linux")
		switch {
		case tc.wantErr == "" && err != nil:
			t.Errorf("driver %q fallback %q: %v", tc.driver, tc.fallback, err)
		case tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)):
			t.Errorf("driver %q fallback %q: err = %v, want %q", tc.driver, tc.fallback, err, tc.wantErr)
		}
	}
}

// The wanted driver and the fallback a user gets: macOS is MicroVM only,
// the docker driver has no fallback, and none wins from either side.
func TestEnterpriseOpenShellSandboxDriverAndFallback(t *testing.T) {
	none := OpenShellAdminConfig{DriverFallback: EnterpriseOpenShellFallbackNone}
	for _, tc := range []struct {
		goos, driver, fallback string
		floor                  OpenShellAdminConfig
		wantDriver, wantFb     string
	}{
		{goos: "linux", wantDriver: "docker", wantFb: ""},
		{goos: "darwin", wantDriver: "vm", wantFb: ""},
		{goos: "darwin", driver: "auto", wantDriver: "vm", wantFb: ""},
		{goos: "linux", driver: "auto", wantDriver: "auto", wantFb: "docker"},
		{goos: "linux", driver: "vm", wantDriver: "vm", wantFb: "docker"},
		{goos: "linux", driver: "vm", fallback: "none", wantDriver: "vm", wantFb: "none"},
		{goos: "linux", driver: "auto", floor: none, wantDriver: "auto", wantFb: "none"},
		{goos: "linux", driver: "vm", fallback: "none", floor: OpenShellAdminConfig{DriverFallback: "docker"}, wantDriver: "vm", wantFb: "none"},
		{goos: "linux", driver: "docker", fallback: "none", wantDriver: "docker", wantFb: ""},
	} {
		o := EnterpriseOpenShellConfig{Driver: tc.driver, DriverFallback: tc.fallback}
		if got := o.SandboxDriver(tc.goos); got != tc.wantDriver {
			t.Errorf("%s driver %q: SandboxDriver = %q, want %q", tc.goos, tc.driver, got, tc.wantDriver)
		}
		if got := o.SandboxDriverFallback(tc.goos, tc.floor); got != tc.wantFb {
			t.Errorf("%s driver %q fallback %q floor %q: SandboxDriverFallback = %q, want %q",
				tc.goos, tc.driver, tc.fallback, tc.floor.DriverFallback, got, tc.wantFb)
		}
	}
}

// A profile may set driver_fallback: none (tighten); docker never loosens a
// none floor.
func TestTightenOpenShellAdminDriverFallback(t *testing.T) {
	for _, tc := range []struct{ base, overlay, want string }{
		{"", "none", "none"},
		{"docker", "none", "none"},
		{"none", "docker", "none"},
		{"none", "", "none"},
		{"docker", "", "docker"},
		{"", "docker", "docker"},
	} {
		got, err := TightenOpenShellAdmin(OpenShellAdminConfig{DriverFallback: tc.base}, &OpenShellAdminConfig{DriverFallback: tc.overlay})
		if err != nil {
			t.Fatal(err)
		}
		if got.DriverFallback != tc.want {
			t.Errorf("base %q overlay %q: driver_fallback = %q, want %q", tc.base, tc.overlay, got.DriverFallback, tc.want)
		}
	}
	a := OpenShellAdminConfig{DriverFallback: "podman"}
	if err := a.validateManagedFloor("sandbox"); err == nil || !strings.Contains(err.Error(), `sandbox.driver_fallback "podman" must be one of docker, none`) {
		t.Fatalf("bad driver_fallback: %v", err)
	}
	if (OpenShellAdminConfig{DriverFallback: "none"}).IsZero() {
		t.Fatal("IsZero ignores driver_fallback")
	}
}
