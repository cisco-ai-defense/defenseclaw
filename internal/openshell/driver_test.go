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

package openshell_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func TestGatewayDriver(t *testing.T) {
	drivers := func(ds ...openshell.ComputeDriverInfo) *openshell.GatewayInfo {
		return &openshell.GatewayInfo{ComputeDrivers: ds}
	}
	for _, tc := range []struct {
		name string
		info *openshell.GatewayInfo
		want openshell.ComputeDriver
		// refusal is what the error must name ("" when the driver is known).
		refusal string
	}{
		{"docker", drivers(openshell.ComputeDriverInfo{Name: "docker", DriverName: "docker"}), openshell.DriverDocker, ""},
		{"docker binary", drivers(openshell.ComputeDriverInfo{Name: "docker", DriverName: "openshell-driver-docker"}), openshell.DriverDocker, ""},
		// What the Mac's 0.1.1 gateway logs: configured_driver=vm advertised_driver=openshell-driver-vm.
		{"vm", drivers(openshell.ComputeDriverInfo{Name: "vm", DriverName: "openshell-driver-vm"}), openshell.DriverVM, ""},
		{"vm binary only", drivers(openshell.ComputeDriverInfo{DriverName: "openshell-driver-vm"}), openshell.DriverVM, ""},
		{"docker binary only", drivers(openshell.ComputeDriverInfo{DriverName: "docker"}), openshell.DriverDocker, ""},
		// An unknown binary name does not veto the gateway-selected name.
		{"unknown binary", drivers(openshell.ComputeDriverInfo{Name: "vm", DriverName: "libkrun-runner"}), openshell.DriverVM, ""},
		{"nil info", nil, "", "no compute driver"},
		{"no driver", drivers(), "", "no compute driver"},
		{"two drivers", drivers(openshell.ComputeDriverInfo{Name: "docker"}, openshell.ComputeDriverInfo{Name: "vm"}), "", `several ("docker", "vm")`},
		{"podman", drivers(openshell.ComputeDriverInfo{Name: "podman", DriverName: "openshell-driver-podman"}), "", `runs "podman"`},
		{"kubernetes", drivers(openshell.ComputeDriverInfo{Name: "kubernetes"}), "", `runs "kubernetes"`},
		// driver_config is keyed by the name: a docker binary under another
		// name would not read the docker key.
		{"renamed docker", drivers(openshell.ComputeDriverInfo{Name: "local", DriverName: "openshell-driver-docker"}), "", `"local" (driver binary "openshell-driver-docker")`},
		{"name and binary disagree", drivers(openshell.ComputeDriverInfo{Name: "docker", DriverName: "openshell-driver-vm"}), "", "whose name and binary disagree"},
		{"unnamed", drivers(openshell.ComputeDriverInfo{}), "", "without a name"},
		{"unknown binary only", drivers(openshell.ComputeDriverInfo{DriverName: "openshell-driver-podman"}), "", `binary "openshell-driver-podman"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := openshell.GatewayDriver(tc.info)
			if tc.refusal == "" {
				if err != nil || d.Name != tc.want {
					t.Fatalf("GatewayDriver = %+v, %v; want %s", d, err, tc.want)
				}
				return
			}
			if !errors.Is(err, openshell.ErrUnsupportedDriver) || !strings.Contains(err.Error(), tc.refusal) || d != (openshell.Driver{}) {
				t.Fatalf("GatewayDriver = %+v, %v; want a refusal naming %s", d, err, tc.refusal)
			}
		})
	}
}

// The table: docker mounts host folders and limits each sandbox; the
// MicroVM driver does neither, bakes the run files into an image, takes its
// identity from the gateway and names images no registry serves.
func TestDriverTable(t *testing.T) {
	docker, ok := openshell.LookupDriver("docker")
	if !ok || docker != (openshell.Driver{Name: openshell.DriverDocker, HostMounts: true, SandboxLimits: true, StopFlushes: true, HostsFile: true}) {
		t.Fatalf("docker = %+v, %v", docker, ok)
	}
	vm, ok := openshell.LookupDriver("vm")
	if !ok || vm.Name != openshell.DriverVM || vm.HostMounts || vm.SandboxLimits || !vm.RunFilesInImage || !vm.GatewayIdentity ||
		vm.MountRefusal == "" || !strings.HasPrefix(vm.ImageRepository, "defenseclaw.invalid/") || vm.StopFlushes ||
		vm.ImageCache != ".local/state/openshell/vm-driver/images" || vm.HostsFile {
		t.Fatalf("vm = %+v, %v", vm, ok)
	}
	// A record from before drivers were kept was made on docker.
	if old, ok := openshell.LookupDriver(""); !ok || old != docker {
		t.Fatalf(`LookupDriver("") = %+v, %v`, old, ok)
	}
	if unknown, ok := openshell.LookupDriver("podman"); ok || unknown != (openshell.Driver{}) {
		t.Fatalf(`LookupDriver("podman") = %+v, %v`, unknown, ok)
	}
	// The zero Driver fails closed.
	if zero := (openshell.Driver{}); zero.HostMounts || zero.SandboxLimits || zero.RunFilesInImage || zero.StopFlushes || zero.HostsFile {
		t.Fatalf("zero Driver = %+v", zero)
	}
}
