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
	"fmt"
	"strings"
)

// ComputeDriver is the name of an OpenShell compute driver as the gateway
// reports it (ComputeDriverInfo.Name): the gateway-selected name, which
// also keys a sandbox template's driver_config.
type ComputeDriver string

// The compute drivers DefenseClaw drives. One gateway runs one driver.
const (
	// DriverDocker runs each sandbox as a container of the gateway's Docker
	// daemon.
	DriverDocker ComputeDriver = "docker"
	// DriverVM runs each sandbox in its own MicroVM (libkrun on Apple's
	// Hypervisor), the driver a Mac runs sandboxes with. OpenShell calls it
	// experimental.
	DriverVM ComputeDriver = "vm"
)

// Driver is everything DefenseClaw does differently per compute driver.
// Code that behaves differently on a driver asks these fields, never the
// driver's name or runtime.GOOS, so this one table says what differs. The
// zero Driver has every capability off and fails closed: it mounts no host
// folders, bakes nothing into an image, syncs before a stop and checks
// the workload after ready.
type Driver struct {
	Name ComputeDriver
	// HostMounts says the driver honours a template's docker driver_config
	// ({"docker": {"mounts": [...]}}): the live project mount of mount mode
	// and the per-run managed files, bind-mounted read-only. Without it a
	// template's DriverConfig is always nil.
	HostMounts bool
	// MountRefusal says why mount mode is clamped to copy on the driver;
	// empty when HostMounts is set.
	MountRefusal string
	// RunFilesInImage says the per-run managed harness files are baked into
	// a run image instead of bind-mounted, so they cannot change after
	// create.
	RunFilesInImage bool
	// SandboxLimits says the driver enforces a template's per-sandbox cpu
	// and memory limits.
	SandboxLimits bool
	// GatewayIdentity says the workload's uid and gid come from the
	// gateway's configuration ([openshell.drivers.vm] sandbox_uid and
	// sandbox_gid), for every sandbox alike; the policy's
	// process.run_as_user is ignored.
	GatewayIdentity bool
	// ImageRepository is the repository of the image references sent to the
	// gateway; empty means the overlay images' own (image.DefaultRepository).
	// The vm driver reads images from the local Docker daemon, and one it
	// does not find there it pulls from a registry instead. Its references
	// therefore use a registry host under the reserved .invalid TLD (RFC
	// 2606), which never resolves, so that pull fails rather than fetching
	// someone else's image. localhost is not used: on macOS any local
	// process can listen on its ports without root, and Docker talks to a
	// localhost registry over plain HTTP.
	ImageRepository string
	// StopFlushes says the driver's stop keeps what the workload wrote. A
	// MicroVM's stop does not flush the guest's page cache: a file written
	// and not synced before it comes back empty at the next start (OpenShell
	// 0.1.1), so without it DefenseClaw runs sync in the sandbox before
	// every stop, and a copy's unpulled work survives the stop.
	StopFlushes bool
	// SkipWorkloadCheck leaves out the check after ready (the identity the
	// workload runs as, its capabilities, DefenseClaw's files in the
	// sandbox). It is new on docker and waits for a live run there before
	// it is turned on; the vm driver needs it from the start, because the
	// workload's identity there is the gateway's configuration.
	SkipWorkloadCheck bool
	// ImageCache is where the driver keeps what it prepares from each image
	// it boots, relative to the home of the user the gateway runs as; empty
	// when it prepares nothing. The vm driver turns an image into a MicroVM
	// root disk there on its first boot (about a minute and about 5 GB),
	// one per image ID, and never removes it: `sandbox image prune` and
	// teardown remove the disks of the image IDs they removed.
	ImageCache string
}

// drivers is the table: what each compute driver DefenseClaw drives can
// and cannot do.
var drivers = map[ComputeDriver]Driver{
	DriverDocker: {Name: DriverDocker, HostMounts: true, SandboxLimits: true, StopFlushes: true, SkipWorkloadCheck: true},
	DriverVM: {
		Name: DriverVM, RunFilesInImage: true, GatewayIdentity: true,
		ImageRepository: "defenseclaw.invalid/sandbox",
		ImageCache:      ".local/state/openshell/vm-driver/images",
		MountRefusal:    "the OpenShell MicroVM (vm) driver mounts no host folders",
	},
}

// driverBinaryPrefix starts the name a compute driver's binary advertises
// (ComputeDriverInfo.DriverName, "openshell-driver-vm").
const driverBinaryPrefix = "openshell-driver-"

// ErrUnsupportedDriver means the gateway runs no compute driver DefenseClaw
// drives, or does not say which one it runs.
var ErrUnsupportedDriver = errors.New("openshell: DefenseClaw drives gateways that run the docker or vm compute driver")

// LookupDriver returns the Driver of a compute driver's name, as a record
// keeps it. The empty name is docker: records from before the driver was
// kept were all made on docker. An unknown name returns the zero Driver
// and false.
func LookupDriver(name string) (Driver, bool) {
	if name == "" {
		return drivers[DriverDocker], true
	}
	d, ok := drivers[ComputeDriver(name)]
	return d, ok
}

// GatewayDriver returns the Driver of the compute driver a gateway reports
// (GetGatewayInfo). The gateway-selected name decides; a driver reported
// without one is judged by its binary's name ("openshell-driver-vm" is vm).
// A gateway that reports no driver, several, a driver DefenseClaw does not
// drive (podman, kubernetes), or a name and binary that disagree is refused
// with ErrUnsupportedDriver and an error that names what it reports.
func GatewayDriver(info *GatewayInfo) (Driver, error) {
	if info == nil || len(info.ComputeDrivers) == 0 {
		return Driver{}, fmt.Errorf("%w; this gateway reports no compute driver", ErrUnsupportedDriver)
	}
	if len(info.ComputeDrivers) > 1 {
		names := make([]string, 0, len(info.ComputeDrivers))
		for _, d := range info.ComputeDrivers {
			names = append(names, describeDriver(d))
		}
		return Driver{}, fmt.Errorf("%w; this gateway reports several (%s), so which one runs a sandbox is not known",
			ErrUnsupportedDriver, strings.Join(names, ", "))
	}
	reported := info.ComputeDrivers[0]
	byBinary, binaryKnown := drivers[ComputeDriver(strings.TrimPrefix(reported.DriverName, driverBinaryPrefix))]
	d, known := drivers[ComputeDriver(reported.Name)]
	switch {
	case reported.Name == "" && binaryKnown:
		return byBinary, nil
	case !known:
		return Driver{}, fmt.Errorf("%w; this gateway runs %s", ErrUnsupportedDriver, describeDriver(reported))
	case binaryKnown && byBinary.Name != d.Name:
		return Driver{}, fmt.Errorf("%w; this gateway reports %s, whose name and binary disagree",
			ErrUnsupportedDriver, describeDriver(reported))
	}
	return d, nil
}

// describeDriver names a reported compute driver for an error: its name,
// and its binary when that says more.
func describeDriver(d ComputeDriverInfo) string {
	switch {
	case d.Name == "" && d.DriverName == "":
		return "a driver without a name"
	case d.Name == "":
		return fmt.Sprintf("the driver binary %q", d.DriverName)
	case d.DriverName == "" || d.DriverName == d.Name || d.DriverName == driverBinaryPrefix+d.Name:
		return fmt.Sprintf("%q", d.Name)
	default:
		return fmt.Sprintf("%q (driver binary %q)", d.Name, d.DriverName)
	}
}
