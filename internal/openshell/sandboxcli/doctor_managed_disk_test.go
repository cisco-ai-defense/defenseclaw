// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// The managed doctor of an account on the MicroVM driver has a Disk space
// row for the account's MicroVM state volume: it passes at 45 GiB free,
// warns at 22 GiB and fails at 12 GiB (GAP-0259). On the docker driver it
// has no such row.
func TestManagedDoctorHasTheMicroVMDiskRow(t *testing.T) {
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			withManagedHost(t)
			ta := newTestApp(t, "")
			ta.GOOS = goos
			ta.daemon.status.Managed = managedStatusFixture()
			ta.daemon.status.Managed.Driver = "vm"
			ta.ManagedE2fsprogsDir = func(context.Context) (string, bool) { return "", false }
			ta.ManagedAccountHome = func() (string, error) { return ta.home, nil }
			var free uint64
			var measured string
			ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
				d.DiskFree = func(path string) (uint64, error) { measured = path; return free, nil }
				return hostReport(nil)(ctx, d)
			}
			for _, tc := range []struct {
				gib  uint64
				want openshell.CheckStatus
			}{{45, openshell.StatusPass}, {22 - 1, openshell.StatusWarn}, {12 - 1, openshell.StatusFail}} {
				free = tc.gib << 30
				row := ta.runDoctor(bg).Get(openshell.CheckIDDisk)
				if row == nil || row.Status != tc.want || !strings.Contains(row.Detail, "free under "+ta.home) {
					t.Fatalf("%d GiB free: %+v, want %s", tc.gib, row, tc.want)
				}
				if !strings.HasPrefix(measured, ta.home) {
					t.Fatalf("measured %q, not under the account's home %q", measured, ta.home)
				}
			}
			ta.daemon.status.Managed.Driver = "docker"
			if row := ta.runDoctor(bg).Get(openshell.CheckIDDisk); row != nil {
				t.Fatalf("docker driver has a MicroVM disk row: %+v", row)
			}
		})
	}
}

// With the docker driver rendered on a managed Mac, the doctor names that
// driver everywhere: no e2fsprogs row, and the Platform row says the docker
// driver instead of the MicroVM note (GAP-0249), whether the account's
// sandbox service answers or not. On the vm driver the note stays.
func TestManagedMacDoctorPlatformFollowsTheDockerDriver(t *testing.T) {
	withManagedHost(t)
	ta := newTestApp(t, "")
	ta.GOOS = "darwin"
	ta.ManagedE2fsprogsDir = func(context.Context) (string, bool) { return "", false }
	ta.ManagedAccountHome = func() (string, error) { return ta.home, nil }
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		d.DiskFree = func(string) (uint64, error) { return 45 << 30, nil }
		return hostReport(func(rep *openshell.DoctorReport) {
			rep.Checks[0] = openshell.Check{ID: openshell.CheckIDPlatform, Title: "Platform", Status: openshell.StatusWarn,
				Detail: "darwin/arm64: macOS sandboxes run in OpenShell MicroVMs (the vm driver, experimental upstream)"}
		})(ctx, d)
	}
	ta.daemon.status.Managed = managedStatusFixture()
	ta.daemon.status.Managed.Driver = "docker"
	rep := ta.runDoctor(bg)
	platform := rep.Get(openshell.CheckIDPlatform)
	if platform == nil || platform.Status != openshell.StatusPass || strings.Contains(platform.Detail, "MicroVM") ||
		!strings.Contains(platform.Detail, "docker driver") || rep.Get(openshell.CheckIDManagedE2fsprogs) != nil {
		t.Fatalf("docker driver: platform %+v, e2fsprogs %+v", platform, rep.Get(openshell.CheckIDManagedE2fsprogs))
	}
	ta.daemon.status.Managed.Driver = "vm"
	rep = ta.runDoctor(bg)
	if platform := rep.Get(openshell.CheckIDPlatform); platform == nil || platform.Status != openshell.StatusWarn || !strings.Contains(platform.Detail, "vm driver") {
		t.Fatalf("vm driver: platform %+v", platform)
	}
}
