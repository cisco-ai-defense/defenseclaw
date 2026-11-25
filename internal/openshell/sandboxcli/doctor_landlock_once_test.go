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

package sandboxcli

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// rel-1-0-10:GAP-1758: `sandbox doctor` on a Mac whose gateway runs the
// docker driver on Docker Desktop probed Docker Desktop's Linux VM for
// Landlock twice per report: once for its Landlock row and once more for
// its last line (doctorRunRefusal). Each probe starts a container, and
// both counted against the 90 s the Python doctor and the TUI give the
// whole report. The last line also ended with sandbox run's own words,
// "nothing was built or created", which a doctor never builds.
func TestGAP1758DoctorProbesDockerDesktopsLandlockOnce(t *testing.T) {
	ta := newTestApp(t, "")
	ta.GOOS, ta.dockerEngine = "darwin", "Docker Desktop"
	ta.dockerLandlock, ta.dockerLandlockErr = 0, openshell.ErrNoProbeImage
	ta.daemon.status.Gateway.Driver = "docker"
	mac := macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) {
		l := r.Get(openshell.CheckIDLandlock)
		l.Status, l.Detail = openshell.StatusWarn, "not checked: the OpenShell base image is not on this machine yet"
	})
	// The host doctor's Landlock row asks the probe it was given, as
	// openshell's dockerVMLandlockCheck does.
	ta.HostDoctor = func(ctx context.Context, d *openshell.Doctor) *openshell.DoctorReport {
		_, _, _ = d.DockerVMLandlockABI(ctx)
		return mac(ctx, d)
	}
	_ = ta.RunDoctor(bg, DoctorOptions{})
	out := ta.output()
	if ta.landlockAsked != 1 {
		t.Fatalf("one sandbox doctor probed Docker Desktop's Linux VM %d times, want 1:\n%s", ta.landlockAsked, out)
	}
	has(t, out, "not ready for sandboxes yet: sandbox run refuses on this machine: no sandbox can start on this gateway")
	if strings.Contains(out, "nothing was built or created") {
		t.Fatalf("the doctor's last line uses sandbox run's 'nothing was built or created':\n%s", out)
	}

	// sandbox run keeps its own words.
	ta = newTestApp(t, "")
	ta.GOOS, ta.dockerEngine = "darwin", "Docker Desktop"
	ta.dockerLandlock, ta.dockerLandlockErr = 0, openshell.ErrNoProbeImage
	ta.daemon.status.Gateway.Driver = "docker"
	ta.HostDoctor = mac
	err := ta.Run(bg, RunOptions{Harness: "claude"})
	if err == nil || !strings.Contains(err.Error(), "; nothing was built or created") {
		t.Fatalf("sandbox run refusal = %v, want it to say nothing was built or created", err)
	}
}
