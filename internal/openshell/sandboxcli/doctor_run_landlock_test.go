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
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// rel-1-0-10:GAP-1746: on a Mac whose gateway runs the docker driver on
// Docker Desktop, `sandbox doctor` and `sandbox run` read the Landlock of
// Docker Desktop's Linux VM from one probe (App.DockerVMLandlock) and give
// one verdict: the doctor says ready for sandboxes, in text and in JSON,
// only where a run goes on to create the sandbox. A probe that could not
// decide (no image to check in, a probe container that fails) left the
// doctor's Landlock row a warning, so the doctor said ready while every
// run was refused before anything was built.
func TestGAP1746DoctorAndRunAgreeOnDockerDesktopsLandlock(t *testing.T) {
	for _, c := range []struct {
		name   string
		abi    int
		err    error
		row    openshell.CheckStatus // the doctor's Landlock row for this probe (dockerVMLandlockCheck)
		detail string
		ready  bool
	}{
		{"ABI 8 (Docker Desktop 29.8)", 8, nil, openshell.StatusPass, "ABI 8 in Docker Desktop's Linux VM", true},
		{"ABI 2", 2, nil, openshell.StatusFail, "Docker Desktop's Linux VM has Landlock ABI 2; OpenShell needs ABI 3 or newer", false},
		{"no Landlock", 0, openshell.ErrLandlockMissing, openshell.StatusFail, "Docker Desktop's Linux VM has no Landlock, and OpenShell sandboxes need it", false},
		{"no image to check in", 0, openshell.ErrNoProbeImage, openshell.StatusWarn, "not checked: sandboxes run on the kernel of Docker Desktop's Linux VM, " +
			"which DefenseClaw checks in the OpenShell base image, and that image is not on this machine yet", false},
		{"probe failed", 0, errors.New("the probe container failed"), openshell.StatusWarn, "could not check Docker Desktop's Linux VM: the probe container failed", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			app := func() *testApp {
				ta := newTestApp(t, "")
				ta.GOOS, ta.dockerEngine = "darwin", "Docker Desktop"
				ta.dockerLandlock, ta.dockerLandlockErr = c.abi, c.err
				ta.daemon.status.Gateway.Driver = "docker"
				ta.HostDoctor = macReport(openshell.DriverDocker, func(r *openshell.DoctorReport) {
					l := r.Get(openshell.CheckIDLandlock)
					l.Status, l.Detail = c.row, c.detail
				})
				return ta
			}
			// The doctor probes with the probe sandbox run decides by.
			ta := app()
			d := ta.defaultDoctor()
			if d.DockerVMLandlockABI == nil {
				t.Fatal("the doctor probes Docker Desktop's Linux VM on its own, not with the probe sandbox run decides by")
			}
			if abi, _, err := d.DockerVMLandlockABI(bg); abi != c.abi || !errors.Is(err, c.err) || ta.landlockAsked != 1 {
				t.Fatalf("doctor probe = %d, %v (run probe asked %d times), want %d, %v from the run probe", abi, err, ta.landlockAsked, c.abi, c.err)
			}

			ta = app()
			ta.daemon.errors["POST "+sandboxapi.PathSandboxes] = &sandboxapi.Error{Code: sandboxapi.CodeUpstream, Message: "create reached"}
			runErr := ta.Run(bg, RunOptions{Harness: "claude"})
			reached := runErr != nil && strings.HasPrefix(runErr.Error(), "create reached")

			ta = app()
			_ = ta.RunDoctor(bg, DoctorOptions{})
			out := ta.output()
			said := strings.Contains(out, "ready for sandboxes") && !strings.Contains(out, "not ready for sandboxes")

			ta = app()
			_ = ta.RunDoctor(bg, DoctorOptions{Output: OutputJSON})
			m := regexp.MustCompile(`"ready":\s*(true|false)`).FindStringSubmatch(ta.output())
			if m == nil {
				t.Fatalf("doctor --json has no ready field:\n%s", ta.output())
			}
			jsonReady := m[1] == "true"

			if reached != c.ready || said != c.ready || jsonReady != c.ready {
				t.Fatalf("run reached the create %v (%v), doctor said ready %v, doctor --json ready %v; want all %v:\n%s",
					reached, runErr, said, jsonReady, c.ready, out)
			}
			if !c.ready && c.row != openshell.StatusFail {
				// The doctor says why, in the run's words.
				has(t, out, "not ready for sandboxes yet: sandbox run refuses on this machine: no sandbox can start on this gateway: it runs sandboxes on the docker driver, and ")
			}
		})
	}
}
