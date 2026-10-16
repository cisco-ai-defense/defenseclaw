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
	"os/exec"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestDoctorDockerDesktopOfALoggedOutAccount: on a Mac, /var/run/docker.sock
// leads to the Docker Desktop of the account that started it last. An
// account that is not logged in to the desktop (one used over ssh only)
// cannot start a Docker Desktop of its own, so the doctor and setup say
// that, and how to get one, instead of the raw permission error and
// "start Docker Desktop" (GAP-0389). They never offer the other account
// socket. Logged in, or when launchctl cannot tell, the fix stays as it was.
func TestDoctorDockerDesktopOfALoggedOutAccount(t *testing.T) {
	const denied = "permission denied while trying to connect to the docker API at unix:///var/run/docker.sock"
	exitErr := exec.Command("false").Run()
	var exit *exec.ExitError
	if !errors.As(exitErr, &exit) {
		t.Skipf("no false(1) to produce an exit status: %v", exitErr)
	}
	for _, tc := range []struct {
		name    string
		session func(f *doctorFixture)
		fix     string
	}{
		{"not logged in to the desktop", func(f *doctorFixture) {
			f.runner.On("launchctl print gui/502", "Bad request.\nCould not find domain for port identifier: gui/502\n", exitErr)
		}, "Docker Desktop runs only in a desktop session, and dcm-std1 is not logged in to this Mac\x27s desktop: log in to the desktop as dcm-std1"},
		{"logged in to the desktop", func(f *doctorFixture) {
			f.runner.On("launchctl print gui/502", "gui/502 = {\n\ttype = login\n}\n", nil)
		}, "start Docker Desktop in this account: /var/run/docker.sock leads to another account"},
		{"launchctl cannot tell", func(*doctorFixture) {}, "start Docker Desktop in this account: /var/run/docker.sock leads to another account"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onBrew()
			f.doctor.Geteuid = func() int { return 502 }
			f.doctor.Username = func() (string, error) { return "dcm-std1", nil }
			f.runner.On("docker info", denied, errors.New("exit status 1"))
			tc.session(f)
			c := expectCheck(t, f.run(), openshell.CheckIDDocker, openshell.StatusFail, "Docker Desktop is not running in this account ("+denied+")")
			fix := tc.fix
			if c.Fix == nil || c.Fix.Apply != nil || c.Fix.Command != "" || !strings.HasPrefix(c.Fix.Summary, fix) ||
				strings.Contains(c.Fix.Summary, "DOCKER_HOST") || strings.Contains(c.Fix.Summary, "/Users/") {
				t.Fatalf("fix = %+v, want one starting %q", c.Fix, fix)
			}
		})
	}
}
