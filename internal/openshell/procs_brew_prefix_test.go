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
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestDoctorGatewayOfAnotherHomebrew: a gateway that the openshell formula
// of a Homebrew of your own runs (~/homebrew), while HOMEBREW_PREFIX and
// PATH name another Homebrew (an ssh session without its shellenv), is
// not one started by hand: the doctor names both Homebrews and the shellenv
// that lets DefenseClaw see and restart its service (GAP-0391, where the
// gateway of the formula 0.1.1 in ~/homebrew read as started by hand).
func TestDoctorGatewayOfAnotherHomebrew(t *testing.T) {
	for _, keg := range []string{filepath.Join("opt", "openshell"), filepath.Join("Cellar", "openshell", "0.1.1")} {
		t.Run(keg, func(t *testing.T) {
			f := newDoctorFixture(t)
			f.onMicroVMs()
			f.doctor.Gateway.BrewFormulaInstalled = func() bool { return false }
			// The Homebrew that the shell names is the machine one.
			f.doctor.Gateway.BrewPrefix = "/opt/homebrew"
			prefix := filepath.Join(f.home, "homebrew")
			gateway := filepath.Join(prefix, keg, "bin", "openshell-gateway")
			if err := os.MkdirAll(filepath.Dir(gateway), 0o755); err != nil {
				t.Fatal(err)
			}
			f.runner.On("ps -axww -o pid=,ppid=,uid=,comm=", "    1     0     0 /sbin/launchd\n 7976     1   501 "+gateway+"\n", nil)
			f.contactedGatewayPID(7976)
			f.runner.On("launchctl list", "PID\tStatus\tLabel\n7976\t0\tsh.brew.openshell\n", nil)
			r := f.run()
			c := expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusWarn, gateway+
				" (process 7976) is the nvidia/openshell/openshell formula of the Homebrew at "+prefix+", but DefenseClaw uses the Homebrew at /opt/homebrew")
			if c.Fix == nil || c.Fix.Apply != nil || c.Fix.Command != "eval \"$("+filepath.Join(prefix, "bin", "brew")+" shellenv)\"" {
				t.Fatalf("fix = %+v", c.Fix)
			}
		})
	}
}
