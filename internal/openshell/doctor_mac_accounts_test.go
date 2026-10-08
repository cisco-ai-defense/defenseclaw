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
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// brewTmuxRefusal is `brew services info` in a tmux session without access
// to the account's macOS login session: usage text, then its Error: line.
const brewTmuxRefusal = "Usage: brew [sudo] brew services info (formula|--all) [--json]:\n\n" +
	"  -h, --help                       Show this message.\n\n" +
	"Error: Invalid usage: `brew services` cannot run under tmux!\n"

// TestDoctorOnAMacWhoseGatewayIsAnotherAccounts (GAP-0191, GAP-0192): a
// second account on a Mac whose Homebrew prefix, gateway configuration
// (private) and gateway (on the port) are the first account's, in a tmux
// session `brew services` refuses to run in. The doctor said the gateway
// runs the docker driver, printed brew's usage text and a raw permission
// error; it says the gateway is the other account's and its driver is not
// known here.
func TestDoctorOnAMacWhoseGatewayIsAnotherAccounts(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a file of mode 000")
	}
	newMac := func(t *testing.T) *doctorFixture {
		f := newDoctorFixture(t)
		f.onMicroVMs()
		// This account has no gateway files and no registration: the
		// prefix's gateway.toml is the other account's.
		if err := os.RemoveAll(f.dir); err != nil {
			t.Fatal(err)
		}
		toml := filepath.Join(f.brew, "var", "openshell", "gateway.toml")
		if err := os.MkdirAll(filepath.Dir(toml), 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, toml, microVMTOML, 0o000)
		theirs, err := os.Lstat(toml)
		if err != nil {
			t.Fatal(err)
		}
		openshell.SetGatewayFileOwner(t, func(info fs.FileInfo) bool { return !os.SameFile(info, theirs) })
		f.runner.On("brew services info nvidia/openshell/openshell --json", brewTmuxRefusal, errors.New("exit status 1"))
		return f
	}

	t.Run("another account holds the port", func(t *testing.T) {
		f := newMac(t)
		f.busy["127.0.0.1:17670"] = true
		// lsof shows none of this account's processes on the port.
		f.doctor.PortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{UID: -1}, daemon.ErrNoListener }
		r := f.run()
		svc := expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusFail, "127.0.0.1:17670, the gateway's port, is held by a process of another account")
		if svc.Fix == nil || !strings.Contains(svc.Fix.Summary, "one OpenShell gateway runs on a machine") {
			t.Fatalf("service fix = %+v", svc.Fix)
		}
		// What follows from it is not checked, with no fix of its own (GAP-0296).
		if reg := expectCheck(t, r, openshell.CheckIDRegistration, openshell.StatusSkip, "another account's (see Gateway service)"); reg.Fix != nil {
			t.Fatalf("registration fix = %+v", reg.Fix)
		}
		unknown := "the gateway's compute driver is not known here: " + filepath.Join(f.brew, "var", "openshell", "gateway.toml") + " belongs to "
		expectCheck(t, r, openshell.CheckIDVMIdentity, openshell.StatusSkip, unknown)
		expectCheck(t, r, openshell.CheckIDVMResources, openshell.StatusSkip, unknown)
		expectCheck(t, r, openshell.CheckIDBindMounts, openshell.StatusSkip, "may not read another account's gateway configuration")
		if out := r.String(); strings.Contains(out, "docker driver") || strings.Contains(out, "permission denied") || strings.Contains(out, "Usage:") {
			t.Fatalf("doctor still names the docker driver, a raw error or brew usage:\n%s", out)
		}
	})

	t.Run("brew services refuses this tmux session", func(t *testing.T) {
		r := newMac(t).run()
		svc := expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusFail,
			"brew services info nvidia/openshell/openshell: `brew services` refuses to run in a tmux session that has no access to this account's macOS login session")
		if strings.Contains(svc.Detail, "\n") || svc.Fix == nil || !strings.Contains(svc.Fix.Summary, "outside tmux") {
			t.Fatalf("service = %+v, fix %+v", svc, svc.Fix)
		}
	})
}
