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
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// TestDoctorRefusesAnAccountWithoutTheServiceWhileAnotherHoldsThePort
// (GAP-0390): one OpenShell gateway runs on a machine. A second account
// whose own Homebrew (~/homebrew) has no nvidia/openshell formula, or a
// Linux account without the openshell-gateway unit, got "not installed"
// with the install as its fix while another account's gateway held
// 127.0.0.1:17670: setup then installed OpenShell and started a service
// that could not bind the port. The doctor refuses it like an account
// whose service is stopped (GatewayPortElsewhere), names the port's
// holder, and gives the install as the step after the hand-over; it
// starts and installs nothing.
func TestDoctorRefusesAnAccountWithoutTheServiceWhileAnotherHoldsThePort(t *testing.T) {
	const (
		install  = "defenseclaw sandbox setup --install-openshell"
		refusal  = "one OpenShell gateway runs on a machine, under the account that started it, and this account's would not get its port: run sandboxes from that account, or have it hand its gateway over ("
		heldBy   = "127.0.0.1:17670, the gateway's port, is held by "
		otherUID = 502
	)
	// mac is a second account on a Mac: its Homebrew has no formula, it
	// has no gateway files of its own, and the gateway on the port refuses
	// it (its CA is the other account's).
	mac := func(t *testing.T, cli bool) *doctorFixture {
		f := newDoctorFixture(t)
		f.onMicroVMs()
		f.doctor.Gateway.BrewFormulaInstalled = func() bool { return false }
		f.found["openshell"] = cli
		if err := os.RemoveAll(f.dir); err != nil {
			t.Fatal(err)
		}
		f.runner.OnFunc("brew services", func(_ context.Context, c openshell.Command) ([]byte, error) {
			t.Errorf("ran brew %v without the formula", c.Args)
			return []byte("Error: Formula `openshell` is not installed."), errors.New("exit status 1")
		})
		f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		f.busy["127.0.0.1:17670"] = true
		return f
	}
	linux := func(t *testing.T) *doctorFixture {
		f := newDoctorFixture(t)
		f.runner.On("systemctl --user show openshell-gateway", "LoadState=not-found\nActiveState=inactive\nSubState=dead\n", nil)
		f.found["openshell"] = false
		f.fake.FailNext(openshelltest.MethodHealth, errors.New("connection refused"))
		f.busy["127.0.0.1:17670"] = true
		return f
	}
	noListener := func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{UID: -1}, daemon.ErrNoListener }
	otherAccount := func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{PID: 7001, UID: otherUID, Command: "openshell-gateway"}, nil
	}

	for _, tc := range []struct {
		name     string
		fixture  func(t *testing.T) *doctorFixture
		holder   func(string, int) (daemon.PortHolder, error)
		detail   string
		handOver string
		// deferred is a check the other account's gateway decides: the
		// registration (a Mac account without one), or the gateway that
		// refuses this account's.
		deferred string
	}{
		// lsof lists this account's processes only (dc-mac, GAP-0192).
		{"macOS, no OpenShell, port of a process lsof does not list", func(t *testing.T) *doctorFixture { return mac(t, false) }, noListener,
			"nvidia/openshell/openshell is not installed; " + heldBy + "a process of another account",
			"`brew services stop nvidia/openshell/openshell` as that account), then install OpenShell in this account", openshell.CheckIDRegistration},
		// An OpenShell CLI on PATH (the machine Homebrew's) does not make
		// that gateway one this account runs another way.
		{"macOS, a CLI on PATH, port of another uid", func(t *testing.T) *doctorFixture { return mac(t, true) }, otherAccount,
			"nvidia/openshell/openshell is not installed; " + heldBy,
			"`brew services stop nvidia/openshell/openshell` as that account), then install OpenShell in this account", openshell.CheckIDRegistration},
		{"Linux, no unit, port of another uid", linux, otherAccount,
			"openshell-gateway is not installed; " + heldBy,
			"`systemctl --user disable --now openshell-gateway` as that account; a plain stop starts it again at that account's next login), then install OpenShell in this account", openshell.CheckIDGatewayVersion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.fixture(t)
			f.doctor.PortHolder = tc.holder
			r := f.run()
			if !r.GatewayPortElsewhere {
				t.Fatalf("GatewayPortElsewhere = false\n%s", r)
			}
			svc := expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusFail, tc.detail)
			if svc.Fix == nil || svc.Fix.Summary != refusal+tc.handOver || svc.Fix.Command != install || svc.Fix.Apply != nil || svc.Fix.Automatic {
				t.Fatalf("service fix = %+v", svc.Fix)
			}
			// What follows from the other account's gateway is not checked:
			// the only other failure is a missing OpenShell CLI.
			expectCheck(t, r, tc.deferred, openshell.StatusSkip, "another account's (see Gateway service)")
			for _, c := range r.Checks {
				if c.Status == openshell.StatusFail && c.ID != openshell.CheckIDGatewayService && c.ID != openshell.CheckIDCLI {
					t.Fatalf("%s fails too: %s\n%s", c.ID, c.Detail, r)
				}
			}
			// --fix starts nothing and installs nothing.
			if _, err := r.ApplyFixes(context.Background(), func(openshell.Check) (bool, error) { return true, nil }); err != nil {
				t.Fatal(err)
			}
			for _, c := range f.runner.Calls() {
				if a := openshelltest.Argv(c); strings.Contains(a, "services start") || strings.Contains(a, "enable --now") || strings.Contains(a, "install") {
					t.Fatalf("ran %q", a)
				}
			}
		})
	}

	// Unchanged: with the port free, or held by this account's own
	// process, the account without the service is told to install
	// OpenShell, and nothing says another account.
	for _, tc := range []struct {
		name   string
		busy   bool
		holder func(string, int) (daemon.PortHolder, error)
	}{
		{"port free", false, otherAccount},
		{"port held by this account", true, func(string, int) (daemon.PortHolder, error) {
			return daemon.PortHolder{PID: 7002, UID: 501, Command: "openshell-gateway"}, nil
		}},
	} {
		t.Run("macOS, no OpenShell, "+tc.name, func(t *testing.T) {
			f := mac(t, false)
			f.busy["127.0.0.1:17670"] = tc.busy
			f.doctor.PortHolder = tc.holder
			r := f.run()
			svc := expectCheck(t, r, openshell.CheckIDGatewayService, openshell.StatusFail, "nvidia/openshell/openshell is not installed")
			if r.GatewayPortElsewhere || strings.Contains(svc.Detail, "another account") || svc.Fix == nil || svc.Fix.Command != install ||
				strings.Contains(svc.Fix.Summary, "one OpenShell gateway runs on a machine") {
				t.Fatalf("elsewhere %v, service = %+v, fix %+v", r.GatewayPortElsewhere, svc, svc.Fix)
			}
		})
	}
}
