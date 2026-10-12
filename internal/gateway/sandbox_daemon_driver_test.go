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

//go:build linux || darwin

package gateway

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The daemon picks a create's driver at sandbox start from its own probe,
// sends it in the resolve, and shows it in status; under driver_fallback:
// none a sandbox that can't get the MicroVM driver is refused with the
// reason and the caller's contact.
func TestSandboxDaemonSelectsTheDriverAtStart(t *testing.T) {
	probes := 0
	kvm := openshell.VMProbeResult{OK: true}
	regs, err := loadDaemonRegistrations(filepath.Join(t.TempDir(), "registrations.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := &SandboxDaemon{regs: regs, logf: t.Logf, relay: &fakeRelay{}, opts: SandboxDaemonOptions{goos: "linux",
		vmProbe: func(sandboxrelay.DaemonSettings) openshell.VMProbeResult { probes++; return kvm }}}
	// The settings below are current: no status re-reads them (GAP-0256).
	d.settingsAt.Store(time.Now().Add(time.Hour).UnixNano())
	settings := func(driver, fallback string) sandboxrelay.DaemonSettings {
		return sandboxrelay.DaemonSettings{Enabled: true, Available: true, RequestAccess: "it-security@example.com",
			Enterprise: sandboxrelay.EnterpriseOpenShell{Install: "setup", Driver: driver, DriverFallback: fallback}}
	}

	d.settings = settings("auto", "docker")
	if st := d.managedStatus(context.Background()); st.Driver != "auto" || st.DriverReason != "" || probes != 0 {
		t.Fatalf("status before any start probed or guessed: %+v (%d probes)", st, probes)
	}
	choice, err := d.selectDriver(d.settings)
	if err != nil || choice != (openshell.DriverChoice{Driver: openshell.DriverVM, Reason: openshell.DriverReasonKVMAvailable}) {
		t.Fatalf("auto with KVM: %+v %v", choice, err)
	}

	kvm = openshell.VMProbeResult{Reason: openshell.DriverReasonKVMMissing}
	choice, err = d.selectDriver(d.settings)
	if err != nil || choice != (openshell.DriverChoice{Driver: openshell.DriverDocker, Reason: openshell.DriverReasonKVMMissing}) {
		t.Fatalf("auto without KVM: %+v %v", choice, err)
	}
	st := d.managedStatus(context.Background())
	if st.Driver != "docker" || st.DriverReason != "kvm_missing" || st.DriverFallback != "docker" {
		t.Fatalf("status after a fallback start: %+v", st)
	}
	req, err := d.resolveRequest(sandboxapi.CreateRequest{Harness: "claudecode"}, choice, nil)
	if err != nil || req.Driver != "docker" || req.DriverReason != "kvm_missing" {
		t.Fatalf("resolve request: %+v %v", req, err)
	}
	if err := regs.put(daemonRegistration{ID: "reg-" + strings.Repeat("a", 26), Sandbox: "dc-claude-a", Driver: "vm", DriverReason: "configured"}); err != nil {
		t.Fatal(err)
	}
	if st := d.managedStatus(context.Background()); st.Driver != "vm" || st.DriverReason != "configured" {
		t.Fatalf("status names the newest sandbox's driver: %+v", st)
	}

	// The gateway restarted on docker after the organization switched
	// drivers while that newest sandbox (a vm one) is still registered: the
	// driver in force is the gateway's (GAP-0455).
	d.settings = settings("docker", "none")
	st = d.managedStatus(context.Background())
	d.driverInForce(st, "docker")
	if st.Driver != "docker" || st.DriverReason != openshell.DriverReasonKVMMissing {
		t.Fatalf("status after the gateway switched to docker: %+v", st)
	}
	d.driverInForce(st, "vm")
	if st.Driver != "vm" || st.DriverReason != "" {
		t.Fatalf("status after the gateway switched back: %+v", st)
	}
	d.driverInForce(st, "")
	if st.Driver != "vm" {
		t.Fatalf("a gateway that names no driver changed the status: %+v", st)
	}

	d.settings = settings("vm", "none")
	_, err = d.selectDriver(d.settings)
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeUnavailable ||
		!strings.Contains(apiErr.Message, "requires MicroVM sandboxes") || !strings.Contains(apiErr.Message, "KVM not available on this computer") ||
		!strings.Contains(apiErr.Message, "it-security@example.com") {
		t.Fatalf("vm required without KVM: %v", err)
	}

	before := probes
	d.settings = settings("docker", "")
	if choice, err := d.selectDriver(d.settings); err != nil || choice.Driver != openshell.DriverDocker || probes != before {
		t.Fatalf("docker: %+v %v (probed %d)", choice, err, probes-before)
	}
	d.opts.goos = "darwin"
	d.settings = settings("vm", "")
	if choice, err := d.selectDriver(d.settings); err != nil || choice.Driver != openshell.DriverVM || probes != before {
		t.Fatalf("macOS: %+v %v (probed %d)", choice, err, probes-before)
	}
}
