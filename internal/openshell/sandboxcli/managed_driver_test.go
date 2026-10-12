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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The Linux docker fallback is named on every managed surface: the
// banner's Driver line, status, explain and the doctor's Sandbox driver row
// (a warning with the contact while the fallback runs, a pass on the
// MicroVM driver).
func TestManagedDriverFallbackSurfaces(t *testing.T) {
	fallback := managedStatusFixture()
	fallback.Driver, fallback.DriverReason, fallback.DriverFallback = "docker", "kvm_missing", "docker"

	sb := &sandboxapi.Sandbox{Name: "dc-claude-a", Driver: "docker", DriverReason: "kvm_missing"}
	if got := managedDriverLine(sb, fallback); got != "docker (fallback: KVM not available on this computer)" {
		t.Errorf("banner Driver line = %q", got)
	}
	if got := managedDriverLine(sb, nil); got != "" {
		t.Errorf("an unmanaged banner names the driver: %q", got)
	}

	var status string
	for _, r := range managedStatusRows(fallback, time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)) {
		status += r[0] + " " + r[1] + "\n"
	}
	has(t, status, "Driver docker (fallback: KVM not available on this computer)")

	c := managedDriverCheck(fallback)
	if c == nil || c.Status != openshell.StatusWarn || c.Fix == nil {
		t.Fatalf("doctor row on the fallback: %+v", c)
	}
	has(t, c.Detail, "docker (fallback: KVM not available on this computer)", "policy unchanged")
	has(t, c.Fix.Summary, "it-security@example.com")

	vm := managedStatusFixture()
	vm.Driver, vm.DriverReason, vm.DriverFallback = "vm", "kvm_available", "none"
	if c := managedDriverCheck(vm); c == nil || c.Status != openshell.StatusPass ||
		c.Detail != "vm (KVM is available on this computer); MicroVM required (no docker fallback)" {
		t.Fatalf("doctor row on the MicroVM driver: %+v", c)
	}
	if c := managedDriverCheck(&sandboxapi.ManagedStatus{}); c != nil {
		t.Fatalf("doctor row without a driver: %+v", c)
	}

	ex := managedExplainFixture()
	ex.Driver, ex.DriverReason, ex.DriverFallback = "docker", "kvm_access", "docker"
	var explain []string
	for _, r := range managedExplainRows(ex, time.Now()) {
		explain = append(explain, r.label+" "+r.text)
	}
	has(t, strings.Join(explain, "\n"), "Driver docker (fallback: KVM not available for your account on this computer: /dev/kvm must be readable and writable for your account)")
	ex.Driver, ex.DriverReason, ex.DriverFallback = "", "", "none"
	explain = nil
	for _, r := range managedExplainRows(ex, time.Now()) {
		explain = append(explain, r.label+" "+r.text)
	}
	has(t, strings.Join(explain, "\n"), "Driver MicroVM required")
	if got := managedStatusOfExplain(&sandboxapi.ManagedExplain{Driver: "vm", DriverReason: "configured"}); got.Driver != "vm" || got.DriverReason != "configured" {
		t.Errorf("explain to status: %+v", got)
	}
}
