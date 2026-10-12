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

package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// A sandbox on the Linux docker fallback carries the driver and the reason
// (defenseclaw.sandbox.driver, .driver_reason) on its records; a sandbox
// without a reason carries none, and an unregistered reason is refused.
func TestSandboxRecordsCarryTheDriverReason(t *testing.T) {
	harness := newSandboxHarness(t)
	identity := testSandboxIdentity()
	identity.DriverReason = "kvm_missing"
	_, record := harness.recordOne(t, router.AdmissionOrdinary, SandboxLifecycleEvent{Sandbox: identity, Trigger: SandboxTriggerCreate})
	assertSandboxFields(t, sandboxBody(t, record), map[string]any{
		"defenseclaw.sandbox.driver":        "docker",
		"defenseclaw.sandbox.driver_reason": "kvm_missing",
	})
	identity.DriverReason = ""
	_, record = harness.recordOne(t, router.AdmissionOrdinary, SandboxLifecycleEvent{Sandbox: identity, Trigger: SandboxTriggerCreate})
	assertSandboxFields(t, sandboxBody(t, record), map[string]any{"defenseclaw.sandbox.driver_reason": nil})

	identity.DriverReason = "because"
	_, recorder := harness.bind(t, router.AdmissionOrdinary)
	if err := recorder.RecordSandboxLifecycle(context.Background(), SandboxLifecycleEvent{Sandbox: identity, Trigger: SandboxTriggerCreate}); err == nil ||
		!strings.Contains(err.Error(), "driver reason") {
		t.Fatalf("an unregistered driver reason: %v", err)
	}
}
