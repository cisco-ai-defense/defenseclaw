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

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// Every reason code and settings field the gateway and the daemon record
// is a counter label by name; anything else is counted as other
// (audit.SandboxManagedMetricReason). A new code must join the list.
func TestSandboxManagedCounterLabelsKnowEveryRegisteredCode(t *testing.T) {
	codes := []string{requireSandboxReasonRequired, sandboxCodeNoDockerGroup, sandboxCodeNoKVMGroup, sandboxAccountBusyCode,
		sandboxAskReasonFloorDenied, sandboxUnavailable("no listed reason").Code,
		sandboxVMRequired(openshell.DriverReasonKVMMissing).Code, sandboxVMRequired(openshell.DriverReasonKVMAccess).Code,
		sandboxVMRequired("other").Code}
	for _, code := range sandboxUnavailableCodes {
		codes = append(codes, code)
	}
	for _, code := range codes {
		if got := audit.SandboxManagedMetricReason(code); got != code {
			t.Errorf("reason %q is counted as %q", code, got)
		}
	}
	for _, field := range []string{"gateway configuration", "gateway command", "compute driver", "gateway listener",
		"MicroVM workload identity", "Docker sandbox namespace", "OpenShell telemetry"} {
		if want := driftEventField(field); audit.SandboxManagedMetricDriftField(want) != want {
			t.Errorf("settings field %q (%s) is counted as other", field, want)
		}
	}
}
