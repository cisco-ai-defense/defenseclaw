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

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Verify with the guardian stopped names the repair that starts it again
// (GAP-1072); with every service running it adds nothing.
func TestWindowsEnterpriseStoppedServiceNextStep(t *testing.T) {
	services := []enterprisestatus.Service{
		{Name: "DefenseClawGateway", Kind: "gateway", State: "running", Required: true},
		{Name: "DefenseClawHookGuardian", Kind: "guardian", State: "stopped", Required: true},
	}
	got := windowsEnterpriseStoppedServiceNextStep(services)
	for _, want := range []string{"Next step:", "enterprise windows repair --profile standalone", "/repair JSON=1", "start DefenseClawHookGuardian again"} {
		if !strings.Contains(got, want) {
			t.Fatalf("next step %q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "DefenseClawGateway") {
		t.Fatalf("next step names a running service: %q", got)
	}
	services[1].State = "running"
	if got := windowsEnterpriseStoppedServiceNextStep(services); got != "" {
		t.Fatalf("all running, next step = %q", got)
	}
}
