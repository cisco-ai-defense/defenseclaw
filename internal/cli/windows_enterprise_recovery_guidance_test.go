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
	// GAP-1338: the repair names the installed CLI, which Setup keeps off PATH.
	for _, want := range []string{"Next step:", "& '" + managedWindowsAdminCLI() + "' enterprise windows repair --profile standalone", "/repair JSON=1", "start DefenseClawHookGuardian again"} {
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

// GAP-1184: a stopped gateway is named instead of "installer exit 1".
func TestWindowsEnterpriseNotHealthyMessageNamesTheStoppedService(t *testing.T) {
	services := []enterprisestatus.Service{
		{Name: "DefenseClawGateway", Kind: "gateway", State: "stopped", Required: true},
		{Name: "DefenseClawHookGuardian", Kind: "guardian", State: "running", Required: true},
	}
	got := windowsEnterpriseNotHealthyMessage(services, 1)
	if !strings.Contains(got, "the DefenseClawGateway service is stopped") || strings.Contains(got, "installer exit") {
		t.Fatalf("not healthy message = %q", got)
	}
	services[0].State = "running"
	if got := windowsEnterpriseNotHealthyMessage(services, 1); !strings.Contains(got, "& '"+managedWindowsAdminCLI()+"' enterprise windows verify --profile standalone") || strings.Contains(got, "installer exit") {
		t.Fatalf("no stopped service, message = %q", got)
	}
}

// GAP-1276: the enumerator's rule-pack error leads, without its log line.
func TestWindowsEnterpriseEnumeratorFailureTextUnwrapsTheCause(t *testing.T) {
	message := `synchronous target enumeration failed with exit 1603: [hook-enumerator] windows: manifest=C:\ProgramData\Cisco\DefenseClaw\hook-guardian\targets.yaml interval=5m0s once=true initial_delay=30s ` +
		`Error: enterprise windows enumerate: load config: config: managed standalone guardrail.rule_pack_dir C:\pack: the gateway service account NT SERVICE\DefenseClawGateway cannot read C:\pack; grant it Read & execute, for example: icacls "C:\pack" /grant "NT SERVICE\DefenseClawGateway:(OI)(CI)RX" /T`
	text, code, ok := windowsEnterpriseEnumeratorFailureText(message)
	if !ok || code != "rule_pack_unreadable" {
		t.Fatalf("ok=%t code=%q", ok, code)
	}
	if !strings.HasPrefix(text, `the managed config's guardrail.rule_pack_dir C:\pack: the gateway service account NT SERVICE\DefenseClawGateway cannot read`) ||
		!strings.Contains(text, "icacls") || strings.Contains(text, "hook-enumerator") {
		t.Fatalf("text = %q", text)
	}
	if _, _, ok := windowsEnterpriseEnumeratorFailureText("the gateway did not start"); ok {
		t.Fatal("an unrelated message was rewritten")
	}
}
