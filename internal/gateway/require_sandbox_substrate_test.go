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
	"encoding/json"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// E26: on a managed computer whose floor requires an agent in a sandbox
// and allows only Agent Substrate (runtimes: [substrate]), a host run is
// refused with the launcher command, whether or not OpenShell could run
// here, and the refusal is on the audit row.
func TestRequireSandboxSubstrateOnlyPointsToTheLauncher(t *testing.T) {
	for _, devices := range []struct {
		name   string
		access func(string, int) sandboxDeviceAccess
	}{{"openshell-usable", sandboxDevicesUsable}, {"openshell-missing", sandboxDevicesMissing}} {
		useSandboxAvailability(t, devices.access)
		for _, hook := range requireSandboxHooks {
			t.Run(devices.name+"/"+hook.connector, func(t *testing.T) {
				api, store := requireSandboxTestAPI(t, "", hook.connector)
				api.scannerCfg.OpenShell.Admin.Runtimes = []string{config.SandboxRuntimeSubstrate}
				out := postRequireSandboxHook(t, api, hook, requireSandboxProject(t), nil, nil)
				want := sandboxapi.HostRunRefusedSubstrate(hook.connector, "", "", "it-security@example.com")
				if out["action"] != "block" || out["reason"] != want {
					t.Fatalf("host run not refused for Substrate:\n got action=%v reason=%v\nwant %q", out["action"], out["reason"], want)
				}
				var body strings.Builder
				enc := json.NewEncoder(&body)
				enc.SetEscapeHTML(false)
				if err := enc.Encode(out); err != nil || !strings.Contains(body.String(), "defenseclaw substrate run ") ||
					strings.Contains(body.String(), "defenseclaw sandbox run") {
					t.Fatalf("the agent output lacks the launcher command: %s", body.String())
				}
				if got := requireSandboxAuditOutcome(t, store); got != requireSandboxRefused {
					t.Fatalf("audit require_sandbox = %q, want %q", got, requireSandboxRefused)
				}
			})
		}
	}
}

// runtimes: [openshell, substrate] keeps the OpenShell refusal.
func TestRequireSandboxBothRuntimesKeepsTheSandboxCommand(t *testing.T) {
	useSandboxAvailability(t, sandboxDevicesUsable)
	hook := requireSandboxHooks[0]
	api, _ := requireSandboxTestAPI(t, "", hook.connector)
	api.scannerCfg.OpenShell.Admin.Runtimes = []string{config.SandboxRuntimeOpenShell, config.SandboxRuntimeSubstrate}
	project := requireSandboxProject(t)
	out := postRequireSandboxHook(t, api, hook, project, nil, nil)
	if want := sandboxapi.HostRunRefused(hook.connector, "", project, "it-security@example.com"); out["reason"] != want {
		t.Fatalf("reason = %v, want %q", out["reason"], want)
	}
}

func TestHostRunRefusedSubstrateText(t *testing.T) {
	got := sandboxapi.HostRunRefusedSubstrate("claudecode", "", "engineering", "it@example.com")
	for _, want := range []string{"Claude Code can't run on this computer (profile engineering)", "on Agent Substrate",
		"\n  defenseclaw substrate run claude\n", "Contact it@example.com"} {
		if !strings.Contains(got, want) {
			t.Fatalf("refusal %q lacks %q", got, want)
		}
	}
	if app := sandboxapi.HostRunRefusedSubstrate("claudecode", "desktop", "", ""); !strings.Contains(app, "Claude Code desktop app can't run on this computer") {
		t.Fatalf("desktop refusal = %q", app)
	}
}
