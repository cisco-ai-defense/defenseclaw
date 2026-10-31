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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// #1203: right after `ensure` switched the driver (vm to docker), the
// lifecycle's prerequisite record still named the earlier driver, and users
// were told "OpenShell is not set up on this computer" with the exception
// contact. A record of another driver or install mode is a switch under
// way: its reason says so, and the daemon's refusal is a notice (no policy
// block, no contact); no record at all is still a missing setup.
func TestSandboxSetupSwitchIsANoticeNotAMissingSetup(t *testing.T) {
	docker := &config.Config{}
	docker.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverDocker
	vmRecord := sandboxPrerequisitesRecord{Version: 1, Install: config.EnterpriseOpenShellInstallPrerequisite, Driver: "vm"}
	vmRecord.Ready = true
	if got := sandboxPrerequisiteWhy(docker, "linux", "docker", vmRecord, true); got != sandboxrelay.UnavailableSetupChanging {
		t.Fatalf("after a driver switch: %q", got)
	}
	if got := sandboxPrerequisiteWhy(docker, "linux", "docker", sandboxPrerequisitesRecord{}, false); got != sandboxUnavailableNotSetUp {
		t.Fatalf("without a record: %q", got)
	}
	err := managedSettingsRefusal(sandboxrelay.DaemonSettings{Enabled: true, Unavailable: sandboxrelay.UnavailableSetupChanging})
	var apiErr *sandboxapi.Error
	if !errors.As(err, &apiErr) || apiErr.Code != sandboxapi.CodeUnavailable || apiErr.Message != sandboxrelay.UnavailableSetupChanging ||
		apiErr.Detail != sandboxrelay.DetailSetupChanging || strings.Contains(err.Error(), sandboxapi.AdminMessage) {
		t.Fatalf("refusal = %#v", err)
	}
	err = managedSettingsRefusal(sandboxrelay.DaemonSettings{Enabled: true, Unavailable: sandboxUnavailableNotSetUp})
	if !errors.As(err, &apiErr) || apiErr.Message != sandboxapi.AdminMessage || apiErr.Detail != sandboxUnavailableNotSetUp {
		t.Fatalf("a missing setup = %#v", err)
	}
}

// GAP-0434: a switch whose ensure failed never rewrites the record, so the
// switch read as under way for good, with no contact. It reads so for
// sandboxSetupSwitchGrace from when the gateway first sees it, then as not
// set up (the organization's contact); a record that matches again, or
// another switch, starts over.
func TestSandboxSetupSwitchThatDoesNotCompleteReadsAsNotSetUp(t *testing.T) {
	docker := &config.Config{}
	docker.Enterprise.OpenShell.Driver = config.EnterpriseOpenShellDriverDocker
	vmRecord := sandboxPrerequisitesRecord{Version: 1, Install: config.EnterpriseOpenShellInstallPrerequisite, Driver: "vm"}
	vmRecord.Ready = true
	clock := &sandboxSetupSwitchClock{}
	at := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ask := func(record sandboxPrerequisitesRecord, now time.Time) string {
		why := sandboxPrerequisiteWhy(docker, "linux", "docker", record, true)
		return clock.bound(why, sandboxSetupSwitchKey(docker, "linux", record), now)
	}
	if got := ask(vmRecord, at); got != sandboxUnavailableSetupChanging {
		t.Fatalf("a new switch: %q", got)
	}
	if got := ask(vmRecord, at.Add(sandboxSetupSwitchGrace-time.Second)); got != sandboxUnavailableSetupChanging {
		t.Fatalf("within the grace: %q", got)
	}
	if got := ask(vmRecord, at.Add(sandboxSetupSwitchGrace)); got != sandboxUnavailableNotSetUp {
		t.Fatalf("a switch that did not complete: %q", got)
	}
	ready := sandboxPrerequisitesRecord{Version: 1, Install: config.EnterpriseOpenShellInstallPrerequisite, Driver: "docker"}
	ready.Ready = true
	if got := ask(ready, at.Add(sandboxSetupSwitchGrace+time.Minute)); got != "" {
		t.Fatalf("the switch completed: %q", got)
	}
	if got := ask(vmRecord, at.Add(2*sandboxSetupSwitchGrace)); got != sandboxUnavailableSetupChanging {
		t.Fatalf("a later switch starts over: %q", got)
	}
}
