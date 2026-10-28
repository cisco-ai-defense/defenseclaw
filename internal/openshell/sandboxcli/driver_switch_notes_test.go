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

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// After the gateway switched compute drivers, the sandboxes of the old driver
// are listed with that driver, and the doctor does not blame a Docker restart
// for them (GAP-0455).
func TestListAndDoctorNameTheDriverOfASandboxTheGatewayNoLongerRuns(t *testing.T) {
	old := sampleSandbox("old-vm")
	old.Driver, old.Phase = "vm", "error"
	now := sampleSandbox("now-docker")
	now.Driver = "docker"
	ta := newTestApp(t, "", old, now)
	ta.daemon.status.Gateway.Driver = "docker"

	ta.ok(t, ta.List(bg, OutputText))
	has(t, ta.output(), "old-vm (vm) was created on a compute driver the gateway no longer runs", "the gateway runs docker now", "one gateway runs one driver")
	lacks(t, ta.output(), "now-docker (", "Docker restarted")

	c := ta.hooksCheck(bg, "127.0.0.1:18971")
	if c.Status != openshell.StatusWarn {
		t.Fatalf("hooks row = %+v", c)
	}
	has(t, c.Detail, "old-vm (vm) was created on a compute driver the gateway no longer runs")
	lacks(t, c.Detail, "Docker restarted", "error state")

	// A real error state of a sandbox of the running driver still says what it did.
	err := sampleSandbox("lost")
	err.Driver, err.Phase = "docker", "error"
	ta = newTestApp(t, "", err)
	ta.daemon.status.Gateway.Driver = "docker"
	has(t, ta.hooksCheck(bg, "").Detail, "lost is in OpenShell's error state")
	ta.out.Reset()
	ta.ok(t, ta.fresh().List(bg, OutputText))
	lacks(t, ta.output(), "no longer runs")

	// GAP-1431: a MicroVM still being created, which has recorded no driver
	// yet, is no obsolete docker sandbox.
	creating := sampleSandbox("fresh-vm")
	creating.Driver, creating.Phase = "", "creating"
	ta = newTestApp(t, "", creating)
	ta.daemon.status.Gateway.Driver = "vm"
	ta.ok(t, ta.List(bg, OutputText))
	lacks(t, ta.output(), "no longer runs", "fresh-vm (docker)")
	if got := otherDriverNote([]sandboxapi.Sandbox{creating}, "vm"); got != "" {
		t.Fatalf("creating MicroVM note = %q", got)
	}

	// GAP-0663: OpenShell drops the old driver's sandbox a few minutes after
	// the switch, so the note never promises that it runs again.
	if got := otherDriverNote([]sandboxapi.Sandbox{old}, "docker"); !strings.Contains(got, "OpenShell drops it a few minutes after the switch") ||
		strings.Contains(got, "run again") || strings.Contains(got, "switched back") {
		t.Fatalf("note = %q", got)
	}
}
