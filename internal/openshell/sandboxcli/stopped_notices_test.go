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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// The notice that the daemon stopped a sandbox DefenseClaw did not start was
// only in the activity feed; the next list and status say it too, once it is
// recent (GAP-0265).
func TestListAndStatusAnnounceAForeignSandboxTheDaemonStopped(t *testing.T) {
	ta := newTestApp(t, "")
	now := ta.Now()
	notice := func(name string, ago time.Duration) sandboxapi.ActivityEvent {
		return sandboxapi.ActivityEvent{
			Seq: 1, Time: now.Add(-ago), Kind: sandboxapi.ActivityFinding, Reason: sandboxrelay.EventForeignSandbox, Sandbox: name,
			Message: "Sandbox " + name + " was stopped: it wasn't started with defenseclaw sandbox run, which your organization requires.",
		}
	}
	ta.daemon.events = []sandboxapi.ActivityEvent{
		notice("old1", 3*24*time.Hour), notice("raw1", time.Hour), notice("raw1", 30*time.Minute),
		{Seq: 2, Time: now, Kind: sandboxapi.ActivityFinding, Reason: "other", Message: "unrelated finding"},
	}

	ta.ok(t, ta.List(bg, OutputText))
	out := ta.output()
	has(t, out, "Sandbox raw1 was stopped: it wasn't started with defenseclaw sandbox run, which your organization requires.", "no sandboxes")
	lacks(t, out, "old1", "unrelated")
	if n := strings.Count(out, "Sandbox raw1 was stopped"); n != 1 {
		t.Errorf("the same notice printed %d times:\n%s", n, out)
	}

	ta.fresh()
	ta.ok(t, ta.Status(bg, "", OutputText))
	has(t, ta.output(), "Sandbox raw1 was stopped")

	// JSON stays one document.
	ta.fresh()
	ta.ok(t, ta.List(bg, OutputJSON))
	lacks(t, ta.output(), "raw1")

	// GAP-0557: a name created again since the notice is not the sandbox it
	// was about.
	ta = newTestApp(t, "")
	now = ta.Now()
	ta.daemon.events = []sandboxapi.ActivityEvent{
		notice("reused", time.Hour),
		{Seq: 2, Time: now.Add(-30 * time.Minute), Kind: sandboxapi.ActivityLifecycle, Sandbox: "reused", Phase: "creating"},
	}
	ta.ok(t, ta.List(bg, OutputText))
	lacks(t, ta.output(), "reused was stopped")
}
