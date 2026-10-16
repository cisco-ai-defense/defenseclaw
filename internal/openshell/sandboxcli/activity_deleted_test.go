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

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// es-demo:GAP-0017: the feed lives since the daemon started and keeps the
// sandboxes deleted since (for the audit trail), so a second take's
// `sandbox activity` started below every line of the first take. The plain
// listing leaves a deleted sandbox's events out, up to its deletion (a name
// used again after it shows its new life), and says how to see them;
// -o json still lists the whole feed.
func TestActivityLeavesOutDeletedSandboxes(t *testing.T) {
	ta := newTestApp(t, "")
	at := ta.Now()
	ev := func(seq uint64, kind, sandbox, phase, host string) sandboxapi.ActivityEvent {
		return sandboxapi.ActivityEvent{Seq: seq, Kind: kind, Sandbox: sandbox, Phase: phase, Host: host, Time: at,
			Category: "webhook_catcher", Reason: "webhook_catcher"}
	}
	ta.daemon.events = []sandboxapi.ActivityEvent{
		ev(1, sandboxapi.ActivityLifecycle, "take-1", "creating", ""),
		ev(2, sandboxapi.ActivityEgressBlocked, "take-1", "", "first-take.example"),
		ev(3, sandboxapi.ActivityLifecycle, "take-1", "deleted", ""),
		ev(4, sandboxapi.ActivityLifecycle, "reused", "creating", ""),
		ev(5, sandboxapi.ActivityEgressBlocked, "reused", "", "reused-old.example"),
		ev(6, sandboxapi.ActivityLifecycle, "reused", "deleted", ""),
		ev(7, sandboxapi.ActivityLifecycle, "reused", "creating", ""),
		ev(8, sandboxapi.ActivityEgressBlocked, "reused", "", "reused-new.example"),
		ev(9, sandboxapi.ActivityEgressBlocked, "take-2", "", "second-take.example"),
	}
	ta.ok(t, ta.Activity(bg, ActivityOptions{}))
	out := ta.output()
	has(t, out, "second-take.example", "reused-new.example",
		"the events of deleted sandboxes (reused, take-1) are left out; defenseclaw sandbox activity --sandbox NAME or -o json shows them")
	lacks(t, out, "first-take.example", "reused-old.example")

	ta.fresh()
	ta.ok(t, ta.Activity(bg, ActivityOptions{Output: OutputJSON}))
	if out := ta.output(); !strings.Contains(out, "first-take.example") || !strings.Contains(out, "reused-old.example") {
		t.Fatalf("json activity lost history:\n%s", out)
	}

	got, gone := withoutDeletedSandboxes(ta.daemon.events)
	if len(got) != 3 || len(gone) != 2 {
		t.Fatalf("kept %+v gone %v", got, gone)
	}
}
