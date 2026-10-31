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

//go:build linux || darwin

package gateway

import (
	"context"
	"slices"
	"testing"
	"time"
)

// #1204: `sandbox connect` of a stopped MicroVM starts it under its
// registration, which Start reports running first. The MicroVM is listed
// stopped until it is up, and a policy poll in between reported it stopped,
// so the agent's first prompt was refused with a 403. While a Start is
// starting a sandbox, the poll reports it running.
func TestSandboxDaemonPollReportsAStartingSandboxRunning(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	f.d.starting.Store("dc-a", struct{}{})
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-1=running"}) {
		t.Fatalf("reports while starting = %v", got)
	}
	f.d.starting.Delete("dc-a")
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-1=running", "reg-1=stopped"}) {
		t.Fatalf("reports after the start = %v", got)
	}
}

// GAP-0433: a poll lists the phases first and reads the starting marker per
// registration later. A Start that ended in between had reported the
// sandbox running last, and the poll's report from the older list (stopped)
// then undid it. A poll whose list predates a Start's end reports nothing
// for that sandbox; the next poll reports it from a new list.
func TestSandboxDaemonPollKeepsTheReportOfAStartThatEndedAfterItsList(t *testing.T) {
	f := newSandboxDaemonFixture(t)
	if err := f.d.regs.put(daemonRegistration{ID: "reg-1", Sandbox: "dc-a", UpdatedAt: time.Now(), Confirmed: true}); err != nil {
		t.Fatal(err)
	}
	first := true
	f.d.opts.listPhases = func(context.Context) (map[string]string, bool) {
		if first {
			// The list says stopped; the Start then ends, as its deferred
			// final report does, before the poll reads the marker.
			first = false
			f.d.starting.Store("dc-a", struct{}{})
			f.d.startEnded.Store("dc-a", f.d.startsEnded.Add(1))
			f.d.starting.Delete("dc-a")
		}
		return map[string]string{"dc-a": "stopped"}, true
	}
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); len(got) != 0 {
		t.Fatalf("reports from a list older than the start's end = %v", got)
	}
	f.d.pollOnce(context.Background())
	if got := f.relay.reported(); !slices.Equal(got, []string{"reg-1=stopped"}) {
		t.Fatalf("reports of the next poll = %v", got)
	}
}
