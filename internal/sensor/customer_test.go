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

package sensor

import (
	"reflect"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

const customerMarker = "/home/dev/tg2work/dccert-block-marker"

func customerPolicyEvent(pid int, execID string, outcome plane.KernelOutcome, at time.Time) plane.Event {
	action := "post"
	if outcome != plane.OutcomeObserved {
		action = "override"
	}
	return plane.Event{
		Kind: plane.KindPolicyEvent, PolicyOwner: plane.PolicyOwnerCustomer, Policy: "10-file-sensitive",
		KernelHookType: "lsm", KernelFunction: "file_open", KernelAction: action, PolicyMode: "enforce", Outcome: outcome,
		Target: customerMarker, PolicyTags: []string{"files"}, PolicyMessage: "sensitive file access", Count: 1,
		PID: pid, ExecID: execID, Name: "cat", Exe: "/usr/bin/cat", Cmdline: "/usr/bin/cat " + customerMarker,
		UID: uidp(1001), User: "dev", Source: plane.SourceTetragon, At: at,
	}
}

// TestCustomerEventsAreAttributedGatedAndNeverScored: an event of the host's
// own policy below Claude is a record attributed to the agent, its user and
// the hook decision of its tool call (exact, or none for a call no decision
// covered); one in the user's own shell is only counted; container and
// DefenseClaw processes are counted apart. None of it reaches a score, a
// Plane B connect or DefenseClaw's kernel control outcomes.
func TestCustomerEventsAreAttributedGatedAndNeverScored(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	connect := customerPolicyEvent(1303, "cat", plane.OutcomeObserved, base.Add(5*time.Second))
	connect.KernelHookType, connect.KernelFunction, connect.Target = "kprobe", "tcp_connect", "203.0.113.10:443"
	container := customerPolicyEvent(4000, "ctr", plane.OutcomeBlocked, base)
	container.ContainerID = "de1ac97706c1"
	self := customerPolicyEvent(4100, "self", plane.OutcomeObserved, base)
	self.Self = true
	folded := customerPolicyEvent(1300, "root", plane.OutcomeObserved, base.Add(6*time.Second))
	folded.Count = 4
	script := []plane.Event{
		{Kind: plane.KindExec, PID: 1300, PPID: 1, Name: "2.1.292", Exe: claudeExe, ExecID: "root", UID: uidp(1001), At: base},
		{Kind: plane.KindExec, PID: 1301, PPID: 1300, Name: "defenseclaw-hook", Exe: "/opt/defenseclaw/bin/defenseclaw-hook",
			Cmdline: "/opt/defenseclaw/bin/defenseclaw-hook hook --connector claudecode --enterprise-managed",
			Hook:    plane.HookVerified, ExecID: "hook", ParentExecID: "root", UID: uidp(1001), At: base},
		{Kind: plane.KindExec, PID: 1302, PPID: 1300, Name: "bash", Exe: "/usr/bin/bash",
			Cmdline: claudeToolShell("cat " + customerMarker), ExecID: "tool", ParentExecID: "root", UID: uidp(1001),
			At: base.Add(3 * time.Second)},
		{Kind: plane.KindExec, PID: 1303, PPID: 1302, Name: "cat", Exe: "/usr/bin/cat", Cmdline: "/usr/bin/cat " + customerMarker,
			ExecID: "cat", ParentExecID: "tool", UID: uidp(1001), At: base.Add(3 * time.Second)},
		customerPolicyEvent(1303, "cat", plane.OutcomeBlocked, base.Add(3*time.Second)),
		connect,
		// The agent root's own open: attributed, no tool call to join.
		folded,
		// The user's ! command: a tool call no decision covered.
		{Kind: plane.KindExec, PID: 1306, PPID: 1300, Name: "bash", Exe: "/usr/bin/bash",
			Cmdline: claudeToolShell("cat " + customerMarker + "-2"), ExecID: "bang", ParentExecID: "root",
			UID: uidp(1001), At: base.Add(40 * time.Second)},
		{Kind: plane.KindExec, PID: 1307, PPID: 1306, Name: "cat", Exe: "/usr/bin/cat", ExecID: "bangcat",
			ParentExecID: "bang", UID: uidp(1001), At: base.Add(40 * time.Second)},
		customerPolicyEvent(1307, "bangcat", plane.OutcomeWouldBlock, base.Add(40*time.Second)),
		// The user's own shell: gated.
		{Kind: plane.KindExec, PID: 2000, PPID: 1, Name: "bash", Exe: "/usr/bin/bash", ExecID: "shell", UID: uidp(1001), At: base},
		{Kind: plane.KindExec, PID: 2001, PPID: 2000, Name: "cat", Exe: "/usr/bin/cat", ExecID: "shellcat", ParentExecID: "shell",
			UID: uidp(1001), At: base},
		customerPolicyEvent(2001, "shellcat", plane.OutcomeBlocked, base.Add(time.Second)),
		container,
		self,
	}
	source := newFake(fullCoverage(), script...)
	host := newHost(source)
	host.hooks = newHookRing(hookRingSize, hookRingWindow)
	host.hooks.record(HookDecision{
		Connector: "claudecode", SessionID: "sess-1", ToolInvocationID: "tool-1",
		CommandHash: HookCommandHash("cat " + customerMarker), PeerPID: 1301, PeerUID: 1001, At: base,
		Action: "alert", RuleIDs: []string{"R-1", "R-2", "R-3", "R-4"},
	})
	drainAll(t, host, len(script))

	records, dropped := host.drainCustomer()
	if dropped != 0 || len(records) != 4 {
		t.Fatalf("records %d dropped %d: %+v", len(records), dropped, records)
	}
	blocked := records[0]
	if blocked.Policy != "10-file-sensitive" || blocked.Outcome != plane.OutcomeBlocked || blocked.AgentName != "claude" ||
		blocked.Connector != "claudecode" || blocked.RootPID != 1300 || blocked.SessionRootPID != 1300 || blocked.ToolPID != 1302 ||
		blocked.Target != customerMarker || blocked.Function != "file_open" || blocked.Action != "override" ||
		blocked.UID == nil || *blocked.UID != 1001 || blocked.Process != "cat" {
		t.Fatalf("attributed record %+v", blocked)
	}
	if hook := blocked.Hook; hook == nil || !hook.Seen || hook.Confidence != HookJoinExact || hook.SessionID != "sess-1" ||
		hook.ToolInvocationID != "tool-1" || hook.Action != "alert" || !reflect.DeepEqual(hook.RuleIDs, []string{"R-1", "R-2", "R-3"}) {
		t.Fatalf("hook join %+v", blocked.Hook)
	}
	if records[1].Target != "203.0.113.10:443" || records[1].Hook == nil || !records[1].Hook.Seen {
		t.Fatalf("connect record %+v", records[1])
	}
	if records[2].ToolPID != 0 || records[2].Hook != nil || records[2].Count != 4 {
		t.Fatalf("the agent's own open %+v", records[2])
	}
	if hook := records[3].Hook; hook == nil || hook.Seen || records[3].Outcome != plane.OutcomeWouldBlock {
		t.Fatalf("a tool call no decision covered %+v", records[3])
	}

	recent, counts, total := host.customerSnapshot()
	if len(recent) != 4 {
		t.Fatalf("recent %d", len(recent))
	}
	want := CustomerPolicyCounts{Seen: 10, Attributed: 7, Gated: 1, Container: 1, Self: 1}
	if total != want || counts["10-file-sensitive"] != want {
		t.Fatalf("counts %+v total %+v, want %+v", counts, total, want)
	}
	// Not scored, not Plane B, not one of DefenseClaw's kernel outcomes.
	if classified, gated, _, _ := host.stats(); classified != 0 || gated != 0 {
		t.Fatalf("classified %d gated %d", classified, gated)
	}
	if findings := host.harvest(base.Add(time.Minute), 1); len(findings) != 0 {
		t.Fatalf("findings %+v", findings)
	}
	if connects, _ := host.drainConnects(); len(connects) != 0 {
		t.Fatalf("connects %+v", connects)
	}
	if kernel, _ := host.drainKernelEvents(); len(kernel) != 0 {
		t.Fatalf("kernel control outcomes %+v", kernel)
	}
	if got := host.containerEvents.Load(); got != 0 {
		t.Fatalf("customer container events counted as host-plane container events: %d", got)
	}
	// The attributed denial waits for the developer notice; the gated one
	// does not (it has no agent to tell).
	blocks := host.recentBlocks(base)
	if len(blocks) != 1 || blocks[0].Owner != plane.PolicyOwnerCustomer || blocks[0].SessionID != "sess-1" ||
		blocks[0].Policy != "10-file-sensitive" || blocks[0].Function != "file_open" || blocks[0].ID == "" {
		t.Fatalf("blocks %+v", blocks)
	}
	if again, _ := host.drainCustomer(); len(again) != 0 {
		t.Fatalf("a drain returned %d again", len(again))
	}
}

// TestCustomerRecordsAreBounded: past the per-poll bound records are counted,
// and the recent list keeps the newest.
func TestCustomerRecordsAreBounded(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	script := []plane.Event{{Kind: plane.KindExec, PID: 1300, PPID: 1, Name: "2.1.292", Exe: claudeExe, ExecID: "root", At: base}}
	for i := 0; i < maxCustomerRecordsPerPoll+10; i++ {
		script = append(script, customerPolicyEvent(1300, "root", plane.OutcomeObserved, base.Add(time.Duration(i)*time.Millisecond)))
	}
	host := newHost(newFake(fullCoverage(), script...))
	drainAll(t, host, len(script))
	records, dropped := host.drainCustomer()
	if len(records) != maxCustomerRecordsPerPoll || dropped != 10 {
		t.Fatalf("records %d dropped %d", len(records), dropped)
	}
	recent, _, _ := host.customerSnapshot()
	if len(recent) != maxCustomerRecent || !recent[len(recent)-1].At.Equal(script[len(script)-1].At) {
		t.Fatalf("recent %d", len(recent))
	}
}

// TestBackendMergesTheHelpersAndTheGatewaysCounts: the helper's policies and
// counts from kernel_status, the gateway's attributed and gated beside them,
// and a policy only the gateway counted added.
func TestBackendMergesTheHelpersAndTheGatewaysCounts(t *testing.T) {
	t.Parallel()
	kernel := &KernelState{Status: acquire.KernelStatus{
		CustomerPolicies: []acquire.KernelCustomerPolicy{
			{Name: "10-file-sensitive", Mode: "enforce", State: "enabled",
				KernelCustomerEvents: acquire.KernelCustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2}},
			{Name: "20-net-connect", Mode: "monitor", State: "enabled"},
		},
		CustomerEvents: &acquire.KernelCustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2},
	}}
	backend := &plane.Backend{Kind: plane.BackendTetragon}
	mergeCustomer(backend, kernel, map[string]CustomerPolicyCounts{
		"10-file-sensitive": {Seen: 9, Attributed: 7, Gated: 2},
		"30-late":           {Seen: 1, Gated: 1},
	}, CustomerPolicyCounts{Seen: 10, Attributed: 7, Gated: 3})
	want := []plane.CustomerPolicy{
		{Name: "10-file-sensitive", Mode: "enforce", State: "enabled",
			CustomerEvents: plane.CustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2, Attributed: 7, Gated: 2}},
		{Name: "20-net-connect", Mode: "monitor", State: "enabled"},
		{Name: "30-late", CustomerEvents: plane.CustomerEvents{Gated: 1}},
	}
	if !reflect.DeepEqual(backend.CustomerPolicies, want) {
		t.Fatalf("policies\n got %+v\nwant %+v", backend.CustomerPolicies, want)
	}
	if backend.CustomerEvents != (plane.CustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2, Attributed: 7, Gated: 3}) {
		t.Fatalf("events %+v", backend.CustomerEvents)
	}
	// No helper answer yet: the gateway's counts alone.
	alone := &plane.Backend{Kind: plane.BackendTetragon}
	mergeCustomer(alone, nil, nil, CustomerPolicyCounts{})
	if len(alone.CustomerPolicies) != 0 || alone.CustomerEvents != (plane.CustomerEvents{}) {
		t.Fatalf("alone %+v", alone)
	}
}
