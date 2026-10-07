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

package tetragon

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// testdata/customer-policies.jsonl holds events of the host's own policies,
// shaped on Tetragon 1.7.1's JSON export and sanitized: marker paths and
// marker values only, TEST-NET addresses, no real key or token.

const fixtureMarker = "dccert-block-marker"

var customerModes = map[string]string{
	"10-file-sensitive":             "enforce",
	"11-file-denied":                "enforce",
	"12-file-denied-monitor":        "monitor",
	"13-exec-kill":                  "enforce",
	"defenseclaw-controls-deadbeef": "enforce",
}

func customerMapper(ledger *CustomerLedger, events string) *Mapper {
	return NewMapper(MapperConfig{
		Homes:          []string{fixtureHome},
		PolicyMode:     func(name string) string { return customerModes[name] },
		Owns:           func(name string) bool { return recordedFixture[name] },
		Customer:       ledger,
		CustomerEvents: events,
	})
}

func TestCustomerPolicyEventsAreTypedAndBounded(t *testing.T) {
	ledger := NewCustomerLedger()
	lines := mapFixture(t, customerMapper(ledger, ""), "customer-policies.jsonl")
	if len(lines) != 10 {
		t.Fatalf("%d fixture lines", len(lines))
	}
	marker := fixtureHome + "/tg2work/" + fixtureMarker

	file := one(t, lines[0])
	if file.Kind != plane.KindPolicyEvent || file.PolicyOwner != plane.PolicyOwnerCustomer || file.Policy != "10-file-sensitive" ||
		file.KernelHookType != HookLSM || file.KernelFunction != "file_open" || file.KernelAction != "post" ||
		file.PolicyMode != "enforce" || file.Outcome != plane.OutcomeObserved || file.Target != marker || file.Count != 1 ||
		!reflect.DeepEqual(file.PolicyTags, []string{"files", "sensitive"}) || file.PolicyMessage != "sensitive file access" {
		t.Fatalf("lsm post %+v", file)
	}
	if file.Path != "" || file.Remote != "" || file.Control != "" || file.UID == nil || *file.UID != 1001 || file.User != "dcr-std1" ||
		file.ExecID == "" || file.PPID != 72934 || file.Source != plane.SourceTetragon || !strings.HasPrefix(file.Cmdline, "/usr/bin/cat ") {
		t.Fatalf("process facts %+v", file)
	}

	connect := one(t, lines[1])
	if connect.KernelHookType != HookKprobe || connect.KernelFunction != "tcp_connect" || connect.Target != "203.0.113.10:443" ||
		connect.Kind != plane.KindPolicyEvent || connect.Remote != "" || connect.Outcome != plane.OutcomeObserved {
		t.Fatalf("kprobe connect %+v", connect)
	}
	if denied := one(t, lines[2]); denied.KernelAction != "override" || denied.Outcome != plane.OutcomeBlocked {
		t.Fatalf("override in enforce %+v", denied)
	}
	if monitor := one(t, lines[3]); monitor.PolicyMode != "monitor" || monitor.Outcome != plane.OutcomeWouldBlock {
		t.Fatalf("override in monitor %+v", monitor)
	}
	if kill := one(t, lines[4]); kill.KernelAction != "sigkill" || kill.Outcome != plane.OutcomeBlocked || kill.Target != "/usr/bin/nc" {
		t.Fatalf("sigkill %+v", kill)
	}
	// Named in DefenseClaw's pattern, not recorded: the customer's, and
	// never one of DefenseClaw's kernel controls.
	if shaped := one(t, lines[5]); shaped.PolicyOwner != plane.PolicyOwnerCustomer || shaped.Kind != plane.KindPolicyEvent ||
		shaped.Control != "" || shaped.Outcome != plane.OutcomeBlocked || shaped.Path != "" {
		t.Fatalf("defenseclaw-shaped customer policy %+v", shaped)
	}
	if other := one(t, lines[6]); other.KernelAction != ActionOther || other.Outcome != plane.OutcomeObserved ||
		other.Target != "192.0.2.53:53" || other.PolicyMode != "unknown" {
		t.Fatalf("unknown action %+v", other)
	}
	// No string, byte, integer, capability, label, data, return or stack
	// value of the raw event crosses.
	args := one(t, lines[7])
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), fixtureMarker) || args.Target != "" {
		t.Fatalf("a never-forwarded argument crossed: %s", raw)
	}
	if len(lines[8].batch.Events) != 0 || len(lines[9].batch.Events) != 0 {
		t.Fatalf("container %+v, self %+v", lines[8].batch.Events, lines[9].batch.Events)
	}

	policies, totals := ledger.Snapshot(time.Now())
	if totals.Seen != 10 || totals.Forwarded != 8 || totals.Container != 1 || totals.Self != 1 || totals.Dropped() != 1 {
		t.Fatalf("totals %+v", totals)
	}
	// The override in enforce, the sigkill and the DefenseClaw-shaped
	// customer policy's override: blocked, as their records say.
	if totals.Blocked != 3 {
		t.Fatalf("blocked %d, want the events whose outcome is blocked", totals.Blocked)
	}
	byName := map[string]CustomerPolicyStatus{}
	for _, policy := range policies {
		byName[policy.Name] = policy
	}
	if sensitive := byName["10-file-sensitive"]; sensitive.Seen != 3 || sensitive.Forwarded != 1 || sensitive.Container != 1 ||
		sensitive.Self != 1 || sensitive.Listed || sensitive.LastEvent.IsZero() {
		t.Fatalf("10-file-sensitive %+v", sensitive)
	}
	if len(policies) != 8 {
		t.Fatalf("policies %+v", policies)
	}
}

// TestOwnershipIsTheRecord: without a record nothing is DefenseClaw's, so a
// controls event of an unrecorded name is the customer's, outcome by action.
func TestOwnershipIsTheRecord(t *testing.T) {
	mapper := NewMapper(MapperConfig{Homes: []string{fixtureHome}, Customer: NewCustomerLedger()})
	lines := mapFixture(t, mapper, "tg2-session.jsonl")
	controls := one(t, lines[7])
	if controls.PolicyOwner != plane.PolicyOwnerCustomer || controls.Kind != plane.KindPolicyEvent || controls.Control != "" ||
		controls.Policy != "defenseclaw-controls-0a1b2c3d" || controls.Outcome != plane.OutcomeWouldBlock {
		t.Fatalf("unrecorded controls policy %+v", controls)
	}
}

func TestCustomerEventsOffForwardsNothing(t *testing.T) {
	ledger := NewCustomerLedger()
	for _, line := range mapFixture(t, customerMapper(ledger, OffEvents), "customer-policies.jsonl") {
		if len(line.batch.Events) != 0 {
			t.Fatalf("line %d forwarded %+v", line.line, line.batch.Events)
		}
	}
	if _, totals := ledger.Snapshot(time.Now()); totals.Seen != 10 || totals.Forwarded != 0 || totals.Withheld != 8 ||
		totals.Container != 1 || totals.Self != 1 {
		t.Fatalf("totals %+v", totals)
	}
}

// at returns a copy of a fixture response stamped at t.
func at(response *pb.GetEventsResponse, t time.Time) *pb.GetEventsResponse {
	copied := proto.Clone(response).(*pb.GetEventsResponse)
	copied.Time = timestamppb.New(t)
	return copied
}

// TestCustomerRepeatsFoldIntoACount: repeats of the same policy, process,
// function, action and target within a minute are one record; the next
// window reports how many it folded, on the next event or on a sweep.
func TestCustomerRepeatsFoldIntoACount(t *testing.T) {
	ledger := NewCustomerLedger()
	mapper := customerMapper(ledger, "")
	open := loadFixture(t, "customer-policies.jsonl")[0]
	start := time.Date(2026, 10, 7, 1, 24, 10, 0, time.UTC)
	if events := mapper.Map(at(open, start)).Events; len(events) != 1 || events[0].Count != 1 {
		t.Fatalf("first %+v", events)
	}
	for i := 1; i <= 2; i++ {
		if events := mapper.Map(at(open, start.Add(time.Duration(i)*time.Second))).Events; len(events) != 0 {
			t.Fatalf("repeat %d forwarded %+v", i, events)
		}
	}
	events := mapper.Map(at(open, start.Add(61*time.Second))).Events
	if len(events) != 2 || events[0].Count != 2 || events[1].Count != 1 {
		t.Fatalf("window handover %+v", events)
	}
	// One more repeat, then only unrelated traffic: a sweep reports it.
	if events := mapper.Map(at(open, start.Add(62*time.Second))).Events; len(events) != 0 {
		t.Fatalf("repeat %+v", events)
	}
	exec := execOf(&pb.Process{ExecId: "x", Binary: "/usr/bin/true", Pid: u32(9)}, nil)
	var folded []plane.Event
	for _, event := range mapper.Map(at(exec, start.Add(125*time.Second))).Events {
		if event.Kind == plane.KindPolicyEvent {
			folded = append(folded, event)
		}
	}
	if len(folded) != 1 || folded[0].Count != 1 || folded[0].Policy != "10-file-sensitive" {
		t.Fatalf("swept %+v", folded)
	}
	if _, totals := ledger.Snapshot(start); totals.Seen != 5 || totals.Forwarded != 5 {
		t.Fatalf("totals %+v", totals)
	}
	// A different target is a different record.
	other := at(open, start.Add(200*time.Second))
	other.GetProcessLsm().Args[0].GetFileArg().Path = fixtureHome + "/tg2work/dccert-block-marker-2"
	if events := mapper.Map(other).Events; len(events) != 1 || events[0].Count != 1 {
		t.Fatalf("other target %+v", events)
	}
}

// TestCustomerVolumeBudget: a policy forwards its burst and then its rate;
// the rest is counted exactly and raises the capped count for the hour. The
// host budget bounds every policy together.
func TestCustomerVolumeBudget(t *testing.T) {
	ledger := NewCustomerLedger()
	mapper := customerMapper(ledger, "")
	open := loadFixture(t, "customer-policies.jsonl")[0]
	now := time.Date(2026, 10, 7, 2, 0, 0, 0, time.UTC)
	burst := func(policy string, n int) int {
		forwarded := 0
		for i := 0; i < n; i++ {
			response := at(open, now)
			lsm := response.GetProcessLsm()
			lsm.PolicyName = policy
			lsm.Args[0].GetFileArg().Path = fixtureHome + "/tg2work/" + fixtureMarker + "-" + strconv.Itoa(i)
			forwarded += len(mapper.Map(response).Events)
		}
		return forwarded
	}
	if got := burst("30-noisy", 150); got != CustomerPolicyBurst {
		t.Fatalf("forwarded %d of 150, want the burst %d", got, CustomerPolicyBurst)
	}
	policies, totals := ledger.Snapshot(now)
	if totals.Capped != 50 || totals.CappedLastHour != 50 || totals.Forwarded != 100 || totals.Seen != 150 {
		t.Fatalf("totals %+v", totals)
	}
	if len(policies) != 1 || policies[0].CappedLastHour != 50 || policies[0].Dropped() != 50 {
		t.Fatalf("policies %+v", policies)
	}
	// The host budget (CustomerHostBurst) is shared: one more policy's
	// burst fits, a third's does not.
	if got := burst("31-noisy", 150); got != CustomerHostBurst-CustomerPolicyBurst {
		t.Fatalf("second policy forwarded %d", got)
	}
	if got := burst("32-noisy", 10); got != 0 {
		t.Fatalf("over the host budget, forwarded %d", got)
	}
	// An hour later the capped count is history; the totals stay exact.
	later := now.Add(61 * time.Minute)
	if _, totals := ledger.Snapshot(later); totals.CappedLastHour != 0 || totals.Capped != 50+50+10 {
		t.Fatalf("an hour later %+v", totals)
	}
}

func TestCustomerActionNamesAreTheTelemetryEnum(t *testing.T) {
	names := CustomerActionNames()
	want := []string{"cleanup_enforcer_notification", "copyfd", "dnslookup", "followfd", "geturl", "nopost", "notify_enforcer",
		"other", "override", "post", "set", "sigkill", "signal", "tracksock", "unfollowfd", "untracksock"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("actions %v", names)
	}
	for action := range pb.KprobeAction_name {
		if pb.KprobeAction(action) != pb.KprobeAction_KPROBE_ACTION_UNKNOWN && customerAction(pb.KprobeAction(action)) == ActionOther {
			t.Errorf("Tetragon action %s has no name", pb.KprobeAction(action))
		}
	}
}

func TestCustomerBounds(t *testing.T) {
	long := strings.Repeat("é", 2000)
	if got := boundedText("a\x00b\nc", 64); got != "abc" {
		t.Fatalf("control characters kept: %q", got)
	}
	if got := boundedText(long, MaxTargetBytes); len(got) > MaxTargetBytes || !strings.HasPrefix(long, got) {
		t.Fatalf("bound %d", len(got))
	}
	tags := customerTags([]string{"a", "", "b", "c", "d", "e", "f", "g", "h", "i", strings.Repeat("x", 100)})
	if len(tags) != MaxPolicyTags || tags[0] != "a" || tags[1] != "b" {
		t.Fatalf("tags %v", tags)
	}
	if customerTags([]string{strings.Repeat("y", 100)})[0] != strings.Repeat("y", MaxPolicyTagBytes) {
		t.Fatal("a tag is cut to its bound")
	}
}
