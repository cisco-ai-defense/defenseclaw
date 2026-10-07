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

package acquire

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/plane"
)

func customerEvent(pid int) plane.Event {
	return plane.Event{
		Kind: plane.KindPolicyEvent, PID: pid, PPID: 72934, ResponsiblePID: 72934, Name: "cat",
		Cmdline: "/usr/bin/cat /home/dcr-std1/tg2work/dccert-block-marker", User: "dcr-std1",
		At: time.Unix(0, 1791336250111000000), Exe: "/usr/bin/cat", UID: intPtr(1001), AUID: intPtr(1000),
		ExecID: "ZGMtZmMtcmhlbC10ZzI6MTQ=", ParentExecID: "ZGMtZmMtcmhlbC10ZzI6MTM=", StartNS: 1791336250108000000,
		Source: plane.SourceTetragon, Policy: "10-file-sensitive", PolicyOwner: plane.PolicyOwnerCustomer,
		Outcome: plane.OutcomeBlocked, KernelHookType: "lsm", KernelFunction: "file_open", KernelAction: "override",
		PolicyMode: "enforce", PolicyTags: []string{"files", "sensitive"}, PolicyMessage: "sensitive file opened",
		Target: "/etc/shadow", Count: 3,
	}
}

// TestWireEventCarriesThePolicyEventFields round-trips every field of an
// event of the host's own policy; an event that sets none of them encodes as
// it did before they existed (pinned by TestWireEventCarriesTheTetragonFields).
func TestWireEventCarriesThePolicyEventFields(t *testing.T) {
	event := customerEvent(72936)
	raw, err := json.Marshal(encodeEvent(event))
	if err != nil {
		t.Fatal(err)
	}
	var wire wireEvent
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	decoded := decodeEvent(wire)
	if !reflect.DeepEqual(decoded, event) {
		t.Fatalf("round trip\n got %+v\nwant %+v", decoded, event)
	}
	decoded.PolicyTags[0] = "changed"
	if event.PolicyTags[0] != "files" {
		t.Fatal("the decoded tags alias the encoded ones")
	}
	for _, key := range []string{`"policy_owner":"customer"`, `"kernel_hook_type":"lsm"`, `"kernel_function":"file_open"`,
		`"kernel_action":"override"`, `"policy_mode":"enforce"`, `"policy_tags":["files","sensitive"]`,
		`"policy_message":"sensitive file opened"`, `"target":"/etc/shadow"`, `"count":3`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("%s missing from %s", key, raw)
		}
	}
}

// TestPolicyEventsTravelInTheirOwnFrame: an event of the host's own policy
// reaches the gateway's brokered source as a policy event of the customer,
// and a gateway that predates the member skips it, seeing every other event.
func TestPolicyEventsTravelInTheirOwnFrame(t *testing.T) {
	stub := newStubSource(tetragonCoverage())
	helper := serveStub(t, ServerConfig{}, stubAcquirer{stub})
	source := helper.PlaneSource(nil)
	if err := source.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	stub.events <- customerEvent(72936)
	stub.events <- plane.Event{Kind: plane.KindExec, PID: 42, Source: plane.SourceTetragon, PolicyOwner: plane.PolicyOwnerDefenseClaw}
	var got []plane.Event
	for len(got) < 2 {
		select {
		case event := <-source.Events():
			got = append(got, event)
		case <-time.After(5 * time.Second):
			t.Fatalf("events %+v", got)
		}
	}
	if got[0].Kind != plane.KindPolicyEvent || got[0].PolicyOwner != plane.PolicyOwnerCustomer ||
		got[0].Policy != "10-file-sensitive" || got[0].Target != "/etc/shadow" || got[0].Count != 3 {
		t.Fatalf("policy event %+v", got[0])
	}
	if got[1].Kind != plane.KindExec || got[1].PID != 42 {
		t.Fatalf("exec %+v", got[1])
	}

	// The pre-item-1 gateway's frame type, on a helper of its own (a stub
	// source's events go to whichever subscriber reads first).
	stub = newStubSource(tetragonCoverage())
	helper = serveStub(t, ServerConfig{}, stubAcquirer{stub})
	conn, err := helper.dial(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := writeFrame(conn, Request{Version: protocolVersion, Op: OpEvents}, requestDeadline); err != nil {
		t.Fatal(err)
	}
	var header Response
	if err := readFrame(conn, &header, responseDeadline); err != nil {
		t.Fatal(err)
	}
	type oldFrame struct {
		Event *struct {
			Kind string `json:"kind"`
			PID  int    `json:"pid"`
		} `json:"event"`
	}
	stub.events <- customerEvent(1)
	stub.events <- plane.Event{Kind: plane.KindExec, PID: 2}
	stub.events <- customerEvent(3)
	stub.events <- plane.Event{Kind: plane.KindExit, PID: 4}
	var pids []int
	skipped := 0
	for len(pids) < 2 {
		var response Response
		if err := readFrame(conn, &response, 5*time.Second); err != nil {
			t.Fatalf("after %v: %v", pids, err)
		}
		var frame oldFrame
		if err := json.Unmarshal(response.Body, &frame); err != nil || frame.Event == nil {
			skipped++
			continue
		}
		pids = append(pids, frame.Event.PID)
	}
	if !reflect.DeepEqual(pids, []int{2, 4}) || skipped != 2 {
		t.Fatalf("an old gateway saw %v and skipped %d frames", pids, skipped)
	}
}

// TestKernelStatusCarriesTheCustomerSummary: the customer summary, the
// approval and the progress fields cross unchanged; an older gateway's
// decoder ignores them.
func TestKernelStatusCarriesTheCustomerSummary(t *testing.T) {
	installed := true
	uid := 1001
	want := KernelStatus{
		Available: false, Mode: "consume", IntentMode: "consume", Approval: "not_needed",
		Tetragon: &KernelTetragon{Version: "v1.7.1", PID: 8754, Connected: true, Installed: &installed},
		CustomerPolicies: []KernelCustomerPolicy{
			{Name: "10-file-sensitive", Mode: "enforce", State: "enabled",
				KernelCustomerEvents: KernelCustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2}},
			{Name: "defenseclaw-controls-deadbeef", Mode: "monitor", State: "enabled"},
		},
		CustomerEvents: &KernelCustomerEvents{Seen: 12, Forwarded: 9, Dropped: 1, Container: 2},
		Changes:        []KernelChange{{Seq: 4, Event: "uid_progress", UID: &uid, CoveredSeconds: 3600, NeededSeconds: 604800}},
	}
	helper := serveStub(t, ServerConfig{Tetragon: &TetragonConfig{Mode: "consume",
		KernelStatus: func(context.Context) (KernelStatus, error) { return want, nil }}}, stubAcquirer{newStubSource(native("x"))})
	got, err := helper.KernelStatus(context.Background())
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("status\n got %+v %v\nwant %+v", got, err, want)
	}
	raw, _ := json.Marshal(want)
	for _, key := range []string{`"customer_policies":[{"name":"10-file-sensitive","mode":"enforce","state":"enabled","seen":12,"forwarded":9,"dropped":1,"container":2}`,
		`"customer_events":{"seen":12,"forwarded":9,"dropped":1,"container":2}`, `"approval":"not_needed"`, `"intent_mode":"consume"`,
		`"installed":true`, `"covered_seconds":3600`, `"needed_seconds":604800`} {
		if !strings.Contains(string(raw), key) {
			t.Fatalf("%s missing from %s", key, raw)
		}
	}
	var old struct {
		Available bool   `json:"available"`
		Mode      string `json:"mode"`
	}
	if err := json.Unmarshal(raw, &old); err != nil || old.Mode != "consume" {
		t.Fatalf("an older decoder: %+v %v", old, err)
	}
}
