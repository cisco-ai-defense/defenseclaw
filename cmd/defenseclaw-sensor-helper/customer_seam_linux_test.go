//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/defenseclaw/defenseclaw/internal/sensor/kernelpolicy"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tetragon"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// customerLedger is a ledger fed by a mapper with three events of one
// customer policy: two from a host process (one folded) and one from a
// container.
func customerLedger(t *testing.T) *tetragon.CustomerLedger {
	t.Helper()
	ledger := tetragon.NewCustomerLedger()
	mapper := tetragon.NewMapper(tetragon.MapperConfig{Customer: ledger})
	at := time.Date(2026, 10, 7, 1, 24, 10, 0, time.UTC)
	event := func(docker string) *pb.GetEventsResponse {
		return &pb.GetEventsResponse{Time: timestamppb.New(at), Event: &pb.GetEventsResponse_ProcessLsm{ProcessLsm: &pb.ProcessLsm{
			Process: &pb.Process{ExecId: "x", Pid: wrapperspb.UInt32(72936), Uid: wrapperspb.UInt32(1001), Binary: "/usr/bin/cat", Docker: docker,
				Arguments: "/home/dcr-std1/tg2work/dccert-block-marker"},
			PolicyName: "10-file-sensitive", FunctionName: "file_open", Action: pb.KprobeAction_KPROBE_ACTION_POST,
			Args: []*pb.KprobeArgument{{Arg: &pb.KprobeArgument_FileArg{FileArg: &pb.KprobeFile{Path: "/home/dcr-std1/tg2work/dccert-block-marker"}}}},
		}}}
	}
	for _, response := range []*pb.GetEventsResponse{event(""), event(""), event("de1ac97706c1")} {
		mapper.Map(response)
	}
	return ledger
}

// TestKernelStatusCarriesTheCustomerPolicies: kernel_status names the
// customer policies with the ledger's counts as they are now, in every mode
// with an event stream; off reports none. Names, modes and counts only.
func TestKernelStatusCarriesTheCustomerPolicies(t *testing.T) {
	ledger := customerLedger(t)
	now := time.Now()
	status := kernelStatusOf(kernelpolicy.State{}, kernelpolicy.Intent{Mode: kernelpolicy.ModeConsume})
	withCustomer(&status, ledger, now, true)
	if status.IntentMode != "consume" || status.Approval != kernelpolicy.ApprovalNotNeeded {
		t.Fatalf("intent %q approval %q", status.IntentMode, status.Approval)
	}
	if status.Tetragon == nil || status.Tetragon.Installed == nil || !*status.Tetragon.Installed {
		t.Fatalf("tetragon %+v", status.Tetragon)
	}
	if len(status.CustomerPolicies) != 1 || status.CustomerPolicies[0].Name != "10-file-sensitive" ||
		status.CustomerPolicies[0].Seen != 3 || status.CustomerPolicies[0].Forwarded != 1 || status.CustomerPolicies[0].Container != 1 {
		t.Fatalf("customer policies %+v", status.CustomerPolicies)
	}
	if status.CustomerEvents == nil || status.CustomerEvents.Seen != 3 || status.CustomerEvents.Dropped != 0 {
		t.Fatalf("customer events %+v", status.CustomerEvents)
	}
	raw, _ := json.Marshal(status)
	if strings.Contains(string(raw), "dccert-block-marker") || strings.Contains(string(raw), "/usr/bin/cat") {
		t.Fatalf("kernel_status carries what a user did: %s", raw)
	}

	off := kernelStatusOf(kernelpolicy.State{}, kernelpolicy.Intent{Mode: kernelpolicy.ModeOff})
	withCustomer(&off, ledger, now, true)
	if off.CustomerPolicies != nil || off.CustomerEvents != nil || off.Tetragon != nil {
		t.Fatalf("off %+v", off)
	}

	// The reconciler's state reads the same ledger, with the split of what
	// was not forwarded.
	policies, totals := customerSource(ledger)(now)
	if len(policies) != 1 || policies[0].Seen != 3 || policies[0].Listed || totals.Container != 1 || totals.Forwarded != 1 {
		t.Fatalf("state %+v %+v", policies, totals)
	}
}

func TestKernelStatusApprovalAndTotals(t *testing.T) {
	state := kernelpolicy.State{FileState: kernelpolicy.FileState{Effective: "observe"},
		HitTotals: map[string]int64{"would_block_total": 7, "blocked_total": 2}}
	for _, tc := range []struct {
		acks []string
		want string
	}{
		{nil, kernelpolicy.ApprovalMissing},
		{[]string{"sha256:000000000000"}, kernelpolicy.ApprovalStale},
		{[]string{"sha256:000000000000", kernelpolicy.Digest()}, kernelpolicy.ApprovalApproved},
	} {
		status := kernelStatusOf(state, kernelpolicy.Intent{Mode: kernelpolicy.ModeEnforce, EnforceAcks: tc.acks})
		if status.Approval != tc.want || status.IntentMode != "enforce" || status.Mode != "observe" {
			t.Fatalf("%v: approval %q intent %q mode %q", tc.acks, status.Approval, status.IntentMode, status.Mode)
		}
		if status.Counters["would_block_total"] != 7 || status.Counters["blocked_total"] != 2 {
			t.Fatalf("counters %v", status.Counters)
		}
	}
}
