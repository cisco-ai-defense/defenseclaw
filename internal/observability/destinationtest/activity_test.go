// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package destinationtest

import "testing"

func TestActivityValidation(t *testing.T) {
	t.Parallel()
	valid := []Activity{
		{Phase: "attempt", Destination: "soc", ProbeID: "probe-1", Mode: "handshake", Result: "attempted"},
		{Phase: "outcome", Destination: "collector_1", ProbeID: "probe:2", Mode: "write_probe", Result: "succeeded"},
		{Phase: "outcome", Destination: "collector-2", ProbeID: "probe.3", Mode: "handshake", Result: "failed", FailureClass: "timeout"},
	}
	for _, activity := range valid {
		if err := activity.Validate(); err != nil {
			t.Fatalf("valid activity rejected: %+v: %v", activity, err)
		}
	}

	invalid := []Activity{
		{},
		{Phase: "attempt", Destination: "SOC", ProbeID: "probe-1", Mode: "handshake", Result: "attempted"},
		{Phase: "attempt", Destination: "soc", ProbeID: "probe-1", Mode: "handshake", Result: "failed", FailureClass: "timeout"},
		{Phase: "outcome", Destination: "soc", ProbeID: "probe-1", Mode: "handshake", Result: "failed"},
		{Phase: "outcome", Destination: "soc", ProbeID: "probe-1", Mode: "handshake", Result: "failed", FailureClass: "secret text"},
		{Phase: "outcome", Destination: "soc", ProbeID: "probe-1", Mode: "unknown", Result: "succeeded"},
	}
	for _, activity := range invalid {
		if err := activity.Validate(); err == nil {
			t.Fatalf("invalid activity accepted: %+v", activity)
		}
	}
}
