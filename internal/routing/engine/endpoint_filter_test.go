// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
)

// rel-1-0-10:GAP-1167: a backend the gateway cannot address is skipped with
// filtered_by endpoint (a reason routing explain shows), like an API or
// capability mismatch, and is not a missing-credential case.
func TestEndpointFilterSkipsAnUnaddressableBackendWithAReason(t *testing.T) {
	noEndpoint := func(b Backend, _ Request) bool { return b.Alias != "claude" }
	e := mustEngine(t, testConfig(), Options{EndpointOK: noEndpoint})
	d := e.Decide(context.Background(), chat("refactor"))
	if d.FilteredBy != "endpoint" || !d.OtherUnfit || len(d.NoCredential) != 0 {
		t.Fatalf("decision = %+v", d)
	}
	if d.Backend != nil && d.Backend.Alias == "claude" {
		t.Fatalf("the unaddressable backend was chosen: %+v", d.Backend)
	}
	if ok := mustEngine(t, testConfig(), Options{}).Decide(context.Background(), chat("refactor")); ok.Outcome != OutcomeApplied || ok.Backend == nil || ok.Backend.Alias != "claude" || ok.FilteredBy != "" {
		t.Fatalf("without the filter: %+v", ok)
	}
}
