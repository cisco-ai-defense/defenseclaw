// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// The config.bundle.receipt record carries the --delivery-id of the apply
// (defenseclaw.policy.bundle.delivery_id and the after state), so an agent
// that reads the audit stream or OTel can match its own deliveries. A value
// that is not a delivery id is left out, as is an apply without one.
func TestLogPolicyBundleReceiptCarriesTheDeliveryID(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	for _, id := range []string{"acme-agent:d-000913", "", "agent 7"} {
		if err := logger.LogPolicyBundleReceipt("operator:root", PolicyBundle{ID: testPolicyBundleID, Version: 5},
			PolicyBundleReceipt{ReceiptID: testPolicyBundleID, DeliveryID: id, State: PolicyBundleConfirmed, EnforcingVersion: 5}); err != nil {
			t.Fatalf("LogPolicyBundleReceipt(%q): %v", id, err)
		}
	}
	_, records := runtime.snapshot()
	if len(records) != 3 {
		t.Fatalf("records = %d, want 3", len(records))
	}
	for i, want := range []bool{true, false, false} {
		encoded, err := records[i].Bytes()
		if err != nil {
			t.Fatal(err)
		}
		has := strings.Contains(string(encoded), `"defenseclaw.policy.bundle.delivery_id":"acme-agent:d-000913"`) &&
			strings.Contains(string(encoded), `delivery_id\":\"acme-agent:d-000913`)
		if has != want || (!want && strings.Contains(string(encoded), "delivery_id")) {
			t.Fatalf("record %d: delivery id present %v, want %v: %s", i, has, want, encoded)
		}
	}
}

// principal_ref is a bounded safe token: a bundle principal with an e-mail
// address or a DOMAIN\user account (control-plane:acme/alice@example.com,
// operator:CORP\admin) is left out of the telemetry record, which still
// records the receipt. The public receipt file and bundle status keep the
// full principal; the management guide documents the limit.
func TestLogPolicyBundleReceiptOmitsPrincipalRefOutsideTheSafeTokenSet(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	principals := []string{"control-plane:acme/alice", "control-plane:acme/alice@example.com", `operator:CORP\admin`}
	for _, principal := range principals {
		if err := logger.LogPolicyBundleReceipt(principal, PolicyBundle{ID: testPolicyBundleID, Version: 5},
			PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed, EnforcingVersion: 5}); err != nil {
			t.Fatalf("LogPolicyBundleReceipt(%q): %v", principal, err)
		}
	}
	_, records := runtime.snapshot()
	if len(records) != len(principals) {
		t.Fatalf("records = %d, want %d", len(records), len(principals))
	}
	for i, want := range []bool{true, false, false} {
		encoded, err := records[i].Bytes()
		if err != nil {
			t.Fatal(err)
		}
		if has := strings.Contains(string(encoded), `"defenseclaw.admin.principal_ref"`); has != want {
			t.Fatalf("%s: principal_ref present %v, want %v: %s", principals[i], has, want, encoded)
		}
	}
}
