// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"testing"
	"time"
)

func TestGAP0271PerUserToolCallRequestsReceipt(t *testing.T) {
	opts := Options{answerWatch: &answerWatchdog{}, answerBy: time.Now().Add(time.Second)}
	if !wantsHookDeliveryReceipt(opts) {
		t.Fatal("per-user tool call did not request a delivery receipt")
	}
	opts.SecureClient = true
	if wantsHookDeliveryReceipt(opts) {
		t.Fatal("Secure Client requested a receipt")
	}
}

func TestGAP0271NonToolCallStaysWithoutReceipt(t *testing.T) {
	if wantsHookDeliveryReceipt(Options{}) {
		t.Fatal("event without an answer deadline requested a receipt")
	}
}
