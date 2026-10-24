// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

func failedDelivery(t *testing.T, s *Store) *Receipt {
	t.Helper()
	r, err := s.Receive("", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(r, CodeArchiveInvalid, "not a gzip stream"); err != nil {
		t.Fatal(err)
	}
	return r
}

func receiptEventCount(t *testing.T, s *Store) int {
	t.Helper()
	entries, err := os.ReadDir(s.PublicReceiptEventsDir())
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// While the gateway reporter is down, receipt-events/ keeps the events it
// has not reported; once it caught up they are trimmed to MaxReceiptEvents.
// Past the unreported bound the oldest go, and the receipt that removed
// them carries receipt_events_dropped.
func TestReceiptEventsKeepEventsTheGatewayHasNotReported(t *testing.T) {
	saved := maxUnreportedReceiptEvents
	t.Cleanup(func() { maxUnreportedReceiptEvents = saved })
	maxUnreportedReceiptEvents = MaxReceiptEvents + 20
	s := testStore(t)
	reported := map[string]bool{}
	s.ReceiptEventReported = func(id string) bool { return reported[id] }

	for i := 0; i < MaxReceiptEvents+10; i++ {
		if r := failedDelivery(t, s); slices.Contains(r.WarningCodes, WarnReceiptEventsDropped) {
			t.Fatalf("receipt %d carries %s while nothing was dropped", i, WarnReceiptEventsDropped)
		}
	}
	if n := receiptEventCount(t, s); n != MaxReceiptEvents+10 {
		t.Fatalf("receipt-events holds %d events while the reporter was down, want all %d", n, MaxReceiptEvents+10)
	}

	entries, err := os.ReadDir(s.PublicReceiptEventsDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		reported[strings.TrimSuffix(entry.Name(), ".json")] = true
	}
	failedDelivery(t, s)
	if n := receiptEventCount(t, s); n != MaxReceiptEvents {
		t.Fatalf("receipt-events holds %d events after the reporter caught up, want %d", n, MaxReceiptEvents)
	}

	clear(reported)
	var dropping *Receipt
	for i := 0; i < 30; i++ {
		if r := failedDelivery(t, s); dropping == nil && slices.Contains(r.WarningCodes, WarnReceiptEventsDropped) {
			dropping = r
		}
	}
	if n := receiptEventCount(t, s); n > maxUnreportedReceiptEvents {
		t.Fatalf("receipt-events holds %d events, want at most %d", n, maxUnreportedReceiptEvents)
	}
	if dropping == nil {
		t.Fatalf("no receipt reports that unreported events were dropped")
	}
	event, err := enterprisestatus.ReadPublicReceipt(filepath.Join(s.PublicReceiptEventsDir(), dropping.ReceiptID+".json"))
	if err != nil || !slices.Contains(event.WarningCodes, WarnReceiptEventsDropped) {
		t.Fatalf("event of the dropping receipt = %+v, %v", event, err)
	}
}

// Once the receipt and the receipt event of a first delivery are pruned, a
// redelivery of that bundle still gets a new receipt id: the gateway
// reporter, which remembers reported ids, would hide its audit event.
func TestRedeliveredBundleNeverTakesAPrunedReceiptID(t *testing.T) {
	s := testStore(t)
	first, err := s.Receive(testBundleID(1), 1, "")
	if err != nil || first.ReceiptID != testBundleID(1) {
		t.Fatalf("first delivery = %+v, %v", first, err)
	}
	if err := s.Fail(first, CodeArchiveInvalid, "not a gzip stream"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < MaxReceiptEvents+MaxReceipts; i++ {
		failedDelivery(t, s)
	}
	for _, path := range []string{s.receiptPath(first.ReceiptID), filepath.Join(s.PublicReceiptEventsDir(), first.ReceiptID+".json")} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s was not pruned: %v", path, err)
		}
	}
	again, err := s.Receive(testBundleID(1), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if again.ReceiptID == first.ReceiptID || !strings.HasPrefix(again.ReceiptID, "r-") {
		t.Fatalf("the redelivery took receipt id %s again", again.ReceiptID)
	}
}

// A superseded inbox receipt, written after the bundle the run took, does
// not hide that bundle's refusal in Latest or receipt.json.
func TestLatestPrefersARefusalOverASupersededReceipt(t *testing.T) {
	s := testStore(t)
	top, err := s.Receive(testBundleID(3), 3, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(top, CodeArchiveInvalid, "not a gzip stream"); err != nil {
		t.Fatal(err)
	}
	low, err := s.Receive(testBundleID(2), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(low, CodeSuperseded, "the bundle inbox also held version 3"); err != nil {
		t.Fatal(err)
	}
	if _, refusal, err := s.Latest(); err != nil || refusal == nil || refusal.ReceiptID != top.ReceiptID {
		t.Fatalf("latest refusal = %+v, %v; want %s", refusal, err, top.ReceiptID)
	}
	public, err := enterprisestatus.ReadPublicReceipt(s.PublicReceiptPath())
	if err != nil || public.LastRefusal == nil || public.LastRefusal.ReceiptID != top.ReceiptID {
		t.Fatalf("receipt.json last_refusal = %+v, %v", public.LastRefusal, err)
	}
	if _, err := os.Lstat(filepath.Join(s.PublicReceiptEventsDir(), low.ReceiptID+".json")); err != nil {
		t.Fatalf("no event for the superseded receipt: %v", err)
	}
	// Only superseded receipts: that is the refusal.
	only := testStore(t)
	r, err := only.Receive(testBundleID(2), 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := only.Fail(r, CodeSuperseded, "superseded"); err != nil {
		t.Fatal(err)
	}
	if _, refusal, err := only.Latest(); err != nil || refusal == nil || refusal.ReceiptID != r.ReceiptID {
		t.Fatalf("latest refusal with only a superseded receipt = %+v, %v", refusal, err)
	}
}
