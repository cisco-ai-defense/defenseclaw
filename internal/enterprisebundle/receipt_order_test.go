// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A delivery made while the clock ran a day ahead must not stay the latest
// receipt once the clock is back and a newer delivery is confirmed: status
// orders receipts by delivery, not by their timestamps.
func TestReceiptsOrderByDeliveryNotByClock(t *testing.T) {
	s := testStore(t)
	clock := time.Date(2026, 10, 21, 7, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { clock = clock.Add(time.Second); return clock }
	applyThrough(t, s, 1, 1, StateConfirmed)
	normal := clock
	clock = clock.Add(24 * time.Hour)
	applyThrough(t, s, 2, 2, StateConfirmed)
	clock = normal.Add(time.Minute)
	newest := applyThrough(t, s, 3, 3, StateConfirmed)

	last, _, err := s.Latest()
	if err != nil || last == nil || last.ReceiptID != newest.ReceiptID {
		t.Fatalf("latest = %+v, %v; want receipt %s", last, err, newest.ReceiptID)
	}
	summary, err := s.Summary()
	if err != nil || summary == nil || summary.BundleID != newest.BundleID || summary.Version != 3 {
		t.Fatalf("summary = %+v, %v", summary, err)
	}
	receipts, err := s.Receipts()
	if err != nil || len(receipts) != 3 || receipts[0].Sequence != 3 || receipts[2].Sequence != 1 {
		t.Fatalf("receipts = %+v, %v", receipts, err)
	}
}

// Receipts from a release before the delivery sequence keep their time
// order and sort below every receipt that has one.
func TestReceiptsWithoutSequenceSortBelowNewerOnes(t *testing.T) {
	out := []*Receipt{
		{ReceiptID: testBundleID(1), Transitions: []Transition{{State: StateReceived, At: "2026-10-22T00:00:00.000Z"}}},
		{ReceiptID: testBundleID(2), Sequence: 1, Transitions: []Transition{{State: StateReceived, At: "2026-10-21T00:00:00.000Z"}}},
		{ReceiptID: testBundleID(3), Transitions: []Transition{{State: StateReceived, At: "2026-10-23T00:00:00.000Z"}}},
	}
	sortReceipts(out)
	var got []string
	for _, r := range out {
		got = append(got, r.ReceiptID)
	}
	want := []string{testBundleID(2), testBundleID(3), testBundleID(1)}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}

// The delivery sequence is in the root-only receipt file only: the status
// receipt document has a closed schema.
func TestReceiptSequenceIsStoredButNotInStatusJSON(t *testing.T) {
	s := testStore(t)
	r := applyThrough(t, s, 1, 1, StateReceived)
	raw, err := os.ReadFile(s.receiptPath(r.ReceiptID))
	if err != nil || !strings.Contains(string(raw), `"sequence": 1`) {
		t.Fatalf("receipt file = %s, %v", raw, err)
	}
	out, err := json.Marshal(r)
	if err != nil || strings.Contains(string(out), "sequence") {
		t.Fatalf("status JSON of a receipt = %s, %v", out, err)
	}
}

// A crash during the atomic replace of receipt.json, or of a receipt event,
// leaves a temp file that the next collection removes.
func TestPublicReceiptTempFilesAreCollected(t *testing.T) {
	s := testStore(t)
	applyThrough(t, s, 1, 1, StateConfirmed)
	summaryTemp := filepath.Join(s.BundlesDir, "."+enterprisestatus.PublicReceiptName+".123456.tmp")
	eventTemp := filepath.Join(s.PublicReceiptEventsDir(), "."+testBundleID(9)+".json.42.tmp")
	inbox := filepath.Join(s.BundlesDir, "inbox")
	for _, path := range []string{summaryTemp, eventTemp} {
		if err := os.WriteFile(path, []byte("{"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(inbox, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Settle(); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{summaryTemp, eventTemp} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s survived collection: %v", filepath.Base(path), err)
		}
	}
	for _, path := range []string{s.PublicReceiptPath(), inbox, filepath.Join(s.PublicReceiptEventsDir(), testBundleID(1)+".json")} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("collection removed %s: %v", filepath.Base(path), err)
		}
	}
}

// receipt-events/ keeps a bounded number of events, and always the event of
// the bundle that enforces.
func TestReceiptEventsAreBounded(t *testing.T) {
	s := testStore(t)
	current := applyThrough(t, s, 1, 1, StateConfirmed)
	for i := 0; i < MaxReceiptEvents+10; i++ {
		r, err := s.Receive("", 0, "")
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Fail(r, CodeArchiveInvalid, "not a gzip stream"); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(s.PublicReceiptEventsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) > MaxReceiptEvents+1 {
		t.Fatalf("receipt-events holds %d events, want at most %d", len(entries), MaxReceiptEvents+1)
	}
	if _, err := os.Lstat(filepath.Join(s.PublicReceiptEventsDir(), current.ReceiptID+".json")); err != nil {
		t.Fatalf("the event of the current bundle was pruned: %v", err)
	}
	receipts, err := s.Receipts()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range receipts {
		if _, err := os.Lstat(filepath.Join(s.PublicReceiptEventsDir(), r.ReceiptID+".json")); err != nil {
			t.Fatalf("the event of kept receipt %s was pruned: %v", r.ReceiptID, err)
		}
	}
}

// A receipt event that cannot be written leaves receipt_publish_failed on
// the receipt, so the apply result and bundle status report it.
func TestReceiptPublishFailureIsRecordedOnTheReceipt(t *testing.T) {
	s := testStore(t)
	s.EnsurePublicReceiptEventsDirectory = func(string) error { return errors.New("read-only file system") }
	r := applyThrough(t, s, 1, 1, StateApplied)
	if _, err := s.Confirm(r); err != nil {
		t.Fatalf("a failed receipt event failed the confirm: %v", err)
	}
	receipts, err := s.Receipts()
	if err != nil || len(receipts) != 1 || !slices.Contains(receipts[0].WarningCodes, WarnReceiptPublishFailed) {
		t.Fatalf("receipts = %+v, %v", receipts, err)
	}
	summary, err := s.Summary()
	if err != nil || summary == nil || !slices.Contains(summary.WarningCodes, WarnReceiptPublishFailed) {
		t.Fatalf("summary = %+v, %v", summary, err)
	}

	s.EnsurePublicReceiptEventsDirectory = nil
	next := applyThrough(t, s, 2, 2, StateConfirmed)
	if slices.Contains(next.WarningCodes, WarnReceiptPublishFailed) {
		t.Fatalf("a published receipt carries %s", WarnReceiptPublishFailed)
	}
}
