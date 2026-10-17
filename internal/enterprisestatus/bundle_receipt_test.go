// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisestatus

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F10: a delivery id is 1 to 128 bytes of A-Z a-z 0-9 . _ : - and nothing
// else, so it is safe in a file, a log line and a JSON string as given.
func TestCheckDeliveryID(t *testing.T) {
	for _, id := range []string{"a", "agent-7:delivery.0042_x", "01JAB3K9QX4M2N8P6R5T0V1WYZ", strings.Repeat("Z", MaxDeliveryIDBytes)} {
		if err := CheckDeliveryID(id); err != nil || !ValidDeliveryID(id) {
			t.Errorf("CheckDeliveryID(%q) = %v, want valid", id, err)
		}
	}
	for id, want := range map[string]string{
		"": "1 to 128",
		strings.Repeat("a", MaxDeliveryIDBytes+1): "at most 128 bytes, not 129",
		"has space":   "byte 4 is 0x20",
		"tab\tid":     "byte 4 is 0x09",
		"nul\x00id":   "byte 4 is 0x00",
		"line\nbreak": "byte 5 is 0x0a",
		"del\x7fid":   "byte 4 is 0x7f",
		"café":        "byte 4 is 0xc3",
		"slash/id":    "byte 6 is 0x2f",
		"quote\"id":   "byte 6 is 0x22",
	} {
		err := CheckDeliveryID(id)
		if err == nil || ValidDeliveryID(id) {
			t.Errorf("CheckDeliveryID(%q) accepted an invalid id", id)
			continue
		}
		if !strings.Contains(err.Error(), "--delivery-id") || !strings.Contains(err.Error(), want) {
			t.Errorf("CheckDeliveryID(%q) = %q, want it to name --delivery-id and %q", id, err, want)
		}
	}
}

// F10: readers validate every field again, so a receipt.json whose
// delivery_id is not one the lifecycle could have written is refused.
func TestReadPublicReceiptRefusesAnInvalidDeliveryID(t *testing.T) {
	path := filepath.Join(t.TempDir(), PublicReceiptName)
	write := func(delivery string) {
		t.Helper()
		doc := `{"schema_version":1,"receipt_id":"b-01JAB3K9QX4M2N8P6R5T0V1WYZ","state":"confirmed","finished_at":"2026-10-17T10:00:00Z","sessions_restart_required":0` + delivery + `}`
		if err := os.WriteFile(path, []byte(doc), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`,"delivery_id":"agent-7:d.1"`)
	if got, err := ReadPublicReceipt(path); err != nil || got.DeliveryID != "agent-7:d.1" {
		t.Fatalf("valid delivery_id: %+v, %v", got, err)
	}
	write("")
	if got, err := ReadPublicReceipt(path); err != nil || got.DeliveryID != "" {
		t.Fatalf("no delivery_id: %+v, %v", got, err)
	}
	write(`,"delivery_id":"bad id"`)
	if _, err := ReadPublicReceipt(path); err == nil || !strings.Contains(err.Error(), "delivery_id") {
		t.Fatalf("invalid delivery_id read without error: %v", err)
	}
}
