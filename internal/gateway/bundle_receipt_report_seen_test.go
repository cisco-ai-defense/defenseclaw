// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The lifecycle keeps a receipt event until the reporter marked it; both
// must name the same marker.
func TestBundleReceiptReporterMarkIsWhatTheLifecycleReads(t *testing.T) {
	dataDir := t.TempDir()
	r := &bundleReceiptReporter{markerPath: filepath.Join(dataDir, bundleReceiptMarkerName)}
	const id = "b-01JA0000000000000000000042"
	if enterprisestatus.ReceiptEventReported(dataDir, id) {
		t.Fatal("an unmarked receipt reads as reported")
	}
	r.markSeen(id)
	if !enterprisestatus.ReceiptEventReported(dataDir, id) {
		t.Fatal("the lifecycle does not see the reporter's marker")
	}
}
