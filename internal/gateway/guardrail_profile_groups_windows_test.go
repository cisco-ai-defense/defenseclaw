// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"context"
	"testing"
)

func TestWindowsGroupLookupReportsDefinitiveMissingName(t *testing.T) {
	known, err := profileGroupExists(context.Background(), "DEFENSECLAW-NOSUCH-GROUP-918273645")
	if err != nil || known {
		t.Fatalf("missing group = %v, %v; want definitive absence", known, err)
	}
}

func TestWindowsGroupLookupReportsDeletedSID(t *testing.T) {
	known, err := profileGroupExists(context.Background(), "S-1-5-21-1-2-3-1104")
	if err != nil || known {
		t.Fatalf("deleted SID = %v, %v; want definitive absence", known, err)
	}
}

func TestWindowsGroupLookupReportsMalformedSID(t *testing.T) {
	known, err := profileGroupExists(context.Background(), "S-1-5-bad")
	if err != nil || known {
		t.Fatalf("malformed SID = %v, %v; want definitive absence", known, err)
	}
}
