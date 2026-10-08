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
