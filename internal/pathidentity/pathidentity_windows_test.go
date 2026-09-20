// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathidentity

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestSameMissingUsesWindowsOrdinalCaseRules(t *testing.T) {
	// Go's Unicode simple-fold table equates ASCII K and the Kelvin sign.
	// CompareStringOrdinal and Windows path lookup do not treat those distinct
	// on-disk spellings as the same name.
	left := filepath.Join(t.TempDir(), "missing-K")
	right := filepath.Join(filepath.Dir(left), "missing-K")
	if !strings.EqualFold(left, right) {
		t.Fatal("test precondition: Go EqualFold should equate K and Kelvin sign")
	}
	if Same(left, right) {
		t.Fatal("distinct missing Windows path spellings must not compare as identical")
	}
}
