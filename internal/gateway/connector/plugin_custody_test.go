// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"testing"
)

// Secure Client behaviour is unchanged: a refusal that was classed as managed
// permission drift keeps that class once the fix is added to its text, and the
// plain refusal does not become drift.
func TestGAP0730CustodyRefusalKeepsTheCausesClass(t *testing.T) {
	drift := &pluginCustodyError{cause: managedDriftError{err: errors.New("x")}, failing: []string{"/a"}, fix: "chmod go-w /a"}
	if !isManagedPermissionDrift(drift) || !errors.Is(drift, ErrPluginFolderCustody) {
		t.Fatalf("managed drift class lost: %v", drift)
	}
	plain := &pluginCustodyError{cause: errors.New("x"), failing: []string{"/a"}, fix: "chmod go-w /a"}
	if isManagedPermissionDrift(plain) {
		t.Fatal("a plain refusal became permission drift")
	}
}
