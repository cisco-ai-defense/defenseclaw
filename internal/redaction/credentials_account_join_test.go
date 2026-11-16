// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"errors"
	"strings"
	"testing"
)

// An account join key never passes the telemetry credential guard.
func TestAccountJoinKeyIsATelemetryCredential(t *testing.T) {
	key := "ak1:1:a2f018c3bbe491743da16cc799c63d0b"
	err := AssertNoCredentials("user " + key)
	if !errors.Is(err, ErrCredentialDetected) || strings.Contains(err.Error(), key) {
		t.Fatalf("got %v", err)
	}
	if err := AssertNoCredentials("ak1: short"); err != nil {
		t.Fatalf("a short value is not a key: %v", err)
	}
}
