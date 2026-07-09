// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package notify

import (
	"errors"
	"testing"
)

func TestWindowsBackendIsExplicitlyUnsupported(t *testing.T) {
	err := sendPlatform(Notification{Title: "DefenseClaw", Body: "test"})
	if !errors.Is(err, ErrDesktopUnsupported) {
		t.Fatalf("sendPlatform error = %v, want ErrDesktopUnsupported", err)
	}
}
