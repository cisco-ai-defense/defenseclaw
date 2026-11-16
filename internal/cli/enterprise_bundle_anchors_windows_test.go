// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "testing"

// Windows installs trust anchors with `enterprise windows ensure --profile
// standalone --trust-anchors`; the bundle group has no anchors verb there.
func TestEnterpriseBundleAnchorsVerbIsAbsentOnWindows(t *testing.T) {
	for _, cmd := range newEnterpriseBundleCommand().Commands() {
		if cmd.Name() == "anchors" {
			t.Fatal("enterprise bundle anchors is registered on Windows")
		}
	}
}
