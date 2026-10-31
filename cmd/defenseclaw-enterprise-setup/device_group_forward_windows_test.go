//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

// rel-1-0-6:GAP-0036: the lifecycle receives DEVICEGROUP= as --device-group.
func TestEnterpriseLifecycleForwardsTheDeviceGroup(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	got := strings.Join(enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: "ensure", Standalone: true,
		Bundle: `C:\b\v7.dcbundle`, TrustAnchors: `C:\b\a.json`, DeviceGroup: "eng", JSON: true}), " ")
	if !strings.Contains(got, `--trust-anchors C:\b\a.json`) || !strings.Contains(got, "--device-group eng") {
		t.Fatalf("ensure arguments %q lack the anchors and the device group", got)
	}
}
