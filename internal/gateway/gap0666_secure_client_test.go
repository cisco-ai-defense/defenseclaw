// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestGAP0666SecureClientKeepsGuardrailCapabilityMapping(t *testing.T) {
	profile := connector.NewCodexConnector().HookProfile(connector.SetupOpts{})
	mode, event := "observe", "PreToolUse"
	wantAction, wantWouldBlock := mapHookActionForProfile("block", mode, event, profile.Capabilities, profile, nil)
	action, wouldBlock := mapAssetBlockForProfile(mode, event, profile.Capabilities, profile, nil, true)
	if action != wantAction || wouldBlock != wantWouldBlock {
		t.Fatalf("Secure Client action=%q would_block=%v, want %q/%v", action, wouldBlock, wantAction, wantWouldBlock)
	}
	action, wouldBlock = mapAssetBlockForProfile(mode, event, profile.Capabilities, profile, nil, false)
	if action != "block" || wouldBlock {
		t.Fatalf("asset-policy action=%q would_block=%v, want block/false", action, wouldBlock)
	}
}
