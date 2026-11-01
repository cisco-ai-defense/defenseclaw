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
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// GAP-2427: gateway start after an upgrade, with kiro enrolled at kiro-cli
// 2.26.1 and the vendor CLI self-updated to 2.35.1, must admit the update
// (refresh the lock) instead of refusing the guardrail. A below-floor update
// keeps the refusal.
func TestHookContractDriftAdmissionAdmitsAKiroSelfUpdate(t *testing.T) {
	entry := func(raw string) connector.HookContractLockEntry {
		r := connector.ResolveHookContract("kiro", raw)
		return connector.HookContractLockEntry{Connector: "kiro", RawAgentVersion: r.RawVersion, NormalizedAgentVersion: r.NormalizedVersion, CompatibilityStatus: r.Status}
	}
	previous := entry("kiro-cli 2.26.1")
	if err := hookContractDriftAdmission("kiro", previous, entry("kiro-cli 2.35.1")); err != nil {
		t.Fatalf("kiro-cli 2.26.1 -> 2.35.1 refused: %v", err)
	}
	err := hookContractDriftAdmission("kiro", previous, entry("kiro-cli 2.26.5"))
	if !errors.Is(err, ErrHookContractAdmission) {
		t.Fatalf("below-floor kiro-cli update err=%v, want ErrHookContractAdmission", err)
	}
}
