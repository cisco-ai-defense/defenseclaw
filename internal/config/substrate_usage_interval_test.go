// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"testing"
	"time"
)

// TestSubstrateUsageSyncIntervalForms: sync_interval takes what the schema's
// duration allows (a Go duration or integer seconds) with spaces trimmed,
// and still refuses values out of 1s..30s (RV2 P4-2).
func TestSubstrateUsageSyncIntervalForms(t *testing.T) {
	for raw, want := range map[string]time.Duration{" 5s": 5 * time.Second, "10": 10 * time.Second, "2s ": 2 * time.Second, "30": 30 * time.Second} {
		var errs []string
		u := SubstrateUsageConfig{SyncInterval: raw}
		u.validate(func(key, format string, a ...any) { errs = append(errs, key+": "+fmt.Sprintf(format, a...)) })
		if len(errs) != 0 || u.EffectiveSyncInterval() != want {
			t.Errorf("sync_interval %q: errs %q, interval %v, want %v", raw, errs, u.EffectiveSyncInterval(), want)
		}
	}
	for _, raw := range []string{"0", "31", "500ms", "1m", "-5", "5x"} {
		var errs []string
		u := SubstrateUsageConfig{SyncInterval: raw}
		u.validate(func(key, format string, a ...any) { errs = append(errs, key) })
		if len(errs) != 1 {
			t.Errorf("sync_interval %q accepted", raw)
		}
	}
}

// TestSubstrateIssuerRefusesKeyDelimiters: config validation refuses '#'
// and '?' anywhere in an issuer URL, empty ones too (RV2 P4-1).
func TestSubstrateIssuerRefusesKeyDelimiters(t *testing.T) {
	for _, raw := range []string{"https://idp.example#", "https://idp.example?", "https://idp.example/a#b"} {
		if httpsURL(raw) {
			t.Errorf("issuer %q accepted", raw)
		}
	}
	if !httpsURL("https://idp.example/realms/eng") {
		t.Error("plain issuer refused")
	}
}
