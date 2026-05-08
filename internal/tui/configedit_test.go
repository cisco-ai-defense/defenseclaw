// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package tui

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestParseDurationOrSeconds pins the Notifications-section round-trip
// contract. The Setup-tab field accepts either a Go duration string
// ("30s", "1m", "500ms") or a bare integer interpreted as seconds.
// Empty or malformed input must resolve to 0 (which the dispatcher's
// EffectiveDedupWindow() reads as "use default") rather than to a
// surprising 0.25s — that would silently disable dedup.
func TestParseDurationOrSeconds(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"   ", 0},
		{"30s", 30 * time.Second},
		{"1m", time.Minute},
		{"500ms", 500 * time.Millisecond},
		{"1m30s", 90 * time.Second},
		{"30", 30 * time.Second},  // bare-int seconds
		{"0", 0},                  // bare-zero stays zero (default)
		{"banana", 0},             // unparseable falls back to zero
		{"-5s", -5 * time.Second}, // negatives are accepted by Go's parser
	}
	for _, tc := range cases {
		got := parseDurationOrSeconds(tc.in)
		if got != tc.want {
			t.Errorf("parseDurationOrSeconds(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestFmtNotificationsDedupWindow guards the display side of the
// round-trip. Zero MUST render as "" so the operator sees an empty
// field meaning "use default" — printing "0s" would imply dedup is
// off, which is the opposite of what zero means in the dispatcher.
func TestFmtNotificationsDedupWindow(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{0, ""},
		{-1 * time.Second, ""},
		{30 * time.Second, "30s"},
		{time.Minute, "1m0s"},
		{500 * time.Millisecond, "500ms"},
	}
	for _, tc := range cases {
		got := fmtNotificationsDedupWindow(tc.in)
		if got != tc.want {
			t.Errorf("fmtNotificationsDedupWindow(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestApplyConfigField_NotificationsSection exercises every key the
// Setup-tab Notifications section emits, verifying writes land on the
// matching field of cfg.Notifications. A regression here would mean
// the form silently swallows edits — exactly the failure mode the
// section is supposed to fix relative to hand-editing config.yaml.
func TestApplyConfigField_NotificationsSection(t *testing.T) {
	c := &config.Config{}

	// Categories + sources start zero; flipping to "true" must land.
	applyConfigField(c, "notifications.enabled", "true")
	applyConfigField(c, "notifications.block_enforced", "true")
	applyConfigField(c, "notifications.block_would_block", "true")
	applyConfigField(c, "notifications.hitl_approval", "true")
	applyConfigField(c, "notifications.sources.hook", "true")
	applyConfigField(c, "notifications.sources.guardrail", "true")
	applyConfigField(c, "notifications.sources.asset_policy", "true")
	applyConfigField(c, "notifications.dedup_window", "45s")
	applyConfigField(c, "notifications.max_per_minute", "20")

	if !c.Notifications.Enabled {
		t.Error("notifications.enabled didn't persist")
	}
	if !c.Notifications.BlockEnforced {
		t.Error("notifications.block_enforced didn't persist")
	}
	if !c.Notifications.BlockWouldBlock {
		t.Error("notifications.block_would_block didn't persist")
	}
	if !c.Notifications.HITLApproval {
		t.Error("notifications.hitl_approval didn't persist")
	}
	if !c.Notifications.Sources.Hook {
		t.Error("notifications.sources.hook didn't persist")
	}
	if !c.Notifications.Sources.Guardrail {
		t.Error("notifications.sources.guardrail didn't persist")
	}
	if !c.Notifications.Sources.AssetPolicy {
		t.Error("notifications.sources.asset_policy didn't persist")
	}
	if c.Notifications.DedupWindow != 45*time.Second {
		t.Errorf("notifications.dedup_window = %v, want 45s",
			c.Notifications.DedupWindow)
	}
	if c.Notifications.MaxPerMinute != 20 {
		t.Errorf("notifications.max_per_minute = %d, want 20",
			c.Notifications.MaxPerMinute)
	}

	// Flipping back to "false" / "" must clear the same fields so the
	// form can express both directions of every toggle (the failure
	// mode for a one-way write is silent and only surfaces when an
	// operator tries to dial down notifications and the field stays
	// stuck on).
	applyConfigField(c, "notifications.enabled", "false")
	applyConfigField(c, "notifications.sources.guardrail", "false")
	applyConfigField(c, "notifications.dedup_window", "")
	applyConfigField(c, "notifications.max_per_minute", "0")

	if c.Notifications.Enabled {
		t.Error("notifications.enabled didn't clear back to false")
	}
	if c.Notifications.Sources.Guardrail {
		t.Error("notifications.sources.guardrail didn't clear back to false")
	}
	if c.Notifications.DedupWindow != 0 {
		t.Errorf("notifications.dedup_window cleared to %v, want 0",
			c.Notifications.DedupWindow)
	}
	if c.Notifications.MaxPerMinute != 0 {
		t.Errorf("notifications.max_per_minute cleared to %d, want 0",
			c.Notifications.MaxPerMinute)
	}
}
