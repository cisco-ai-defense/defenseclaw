// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSubstrateActivityConfig(t *testing.T) {
	var zero SubstrateActivityConfig
	if zero.EffectiveStatusWindow() != 20*time.Second || !zero.NotificationsOn() {
		t.Fatalf("defaults: window %v, notifications on %v", zero.EffectiveStatusWindow(), zero.NotificationsOn())
	}
	if (SubstrateActivityConfig{StatusWindow: "0s"}).EffectiveStatusWindow() != 0 {
		t.Fatal("0s must switch the thinking state off")
	}
	if (SubstrateActivityConfig{Notifications: "OFF"}).NotificationsOn() {
		t.Fatal("notifications: off must turn them off")
	}
	for name, mut := range map[string]func(*SubstrateConfig){
		"activity.status_window": func(s *SubstrateConfig) { s.Activity.StatusWindow = "11m" },
		"status_window junk":     func(s *SubstrateConfig) { s.Activity.StatusWindow = "soon" },
		"activity.notifications": func(s *SubstrateConfig) { s.Activity.Notifications = "maybe" },
	} {
		c := validSubstrate()
		mut(&c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: a bad value was accepted", name)
		}
	}
	c := validSubstrate()
	c.Activity = SubstrateActivityConfig{StatusWindow: "0s", Notifications: "off"}
	if err := c.Validate(); err != nil {
		t.Fatalf("a valid activity block refused: %v", err)
	}
}

func TestNotificationsSubstrateIsZeroAtDefaults(t *testing.T) {
	if !(NotificationsSubstrateConfig{Asks: true, TaskEnd: true}).IsZero() {
		t.Fatal("both on is the default and is not written")
	}
	if (NotificationsSubstrateConfig{Asks: true}).IsZero() {
		t.Fatal("a person who turned task_end off must keep it")
	}
}

// TestSubstrateNotificationsOffTable pins how substrate.activity.notifications
// is read against the table the Python doctor row reads too (GAP-1020).
func TestSubstrateNotificationsOffTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "substrate_activity_notifications.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		Cases []struct {
			Value string `json:"value"`
			Off   bool   `json:"off"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	if len(table.Cases) == 0 {
		t.Fatal("the table has no cases")
	}
	for _, c := range table.Cases {
		if got := !(SubstrateActivityConfig{Notifications: c.Value}).NotificationsOn(); got != c.Off {
			t.Errorf("notifications %q: off = %v, want %v", c.Value, got, c.Off)
		}
	}
}
