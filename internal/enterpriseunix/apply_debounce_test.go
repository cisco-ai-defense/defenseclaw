// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestApplyTriggerDebounceWaitsThroughSecondPush(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	now := start
	pushed := false
	advance := func(_ context.Context, duration time.Duration) error {
		now = now.Add(duration)
		if !pushed && !now.Before(start.Add(5*time.Second)) {
			pushed = true
			if err := os.WriteFile(path, []byte("second push"), 0o600); err != nil {
				return err
			}
		}
		return nil
	}
	if err := waitForApplyTriggerQuiet(t.Context(), path, func() time.Time { return now }, advance, os.Lstat); err != nil {
		t.Fatal(err)
	}
	if !pushed || now.Sub(start) != 11*time.Second {
		t.Fatalf("the trigger planned at %s after the second push; want 11s", now.Sub(start))
	}
}

func TestApplyTriggerDebounceCapsContinuousWrites(t *testing.T) {
	path := t.TempDir() + "/config.yaml"
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC)
	now := start
	writes := 0
	advance := func(_ context.Context, duration time.Duration) error {
		now = now.Add(duration)
		writes++
		return os.WriteFile(path, []byte(strings.Repeat("x", writes+5)), 0o600)
	}
	if err := waitForApplyTriggerQuiet(t.Context(), path, func() time.Time { return now }, advance, os.Lstat); err != nil {
		t.Fatal(err)
	}
	if now.Sub(start) != applyTriggerMaxWait || writes < 2 {
		t.Fatalf("continuous writes waited %s across %d samples; want cap %s", now.Sub(start), writes, applyTriggerMaxWait)
	}
}

// A restart-required change still restarts, but a second push inside the
// trigger's quiet window is the one the first ensure plans. The queued ensure
// then observes the committed bytes and does no work.
func TestTwoRestartRequiredPushesInsideApplyTriggerWindowRestartOnce(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			base := string(DefaultConfig(h.env.Layout)) + "  hook_self_heal_debounce_ms: 500\n"
			basePath := writeTempConfig(t, []byte(base))
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: basePath}))
			first := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 600", 1)
			second := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 700", 1)
			path := h.env.P(h.env.Layout.ConfigPath)
			if err := os.WriteFile(path, []byte(first), 0o640); err != nil {
				t.Fatal(err)
			}
			debounced := false
			h.env.ApplyTriggerDebounce = func(context.Context, string) error {
				if !debounced {
					debounced = true
					return os.WriteFile(path, []byte(second), 0o640)
				}
				return nil
			}
			gateway := unitOf(goos, "gateway")
			from := len(h.services.calls)
			firstResult := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, firstResult)
			secondResult := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, secondResult)
			if !debounced || !secondResult.Noop || secondResult.NoopReason != "up_to_date" {
				t.Fatalf("second push or queued ensure failed: debounced=%t result=%+v", debounced, secondResult)
			}
			restarts := 0
			for _, call := range h.services.calls[from:] {
				if call == "stop "+gateway || call == "restart "+gateway {
					restarts++
				}
			}
			if restarts != 1 {
				t.Fatalf("gateway restarted %d times, want one: %v", restarts, h.services.calls[from:])
			}
			record, err := h.env.loadDeployment()
			if err != nil || record == nil || record.ConfigSHA256 != sha256Bytes([]byte(second)) {
				t.Fatalf("second push not committed: record=%+v err=%v", record, err)
			}
		})
	}
}
