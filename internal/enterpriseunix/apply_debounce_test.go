// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func requireOpenQuietWindow(t *testing.T, h *testHost, ctx context.Context) {
	t.Helper()
	if _, err := os.Lstat(h.env.P(h.env.Layout.LifecycleMarkerPath)); !os.IsNotExist(err) {
		t.Fatalf("lifecycle marker exists during the quiet window: %v", err)
	}
	file, err := os.Open(filepath.Join(h.env.P(h.env.Layout.LifecycleDir), lockFileName))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("lifecycle lock is held during the quiet window: %v", err)
	}
	defer syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	if !h.services.Active(ctx, Unit{Name: unitOf(h.env.GOOS, "gateway")}) {
		t.Fatal("the gateway is not active during the quiet window")
	}
}

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

func TestApplyTriggerNoopAndChangedConfigWaitOnlyBeforeApply(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			base := string(DefaultConfig(h.env.Layout)) + "  hook_self_heal_debounce_ms: 500\n"
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(base))}))
			waits := 0
			h.env.ApplyTriggerDebounce = func(ctx context.Context, _ string) error {
				requireOpenQuietWindow(t, h, ctx)
				waits++
				return nil
			}
			applied := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, applied)
			if waits != 0 || !applied.Noop || applied.NoopReason != "up_to_date" {
				t.Fatalf("already-applied path event: waits=%d result=%+v, want no wait and a no-op", waits, applied)
			}
			requireOK(t, h.run(Options{Action: ActionStatus}))
			configPath := h.env.P(h.env.Layout.ConfigPath)
			_, serviceGID, err := h.env.OwnerOf(configPath)
			if err != nil || serviceGID == 0 {
				t.Fatalf("installed config group = %d, %v", serviceGID, err)
			}
			if err := h.env.Lchown(configPath, 0, 0); err != nil {
				t.Fatal(err)
			}
			metadata := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, metadata)
			if waits != 0 || !metadata.Noop || !hasWarning(metadata, codeConfigMetadataRestored) {
				t.Fatalf("unchanged config metadata: waits=%d noop=%t warnings=%+v", waits, metadata.Noop, metadata.Warnings)
			}
			if _, got, err := h.env.OwnerOf(configPath); err != nil || got != serviceGID {
				t.Fatalf("restored config group = %d, want %d (%v)", got, serviceGID, err)
			}
			edited := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 600", 1)
			if err := os.WriteFile(configPath, []byte(edited), 0o640); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason}))
			if waits != 1 {
				t.Fatalf("edited config waited %d times, want once", waits)
			}
			record, err := h.env.loadDeployment()
			if err != nil || record == nil || record.ConfigSHA256 != sha256Bytes([]byte(edited)) {
				t.Fatalf("edited config not applied: record=%+v err=%v", record, err)
			}
		})
	}
}

type applyTriggerVersionWriter struct {
	ServiceManager
	once  sync.Once
	write func()
}

func (s *applyTriggerVersionWriter) Version(ctx context.Context) int {
	s.once.Do(s.write)
	return s.ServiceManager.Version(ctx)
}

type applyTriggerMarkerWriter struct {
	ServiceManager
	marker string
	once   sync.Once
	write  func()
}

func (s *applyTriggerMarkerWriter) Version(ctx context.Context) int {
	if _, err := os.Lstat(s.marker); err == nil {
		s.once.Do(s.write)
	}
	return s.ServiceManager.Version(ctx)
}

// The first push lands after the early no-op check, at the later planning
// boundary. A second push during the quiet window must be the applied one.
func TestApplyTriggerLateConfigWriteDebouncesOnce(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			base := string(DefaultConfig(h.env.Layout)) + "  hook_self_heal_debounce_ms: 500\n"
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(base))}))
			first := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 600", 1)
			second := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 700", 1)
			path := h.env.P(h.env.Layout.ConfigPath)
			wroteFirst, waits := false, 0
			h.env.Services = &applyTriggerMarkerWriter{
				ServiceManager: h.services,
				marker:         h.env.P(h.env.Layout.LifecycleMarkerPath),
				write: func() {
					if err := os.WriteFile(path, []byte(first), 0o640); err != nil {
						t.Fatal(err)
					}
					wroteFirst = true
				},
			}
			h.env.ApplyTriggerDebounce = func(ctx context.Context, _ string) error {
				requireOpenQuietWindow(t, h, ctx)
				waits++
				return os.WriteFile(path, []byte(second), 0o640)
			}
			from := len(h.services.calls)
			requireOK(t, h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason}))
			queued := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, queued)
			if !wroteFirst || waits != 1 || !queued.Noop || queued.NoopReason != "up_to_date" {
				t.Fatalf("late config write: first=%t waits=%d queued=%+v", wroteFirst, waits, queued)
			}
			gateway := unitOf(goos, "gateway")
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
				t.Fatalf("second push not applied: record=%+v err=%v", record, err)
			}
		})
	}
}

// The first push begins after the old pre-lock digest check, when
// closePrivateDirs asks the service manager for its version. A second push
// lands during the quiet window. The first ensure must apply only the final
// bytes and the queued ensure must not restart the gateway again.
func TestApplyTriggerRacingConfigWriteDebouncesOnce(t *testing.T) {
	for _, firstIncomplete := range []bool{false, true} {
		name := "complete_first_write"
		if firstIncomplete {
			name = "partial_first_write"
		}
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			base := string(DefaultConfig(h.env.Layout)) + "  hook_self_heal_debounce_ms: 500\n"
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(base))}))
			first := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 600", 1)
			second := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 700", 1)
			path := h.env.P(h.env.Layout.ConfigPath)
			wroteFirst, waits := false, 0
			h.env.Services = &applyTriggerVersionWriter{ServiceManager: h.services, write: func() {
				data := []byte(first)
				if firstIncomplete {
					data = data[:len(data)/2]
				}
				if err := os.WriteFile(path, data, 0o640); err != nil {
					t.Fatal(err)
				}
				wroteFirst = true
			}}
			h.env.ApplyTriggerDebounce = func(ctx context.Context, _ string) error {
				requireOpenQuietWindow(t, h, ctx)
				waits++
				return os.WriteFile(path, []byte(second), 0o640)
			}
			from := len(h.services.calls)
			requireOK(t, h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason}))
			queued := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, queued)
			if !wroteFirst || waits != 1 || !queued.Noop || queued.NoopReason != "up_to_date" {
				t.Fatalf("racing push: first=%t waits=%d queued=%+v", wroteFirst, waits, queued)
			}
			gateway := unitOf("linux", "gateway")
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
				t.Fatalf("second push not applied: record=%+v err=%v", record, err)
			}
		})
	}
}

// A metadata repair completed before a later config push is still reported
// after the quiet-window retry applies the final config.
func TestApplyTriggerLateRetryReportsCompletedMetadataRepair(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			base := string(DefaultConfig(h.env.Layout)) + "  hook_self_heal_debounce_ms: 500\n"
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(base))}))
			configPath := h.env.P(h.env.Layout.ConfigPath)
			_, serviceGID, err := h.env.OwnerOf(configPath)
			if err != nil || serviceGID == 0 {
				t.Fatalf("installed config group = %d, %v", serviceGID, err)
			}
			if err := h.env.Lchown(configPath, 0, 0); err != nil {
				t.Fatal(err)
			}
			first := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 600", 1)
			second := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 700", 1)
			wroteFirst, waits := false, 0
			h.env.Services = &applyTriggerMarkerWriter{
				ServiceManager: h.services,
				marker:         h.env.P(h.env.Layout.LifecycleMarkerPath),
				write: func() {
					if err := os.WriteFile(configPath, []byte(first), 0o640); err != nil {
						t.Fatal(err)
					}
					wroteFirst = true
				},
			}
			h.env.ApplyTriggerDebounce = func(ctx context.Context, _ string) error {
				requireOpenQuietWindow(t, h, ctx)
				waits++
				return os.WriteFile(configPath, []byte(second), 0o640)
			}
			result := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, result)
			if !wroteFirst || waits != 1 || !hasWarning(result, codeConfigMetadataRestored) {
				t.Fatalf("completed metadata repair: first=%t waits=%d warnings=%+v", wroteFirst, waits, result.Warnings)
			}
			if _, got, err := h.env.OwnerOf(configPath); err != nil || got != serviceGID {
				t.Fatalf("config group = %d, want %d (%v)", got, serviceGID, err)
			}
			record, err := h.env.loadDeployment()
			if err != nil || record == nil || record.ConfigSHA256 != sha256Bytes([]byte(second)) {
				t.Fatalf("final config not applied: record=%+v err=%v", record, err)
			}
			// An unchanged path event after the repair remains an ordinary no-op.
			benign := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
			requireOK(t, benign)
			if waits != 1 || !benign.Noop || benign.NoopReason != "up_to_date" || hasWarning(benign, codeConfigMetadataRestored) {
				t.Fatalf("unchanged path event: waits=%d result=%+v", waits, benign)
			}
		})
	}
}

// A directory flag removed before the later push is a completed repair even
// though the retry no longer finds that flag on disk.
func TestApplyTriggerLateRetryReportsCompletedDirFlagRepair(t *testing.T) {
	h := newTestHost(t, "darwin")
	base := string(DefaultConfig(h.env.Layout)) + "  hook_self_heal_debounce_ms: 500\n"
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0"), ConfigFile: writeTempConfig(t, []byte(base))}))
	configPath := h.env.P(h.env.Layout.ConfigPath)
	lifecycleDir := h.env.P(h.env.Layout.LifecycleDir)
	flagged, clears, waits := true, 0, 0
	h.env.clearDirFlags = func(path string) (string, error) {
		if path == lifecycleDir && flagged {
			flagged = false
			clears++
			return "uchg", nil
		}
		return "", nil
	}
	first := strings.Replace(base, "debounce_ms: 500", "debounce_ms: 600", 1)
	second := base
	h.env.Services = &applyTriggerMarkerWriter{
		ServiceManager: h.services,
		marker:         h.env.P(h.env.Layout.LifecycleMarkerPath),
		write: func() {
			if err := os.WriteFile(configPath, []byte(first), 0o640); err != nil {
				t.Fatal(err)
			}
		},
	}
	h.env.ApplyTriggerDebounce = func(ctx context.Context, _ string) error {
		requireOpenQuietWindow(t, h, ctx)
		waits++
		return os.WriteFile(configPath, []byte(second), 0o640)
	}
	result := h.run(Options{Action: ActionEnsure, Reason: ApplyTriggerReason})
	requireOK(t, result)
	note := "cleared the macOS uchg flag of " + lifecycleDir
	if clears != 1 || waits != 1 || !strings.Contains(strings.Join(result.Changes, "\n"), note) || result.Noop || result.NoopReason != "" {
		t.Fatalf("completed directory repair: clears=%d waits=%d noop=%t reason=%q changes=%q", clears, waits, result.Noop, result.NoopReason, result.Changes)
	}
}
