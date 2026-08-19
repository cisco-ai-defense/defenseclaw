// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestIsMissingConfigErrClassifier(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"raw os.ErrNotExist", os.ErrNotExist, true},
		{"wrapped os.ErrNotExist", fmt.Errorf("read v8 config /path: %w", os.ErrNotExist), true},
		{"double-wrapped", fmt.Errorf("outer: %w", fmt.Errorf("mid: %w", os.ErrNotExist)), true},
		{"parse failure", fmt.Errorf("v8 parse: unexpected token"), false},
		{"generic io error", errors.New("read: input/output error"), false},
		{"permission denied wrapped", fmt.Errorf("open: %w", os.ErrPermission), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isMissingConfigErr(tc.err); got != tc.want {
				t.Fatalf("err=%v got=%v want=%v", tc.err, got, tc.want)
			}
		})
	}
}

// TestEnterConfigWaitLoopIfManagedGatesOnDeployMode asserts the wait
// loop does NOT engage for non-managed-enterprise deploy modes even
// when the error is a missing-file case. Spec 003 REQ-13 + REQ-28.
func TestEnterConfigWaitLoopIfManagedGatesOnDeployMode(t *testing.T) {
	tests := []struct {
		name      string
		pinValue  string
		wantRetry bool
	}{
		{"unset (OSS)", "", false},
		{"unmanaged_byod", "unmanaged_byod", false},
		{"ci_cd", "ci_cd", false},
		{"managed_enterprise", "managed_enterprise", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(managed.DeploymentModeEnv, tc.pinValue)

			// Point the "wait" path at a temp dir whose config path
			// exists so waitForConfigV8Managed returns immediately
			// once the classifier says to enter the loop.
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(cfgPath, []byte("deployment_mode: managed_enterprise\n"), 0o644); err != nil {
				t.Fatalf("stage cfg: %v", err)
			}

			// Bounded ctx so a regression in the entry-time probe
			// fails the test at 2s rather than at the `go test`
			// binary's 10-minute wall-clock timeout — the failure
			// diagnostic in the latter case points at an unrelated
			// panic. CR spec-003:PRRT_kwDORuAK-s6alkrh.
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			retry, err := enterConfigWaitLoopIfManaged(
				ctx,
				cfgPath,
				fmt.Errorf("open %s: %w", cfgPath, os.ErrNotExist),
				io.Discard,
			)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if retry != tc.wantRetry {
				t.Fatalf("retry = %v, want %v", retry, tc.wantRetry)
			}
		})
	}
}

// TestEnterConfigWaitLoopIfManagedNonMissingError verifies that a
// parse-time or permission error is NOT treated as a wait-trigger
// even under managed_enterprise: the wait loop's contract is "wait
// for the file to APPEAR", not "wait for the file to become valid".
func TestEnterConfigWaitLoopIfManagedNonMissingError(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "managed_enterprise")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	// File exists but the error we pass is a parse failure — a real
	// operator problem, not a UCB-arrival-timing problem.
	if err := os.WriteFile(cfgPath, []byte("mangled: [garbage"), 0o644); err != nil {
		t.Fatalf("stage cfg: %v", err)
	}

	retry, err := enterConfigWaitLoopIfManaged(
		context.Background(),
		cfgPath,
		errors.New("v8 parse: unexpected token"),
		io.Discard,
	)
	if err != nil {
		t.Fatalf("unexpected wait error: %v", err)
	}
	if retry {
		t.Fatal("parse error must NOT trigger the wait loop; the file already exists")
	}
}

// TestWaitForConfigV8ManagedReturnsWhenFilePresentOnEntry — the
// entry-time probe returns success when the file was already there,
// avoiding an unnecessary poll interval.
func TestWaitForConfigV8ManagedReturnsWhenFilePresentOnEntry(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("deployment_mode: managed_enterprise\n"), 0o644); err != nil {
		t.Fatalf("stage cfg: %v", err)
	}
	// Bounded ctx so an entry-probe regression fails the test at 2s
	// rather than at `go test`'s wall-clock timeout. CR
	// spec-003:PRRT_kwDORuAK-s6alkrh.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var buf strings.Builder
	if err := waitForConfigV8Managed(ctx, cfgPath, &buf); err != nil {
		t.Fatalf("wait returned error even though file was already present: %v", err)
	}
	if !strings.Contains(buf.String(), "present on entry to wait loop") {
		t.Fatalf("expected entry-time log line, got:\n%s", buf.String())
	}
}

// TestWaitForConfigV8ManagedTimeout — override the compile-time
// constant to a small window, never write the file, expect the
// distinguishable timeout error.
func TestWaitForConfigV8ManagedTimeout(t *testing.T) {
	prevTimeout := waitForConfigV8ManagedTimeout
	prevPoll := waitForConfigV8ManagedPoll
	t.Cleanup(func() {
		waitForConfigV8ManagedTimeout = prevTimeout
		waitForConfigV8ManagedPoll = prevPoll
	})
	waitForConfigV8ManagedTimeout = 150 * time.Millisecond
	waitForConfigV8ManagedPoll = 50 * time.Millisecond

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml") // deliberately absent
	var buf strings.Builder
	err := waitForConfigV8Managed(context.Background(), cfgPath, &buf)
	if err == nil {
		t.Fatalf("expected timeout error, got nil")
	}
	// Distinguishable substring — spec 003 AC-06.
	if !strings.Contains(err.Error(), "configuration wait timeout") {
		t.Fatalf("expected 'configuration wait timeout' in error, got: %v", err)
	}
}

// TestWaitForConfigV8ManagedPicksUpLateWrite — start the wait loop,
// then drop the file into place from a goroutine; the poll ticker
// (or fsnotify event) must observe it and return nil promptly.
func TestWaitForConfigV8ManagedPicksUpLateWrite(t *testing.T) {
	prevPoll := waitForConfigV8ManagedPoll
	t.Cleanup(func() { waitForConfigV8ManagedPoll = prevPoll })
	waitForConfigV8ManagedPoll = 25 * time.Millisecond

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")

	go func() {
		time.Sleep(75 * time.Millisecond)
		_ = os.WriteFile(cfgPath, []byte("deployment_mode: managed_enterprise\n"), 0o644)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var buf strings.Builder
	if err := waitForConfigV8Managed(ctx, cfgPath, &buf); err != nil {
		t.Fatalf("wait returned error: %v\nlog:\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "resuming") {
		t.Fatalf("expected a 'resuming' log line, got:\n%s", buf.String())
	}
}
