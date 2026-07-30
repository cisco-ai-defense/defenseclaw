// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestDarwinProcessInspectionUsesFixedBinaryAndMinimalEnvironment(t *testing.T) {
	t.Setenv("PATH", "/tmp/attacker-controlled")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "must-not-reach-ps")
	t.Setenv("OPENCLAW_GATEWAY_TOKEN", "must-not-reach-ps")

	ctx, cancel := context.WithTimeout(context.Background(), darwinPSTimeout)
	defer cancel()
	cmd := darwinProcessInspectionCommand(ctx, os.Getpid())
	if cmd.Path != "/bin/ps" {
		t.Fatalf("process-inspection helper path = %q, want /bin/ps", cmd.Path)
	}
	if cmd.Dir != "/" {
		t.Fatalf("process-inspection helper dir = %q, want /", cmd.Dir)
	}
	if !slices.Equal(cmd.Env, []string{"LANG=C", "LC_ALL=C"}) {
		t.Fatalf("process-inspection helper environment = %q, want locale-only environment", cmd.Env)
	}
	for _, forbidden := range []string{
		"PATH=/tmp/attacker-controlled",
		"DEFENSECLAW_GATEWAY_TOKEN=must-not-reach-ps",
		"OPENCLAW_GATEWAY_TOKEN=must-not-reach-ps",
	} {
		if slices.Contains(cmd.Env, forbidden) {
			t.Fatalf("process-inspection helper inherited %q", forbidden)
		}
	}
}

func TestDarwinProcessInspectionCommandHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := darwinProcessInspectionCommand(ctx, os.Getpid()).Run()
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled process-inspection command error = %v, want context.Canceled", err)
	}
}

func TestDarwinOriginMainStartIdentityRemainsVerifiable(t *testing.T) {
	legacyIdentity, err := darwinLegacyProcessStartIdentity(os.Getpid())
	if err != nil {
		t.Fatalf("read origin/main start identity: %v", err)
	}
	info := pidInfo{
		PID:           os.Getpid(),
		StartIdentity: legacyIdentity,
	}
	if !New(t.TempDir()).verifyStartIdentity(info) {
		t.Fatalf("origin/main `ps -o lstart=` identity %q was not accepted", legacyIdentity)
	}
}

func TestDarwinLocalizedOriginMainIdentityUsesBoundedLaunchGeneration(t *testing.T) {
	nativeIdentity, err := darwinProcessStartIdentity(os.Getpid())
	if err != nil {
		t.Fatalf("read native start identity: %v", err)
	}
	secondsText, _, ok := strings.Cut(nativeIdentity, ".")
	if !ok {
		t.Fatalf("native identity = %q, want seconds.microseconds", nativeIdentity)
	}
	startedAt, err := strconv.ParseInt(secondsText, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	info := pidInfo{
		PID:           os.Getpid(),
		Executable:    executable,
		StartTime:     startedAt,
		StartIdentity: "localized identity that cannot be reproduced after upgrade",
	}
	d := New(t.TempDir())
	if d.verifyProcess(info) {
		t.Fatal("localized identity unexpectedly passed the general verifier")
	}
	if !d.verifyProcessForAuthenticatedMigration(info) {
		t.Fatal("bounded origin/main launch generation did not qualify for authenticated migration")
	}

	info.StartTime = startedAt - int64(childPIDRegistrationTimeout/time.Second) - 1
	if d.verifyProcessForAuthenticatedMigration(info) {
		t.Fatal("out-of-window launch generation qualified for authenticated migration")
	}
}

func TestDarwinExecutableIdentityRejectsDifferentPathWithSameBasename(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	spoofedPath := filepath.Join(t.TempDir(), filepath.Base(executable))
	info := pidInfo{
		PID:        os.Getpid(),
		Executable: spoofedPath,
	}
	if New(t.TempDir()).verifyExecutable(info) {
		t.Fatalf("different executable path with same basename was accepted: %q", spoofedPath)
	}
}
