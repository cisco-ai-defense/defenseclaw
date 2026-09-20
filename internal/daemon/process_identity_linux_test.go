// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestOriginMainDeletedExecutableUsesAuthenticatedMigrationOnly(t *testing.T) {
	t.Setenv(EnvDaemon, "")
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copiedExecutable := filepath.Join(t.TempDir(), "defenseclaw-gateway")
	sourceFile, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer sourceFile.Close()
	copiedFile, err := os.OpenFile(copiedExecutable, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(copiedFile, sourceFile); err != nil {
		_ = copiedFile.Close()
		t.Fatal(err)
	}
	if err := copiedFile.Close(); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	d := New(dataDir)
	marker := filepath.Join(t.TempDir(), "deleted-executable-probe")
	t.Setenv(daemonRestartProbeEnv, marker)
	cmd := exec.Command(copiedExecutable, "-test.run=^TestDaemonRestartProbe$")
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	reaped := false
	t.Cleanup(func() {
		if reaped {
			return
		}
		_ = cmd.Process.Kill()
		select {
		case <-waitCh:
		case <-time.After(5 * time.Second):
		}
	})
	waitForProbeMarker(t, marker)

	startIdentity, err := processStartIdentity(cmd.Process.Pid)
	if err != nil || startIdentity == "" {
		t.Fatalf("capture start identity: identity=%q err=%v", startIdentity, err)
	}
	if err := os.Remove(copiedExecutable); err != nil {
		t.Fatalf("atomically replaced executable fixture: %v", err)
	}
	liveExecutable, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "exe"))
	if err != nil {
		t.Fatal(err)
	}
	if liveExecutable != copiedExecutable+" (deleted)" {
		t.Fatalf("live executable = %q, want exact deleted path", liveExecutable)
	}

	originMain := pidInfo{
		PID:           cmd.Process.Pid,
		Executable:    copiedExecutable,
		StartTime:     time.Now().Unix(),
		StartIdentity: startIdentity,
	}
	raw, err := json.Marshal(originMain)
	if err != nil {
		t.Fatal(err)
	}
	if err := safefile.WritePrivate(d.pidFile, raw); err != nil {
		t.Fatal(err)
	}

	if d.verifyProcess(originMain) {
		t.Fatal("deleted executable exception authorized the general process verifier")
	}
	if !d.HasAuthenticatedMigrationProcessIdentity(cmd.Process.Pid) {
		t.Fatal("exact deleted executable did not qualify for authenticated migration")
	}
	forged := originMain
	forged.Executable += "-other"
	if d.verifyProcessForAuthenticatedMigration(forged) {
		t.Fatal("non-exact deleted executable path qualified for migration")
	}
	if running, pid := d.IsRunning(); !running || pid != cmd.Process.Pid {
		t.Fatalf("migration liveness = (%v, %d), want PID %d", running, pid, cmd.Process.Pid)
	}
	if err := d.Stop(50 * time.Millisecond); !errors.Is(err, ErrUnsafeProcessIdentity) {
		t.Fatalf("direct stop error = %v, want ErrUnsafeProcessIdentity", err)
	}
	if !processExists(cmd.Process.Pid) {
		t.Fatal("direct stop signalled the deleted executable generation")
	}

	if err := d.StopGracefully(3*time.Second, func(int) error {
		return cmd.Process.Kill()
	}); err != nil {
		t.Fatalf("authenticated migration stop: %v", err)
	}
	select {
	case <-waitCh:
		reaped = true
	case <-time.After(time.Second):
		t.Fatal("deleted executable probe was not reaped")
	}
}
