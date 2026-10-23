// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

const scannerVisibilityHelperEnv = "DC_DAEMON_SCANNER_VISIBILITY_HELPER"

// A scan must not hide the gateway from another same-user status process.
func TestScannerLeavesGatewayVisibleToDaemonStatus(t *testing.T) {
	if base := os.Getenv(scannerVisibilityHelperEnv); base != "" {
		if err := os.WriteFile(base+".initialized", []byte("ready"), 0o600); err != nil {
			t.Fatal(err)
		}
		for {
			if _, err := os.Stat(base + ".begin"); err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		var scans sync.WaitGroup
		for _, suffix := range []string{".first", ".second"} {
			scans.Add(1)
			go func() {
				defer scans.Done()
				cmd := processutil.CommandContext(context.Background(), "/bin/sh", "-c",
					`: > "$1"; while [ ! -e "$2" ]; do sleep 0.02; done`,
					"sh", base+suffix+".active", base+suffix+".release")
				cmd.Stderr = os.Stderr
				result := "scanned"
				if err := processutil.RunTracked(cmd); err != nil {
					result = err.Error()
				}
				if err := os.WriteFile(base+suffix+".complete", []byte(result), 0o600); err != nil {
					t.Error(err)
				}
			}()
		}
		scans.Wait()
		time.Sleep(30 * time.Second)
		return
	}

	base := filepath.Join(t.TempDir(), "scan")
	helper := exec.Command(os.Args[0], "-test.run=^TestScannerLeavesGatewayVisibleToDaemonStatus$")
	helper.Env = append(os.Environ(), scannerVisibilityHelperEnv+"="+base)
	helper.Stdout, helper.Stderr = os.Stdout, os.Stderr
	if err := helper.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = helper.Process.Kill()
		_ = helper.Wait()
	})
	waitForProbeMarker(t, base+".initialized")
	exePath := filepath.Join("/proc", strconv.Itoa(helper.Process.Pid), "exe")
	before, err := os.Readlink(exePath)
	if err != nil {
		t.Fatalf("read gateway executable before scan: %v", err)
	}
	dataDir := t.TempDir()
	d := New(dataDir)
	identity, err := processStartIdentity(helper.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.writePIDInfo(helper.Process.Pid, before, identity); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".begin", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitForProbeMarker(t, base+".first.active")
	waitForProbeMarker(t, base+".second.active")
	if running, pid := d.IsRunning(); !running || pid != helper.Process.Pid {
		t.Fatalf("IsRunning during scan = (%v, %d), want (true, %d)", running, pid, helper.Process.Pid)
	}
	if !d.HasAuthenticatedMigrationProcessIdentity(helper.Process.Pid) {
		t.Fatal("active scan lost authenticated gateway identity")
	}
	if os.Geteuid() != 0 {
		if err := d.Stop(100 * time.Millisecond); !errors.Is(err, ErrUnsafeProcessIdentity) {
			t.Fatalf("unauthenticated stop during scan = %v, want identity refusal", err)
		}
	}
	if err := os.WriteFile(base+".first.release", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitForProbeMarker(t, base+".first.complete")
	if result, err := os.ReadFile(base + ".first.complete"); err != nil || string(result) != "scanned" {
		t.Fatalf("first scan result = %q, %v", result, err)
	}
	if running, pid := d.IsRunning(); !running || pid != helper.Process.Pid {
		t.Fatalf("IsRunning with second scan active = (%v, %d)", running, pid)
	}
	if os.Geteuid() != 0 && d.HasManagedProcessIdentity(helper.Process.Pid) {
		t.Fatal("gateway became dumpable while another scanner remained live")
	}
	if err := os.WriteFile(base+".second.release", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitForProbeMarker(t, base+".second.complete")
	if result, err := os.ReadFile(base + ".second.complete"); err != nil || string(result) != "scanned" {
		t.Fatalf("second scan result = %q, %v", result, err)
	}
	if after, err := os.Readlink(exePath); err != nil || after != before {
		t.Fatalf("gateway executable after scan = %q, %v; want %q", after, err, before)
	}
	if _, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(helper.Process.Pid), "environ")); err != nil {
		t.Fatalf("read gateway environment after scan: %v", err)
	}
	if running, pid := d.IsRunning(); !running || pid != helper.Process.Pid {
		t.Fatalf("IsRunning after scan = (%v, %d), want (true, %d)", running, pid, helper.Process.Pid)
	}
	if !d.HasManagedProcessIdentity(helper.Process.Pid) {
		t.Fatal("gateway did not regain strong process identity after scan")
	}
	if err := d.Stop(5 * time.Second); err != nil {
		t.Fatalf("stop gateway after scan: %v", err)
	}
	if running, _ := d.IsRunning(); running {
		t.Fatal("gateway still reported running after stop")
	}
}
