// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func TestRuntimeAPIAddressNamesOnlyThePublishedPrivateLoopbackListener(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "gateway-api.json")
	// write publishes the record as the gateway does (recordRuntimeAPIAddress
	// protects it: 0600 on POSIX, an owner-only protected DACL on Windows);
	// shared opens it to other accounts: mode 0644 on POSIX, an Everyone
	// read ACE on Windows.
	write := func(body string, shared bool) {
		t.Helper()
		if err := safefile.WritePrivate(record, []byte(body)); err != nil {
			t.Fatal(err)
		}
		if !shared {
			return
		}
		if runtime.GOOS == "windows" {
			if output, err := exec.Command("icacls", record, "/grant", "*S-1-1-0:(R)").CombinedOutput(); err != nil {
				t.Fatalf("icacls grant Everyone read: %v: %s", err, output)
			}
			return
		}
		if err := os.Chmod(record, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":18970}`, false)
	addr := RuntimeAPIAddress(dir, 50721)
	if addr == nil || addr.IP.String() != "127.0.0.1" || addr.Port != 18970 {
		t.Fatalf("RuntimeAPIAddress = %v, want 127.0.0.1:18970", addr)
	}
	if RuntimeAPIAddress(dir, 50720) != nil {
		t.Fatal("a record of another PID named a listener")
	}
	if RuntimeAPIAddress("relative", 50721) != nil || RuntimeAPIAddress(dir, 0) != nil {
		t.Fatal("a relative home or no PID named a listener")
	}
	write(`{"pid":50721,"host":"192.0.2.10","port":18970}`, false)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a non-loopback record named a listener")
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":0}`, false)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a record without a port named a listener")
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":18970}`, true)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a record readable by other accounts named a listener")
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a missing record named a listener")
	}
}
