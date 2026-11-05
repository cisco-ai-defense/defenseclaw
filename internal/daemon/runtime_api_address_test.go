// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRuntimeAPIAddressNamesOnlyThePublishedPrivateLoopbackListener(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "gateway-api.json")
	write := func(body string, mode os.FileMode) {
		if err := os.WriteFile(record, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(record, mode); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":18970}`, 0o600)
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
	write(`{"pid":50721,"host":"192.0.2.10","port":18970}`, 0o600)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a non-loopback record named a listener")
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":0}`, 0o600)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a record without a port named a listener")
	}
	if runtime.GOOS != "windows" {
		write(`{"pid":50721,"host":"127.0.0.1","port":18970}`, 0o644)
		if RuntimeAPIAddress(dir, 50721) != nil {
			t.Fatal("a record readable by other accounts named a listener")
		}
	}
	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a missing record named a listener")
	}
}
