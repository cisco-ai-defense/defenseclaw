// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Only a private record naming the asked PID and a loopback endpoint names a
// listener; another PID, a public address, a shared file or no file do not.
func TestRuntimeAPIAddressNamesOnlyThePublishedPrivateLoopbackListener(t *testing.T) {
	dir := t.TempDir()
	record := filepath.Join(dir, "gateway-api.json")
	// Published as the gateway publishes it: 0600 on POSIX, an owner-only
	// protected DACL on Windows (safefile.ProtectFile).
	write := func(body string) {
		if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectFile(record); err != nil {
			t.Fatal(err)
		}
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":18970}`)
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
	write(`{"pid":50721,"host":"192.0.2.10","port":18970}`)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a non-loopback record named a listener")
	}
	write(`{"pid":50721,"host":"127.0.0.1","port":0}`)
	if RuntimeAPIAddress(dir, 50721) != nil {
		t.Fatal("a record without a port named a listener")
	}
	if runtime.GOOS != "windows" {
		write(`{"pid":50721,"host":"127.0.0.1","port":18970}`)
		if err := os.Chmod(record, 0o644); err != nil {
			t.Fatal(err)
		}
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
