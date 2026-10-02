// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// Another service listening on the same port at a different address is not
// the holder of the configured gateway address.
func TestProcPortHolderMatchesTheConfiguredAddress(t *testing.T) {
	root := t.TempDir()
	header := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	tables := map[string]string{
		// [::1]:8000 held by PID 20 (uid 1001) is listed first.
		"tcp6": header + "   0: 00000000000000000000000001000000:1F40 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 222 1\n",
		// 127.0.0.1:8000 held by PID 10 (uid 1000).
		"tcp": header + "   0: 0100007F:1F40 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n",
	}
	for name, body := range tables {
		writeFile(t, filepath.Join(root, "net", name), body)
	}
	for pid, inode := range map[string]string{"10": "111", "20": "222"} {
		writeFile(t, filepath.Join(root, pid, "comm"), "proc"+pid+"\n")
		if err := os.MkdirAll(filepath.Join(root, pid, "fd"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(root, pid, "fd", "3")); err != nil {
			t.Fatal(err)
		}
	}
	for host, want := range map[string]int{"127.0.0.1": 10, "::1": 20} {
		holder, err := findProcPortHolder(root, host, 8000)
		if err != nil || holder.PID != want || holder.UID != 1000+want/10-1 {
			t.Fatalf("holder of %s:8000 = %+v, %v; want PID %d", host, holder, err, want)
		}
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
