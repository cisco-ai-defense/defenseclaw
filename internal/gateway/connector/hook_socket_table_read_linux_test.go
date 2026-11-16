// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// GAP-1453: the Bash read builtin seeks back after every line of a seekable
// file, and procfs rebuilds a socket table from the start on each backward
// seek, so a line-by-line preflight cost O(rows^2) per hook call. At 10 Hz the
// TIME_WAIT rows piled up and hooks timed out. The preflight must take each
// table in a bounded number of reads, whatever its size, and still find the
// listener after thousands of other rows. /proc/self/io counts the shell's
// read syscalls; a regular-file fixture gets one read per line from the old
// loop, the same pattern that is quadratic on procfs.
func TestHookAPIListenerReadsEachSocketTableInBulk(t *testing.T) {
	if _, err := os.Stat("/proc/self/io"); err != nil {
		t.Skipf("no /proc/self/io: %v", err)
	}
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	const (
		header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
		rows   = 4000
	)
	// Every closed hook connection leaves a TIME_WAIT row on the gateway
	// port, on both ends, until the kernel reaps it.
	filler := func(table string, n int) string {
		var b strings.Builder
		b.WriteString(header)
		for i := 0; i < n; i++ {
			client := 20000 + i%40000
			if table == "tcp" {
				fmt.Fprintf(&b, "%4d: 0100007F:%04X 0100007F:4A10 06 00000000:00000000 03:00000F5A 00000000     0        0 0 3 0000000000000000\n", i, client)
			} else {
				fmt.Fprintf(&b, "%4d: 00000000000000000000000001000000:%04X 00000000000000000000000001000000:4A10 06 00000000:00000000 03:00000F5A 00000000     0        0 0 3 0000000000000000\n", i, client)
			}
		}
		return b.String()
	}
	for _, tc := range []struct {
		name, addr, table, listener, want string
	}{
		{name: "own IPv4 listener after the TIME_WAIT rows", addr: "127.0.0.1:18960", table: "tcp",
			listener: "0100007F:4A10 00000000:0000 0A", want: "1"},
		{name: "foreign IPv4 listener after the TIME_WAIT rows", addr: "127.0.0.1:18960", table: "tcp",
			listener: "0100007F:4A10 00000000:0000 0A", want: "0"},
		{name: "own ::1 listener after the TIME_WAIT rows", addr: "[::1]:18960", table: "tcp6",
			listener: "00000000000000000000000001000000:4A10 00000000000000000000000000000000:0000 0A", want: "1"},
		{name: "foreign ::1 listener after the TIME_WAIT rows", addr: "[::1]:18960", table: "tcp6",
			listener: "00000000000000000000000001000000:4A10 00000000000000000000000000000000:0000 0A", want: "0"},
		{name: "no listener among the TIME_WAIT rows is free", addr: "127.0.0.1:18960", want: "2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			net := filepath.Join(dir, strconv.Itoa(len(tc.name))+strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.MkdirAll(net, 0o700); err != nil {
				t.Fatal(err)
			}
			tables := map[string]string{"tcp": filler("tcp", rows), "tcp6": filler("tcp6", rows)}
			if tc.listener != "" {
				uid := os.Getuid()
				if strings.HasPrefix(tc.name, "foreign") {
					uid += 4242
				}
				tables[tc.table] += fmt.Sprintf("%4d: %s 00000000:00000000 00:00000000 00000000 %5d        0 4242 1 0000000000000000\n", rows, tc.listener, uid)
			}
			for name, body := range tables {
				if err := os.WriteFile(filepath.Join(net, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			script := `set -euo pipefail; . "$1"
reads() { _dc_reads=""; while read -r _k _v; do [ "$_k" != syscr: ] || _dc_reads=$_v; done < /proc/self/io; }
reads; before=$_dc_reads; status=0
defenseclaw_api_listener_unproven "$4" "$2" "$3" || status=$?
reads; echo "$status $((_dc_reads - before))"`
			out, err := exec.Command("bash", "-c", script, "bash", helper, net, filepath.Join(dir, "absent-lsof"), tc.addr).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			fields := strings.Fields(string(out))
			if len(fields) != 2 {
				t.Fatalf("unexpected output %q", out)
			}
			if fields[0] != tc.want {
				t.Fatalf("listener status = %q, want %q", fields[0], tc.want)
			}
			reads, err := strconv.Atoi(fields[1])
			if err != nil {
				t.Fatal(err)
			}
			// Both tables hold 2*rows lines. A bulk read takes a few hundred
			// kilobytes in a few hundred reads at most; one read per line is
			// at least 2*rows.
			if reads >= rows/2 {
				t.Fatalf("preflight made %d read syscalls for %d socket-table rows; it must read each table in bulk", reads, 2*rows)
			}
		})
	}
}
