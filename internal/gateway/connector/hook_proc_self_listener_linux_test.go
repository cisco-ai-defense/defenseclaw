// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// ProcSubset=pid can hide /proc/net even though /proc/self/net still holds
// the network namespace's listener table. This shell probe gates the native
// connected-socket verifier, which must still run before request bytes.
func TestHookAPIListenerUsesProcSelfNetWhenProcNetIsUnavailable(t *testing.T) {
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	net := filepath.Join(dir, "net") // deliberately absent, as with ProcSubset=pid
	selfNet := filepath.Join(dir, "self", "net")
	if err := os.MkdirAll(selfNet, 0o700); err != nil {
		t.Fatal(err)
	}
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	for _, tc := range []struct {
		name string
		uid  int
		want string
	}{
		{name: "same account", uid: os.Getuid(), want: "1"},
		{name: "foreign account", uid: os.Getuid() + 4242, want: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := fmt.Sprintf("   0: 0100007F:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d 0 4242\n", tc.uid)
			if err := os.WriteFile(filepath.Join(selfNet, "tcp"), []byte(header+row), 0o600); err != nil {
				t.Fatal(err)
			}
			script := `set -euo pipefail; . "$1"; status=0
defenseclaw_api_listener_unproven 127.0.0.1:18960 "$2" "$3" || status=$?
echo "$status"`
			out, err := exec.Command("bash", "-c", script, "bash", helper, net, filepath.Join(dir, "absent-lsof")).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("listener status = %q, want %q", got, tc.want)
			}
		})
	}
}
