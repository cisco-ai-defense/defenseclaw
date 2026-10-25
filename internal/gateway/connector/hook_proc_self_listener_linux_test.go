// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
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

// A tcp6 wildcard row does not say whether IPV6_V6ONLY is set. Probe the
// configured IPv4 address without sending bytes before treating that row as
// able to hold the hook's gateway port.
func TestHookAPIListenerIPv6WildcardMustServeConfiguredIPv4(t *testing.T) {
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, network, want string
		reachable           bool
	}{
		{name: "IPv6 only wildcard leaves IPv4 free", network: "tcp6", want: "2"},
		{name: "dual stack wildcard holds IPv4", network: "tcp", reachable: true, want: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen(tc.network, "[::]:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			port := listener.Addr().(*net.TCPAddr).Port
			endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			conn, dialErr := net.DialTimeout("tcp4", endpoint, 200*time.Millisecond)
			if conn != nil {
				conn.Close()
			}
			if (dialErr == nil) != tc.reachable {
				t.Fatalf("IPv4 reachability = %t, want %t (error: %v)", dialErr == nil, tc.reachable, dialErr)
			}
			dir := t.TempDir()
			helper := filepath.Join(dir, "_hardening.sh")
			if err := os.WriteFile(helper, hardening, 0o600); err != nil {
				t.Fatal(err)
			}
			netDir := filepath.Join(dir, "net")
			if err := os.Mkdir(netDir, 0o700); err != nil {
				t.Fatal(err)
			}
			const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(header), 0o600); err != nil {
				t.Fatal(err)
			}
			row := fmt.Sprintf("   0: 00000000000000000000000000000000:%04X 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d 0 4242\n", port, os.Getuid()+4242)
			if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(header+row), 0o600); err != nil {
				t.Fatal(err)
			}
			script := `set -euo pipefail; . "$1"; status=0
defenseclaw_api_listener_unproven "$2" "$3" "$4" || status=$?
echo "$status"`
			out, err := exec.Command("bash", "-c", script, "bash", helper, endpoint, netDir, filepath.Join(dir, "absent-lsof")).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != tc.want {
				t.Fatalf("listener status = %q, want %q", got, tc.want)
			}
		})
	}
}
