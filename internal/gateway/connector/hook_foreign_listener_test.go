// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// GAP-1260: while this account's gateway is not running, a hook sends no token
// to a loopback listener of another account on its API port.
func TestHookAPIListenerForeignNamesAnotherAccountsListener(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell hooks are not used on Windows")
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
	const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	row := func(addr string, uid int) string {
		return fmt.Sprintf("   0: %s:4A10 00000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d        0 4242 1 0 100 0 0 10 0\n", addr, uid)
	}
	own := os.Getuid()
	for _, test := range []struct {
		name, tcp, tcp6 string
		running         bool
		want            string
	}{
		{name: "another account on 127.0.0.1", tcp: row("0100007F", own+4242), want: "foreign"},
		{name: "another account on ::1", tcp6: row("00000000000000000000000001000000", own+4242), want: "foreign"},
		{name: "this account", tcp: row("0100007F", own), want: "send"},
		{name: "another address only", tcp: row("0500000A", own+4242), want: "send"},
		{name: "free port", want: "send"},
		{name: "own gateway running", tcp: row("0100007F", own+4242), running: true, want: "send"},
	} {
		t.Run(test.name, func(t *testing.T) {
			net := filepath.Join(t.TempDir(), "net")
			if err := os.Mkdir(net, 0o700); err != nil {
				t.Fatal(err)
			}
			for name, body := range map[string]string{"tcp": header + test.tcp, "tcp6": header + test.tcp6} {
				if err := os.WriteFile(filepath.Join(net, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			stopped := "return 0"
			if test.running {
				stopped = "return 1"
			}
			script := `set -euo pipefail; . "$1"; defenseclaw_own_gateway_stopped() { ` + stopped + `; }
if defenseclaw_api_listener_foreign 127.0.0.1:18960 "$2"; then echo foreign; else echo send; fi`
			out, err := exec.Command("bash", "-c", script, "bash", helper, net).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != test.want {
				t.Fatalf("defenseclaw_api_listener_foreign = %q, want %q", got, test.want)
			}
		})
	}
}

// Every host hook checks the listener before its gateway request.
func TestHostHooksCheckTheListenerBeforeSending(t *testing.T) {
	entries, err := hookFS.ReadDir("hooks")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".sh") || strings.HasPrefix(name, "_") {
			continue
		}
		body, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		check := strings.Index(text, `defenseclaw_api_listener_foreign "$API_ADDR"`)
		send := strings.Index(text, `defenseclaw_gateway_post "http://${API_ADDR}`)
		if check < 0 || send < 0 || check > send {
			t.Errorf("%s does not check the API listener before its gateway request", name)
		}
	}
}
