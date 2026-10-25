// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The shell preflight and the native helper share one address rule; both
// are checked against testdata/per_user_loopback_addrs.json.
func TestHookLoopbackTargetsMatchTheNativeHelperTable(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "per_user_loopback_addrs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Addr    string   `json:"addr"`
		Targets []string `json:"targets"`
		Port    int      `json:"port"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	helper := writeHardeningHelper(t)
	args := []string{"-c", `set -euo pipefail; . "$1"; shift
for addr in "$@"; do
  if defenseclaw_loopback_targets "$addr"; then echo "${_DC_LOOPBACK_TARGETS[*]} $_DC_LOOPBACK_PORT"; else echo REJECT; fi
done`, "bash", helper}
	for _, vector := range vectors {
		args = append(args, vector.Addr)
	}
	out, err := exec.Command("bash", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(lines) != len(vectors) {
		t.Fatalf("got %d answers for %d vectors:\n%s", len(lines), len(vectors), out)
	}
	for index, vector := range vectors {
		want := "REJECT"
		if len(vector.Targets) > 0 {
			want = fmt.Sprintf("%s %d", strings.Join(vector.Targets, " "), vector.Port)
		}
		if lines[index] != want {
			t.Errorf("%q: shell = %q, want %q", vector.Addr, lines[index], want)
		}
	}
}

func writeHardeningHelper(t *testing.T) string {
	t.Helper()
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(t.TempDir(), "_hardening.sh")
	if err := os.WriteFile(helper, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	return helper
}

// Every spelling the native helper accepts reaches the procfs owner check
// for the endpoint the helper dials first (localhost: 127.0.0.1, then ::1).
func TestHookAPIListenerAcceptsEveryLoopbackSpelling(t *testing.T) {
	helper := writeHardeningHelper(t)
	own := os.Getuid()
	row := func(addr string, uid int) string {
		return fmt.Sprintf("   0: %s:4A10 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000 %5d 0 4242\n", addr, uid)
	}
	const v4one, v4two, v6one, v6any = "0100007F", "0200007F", "00000000000000000000000001000000", "00000000000000000000000000000000"
	for _, test := range []struct {
		name, host, tcp, tcp6, want string
	}{
		{name: "localhost own IPv4", host: "localhost", tcp: row(v4one, own), want: "send"},
		{name: "LOCALHOST own IPv4", host: "LOCALHOST", tcp: row(v4one, own), want: "send"},
		{name: "localhost foreign IPv4", host: "localhost", tcp: row(v4one, own+4242), want: "foreign"},
		{name: "localhost own ::1 only", host: "localhost", tcp6: row(v6one, own), want: "send"},
		{name: "localhost foreign ::1 only", host: "localhost", tcp6: row(v6one, own+4242), want: "foreign"},
		{name: "localhost own IPv4 is dialed before foreign ::1", host: "localhost", tcp: row(v4one, own), tcp6: row(v6one, own+4242), want: "send"},
		{name: "localhost free", host: "localhost", want: "free"},
		{name: "::1 own", host: "[::1]", tcp6: row(v6one, own), want: "send"},
		{name: "::1 expanded own", host: "[0:0:0:0:0:0:0:1]", tcp6: row(v6one, own), want: "send"},
		{name: "::1 foreign", host: "[::1]", tcp6: row(v6one, own+4242), want: "foreign"},
		{name: "::1 own IPv6 wildcard", host: "[::1]", tcp6: row(v6any, own), want: "send"},
		{name: "::1 foreign IPv6 wildcard", host: "[::1]", tcp6: row(v6any, own+4242), want: "foreign"},
		{name: "::1 exact own over foreign IPv6 wildcard", host: "[::1]", tcp6: row(v6one, own) + row(v6any, own+4242), want: "send"},
		{name: "::1 not served by a foreign IPv4 wildcard", host: "[::1]", tcp: row("00000000", own+4242), want: "free"},
		{name: "::1 not served by foreign 127.0.0.1", host: "[::1]", tcp: row(v4one, own+4242), want: "free"},
		{name: "mapped spelling own IPv4", host: "[::ffff:127.0.0.1]", tcp: row(v4one, own), want: "send"},
		{name: "mapped hex spelling own 127.0.0.2", host: "[::ffff:7f00:2]", tcp: row(v4two, own), want: "send"},
		{name: "mapped spelling foreign IPv4", host: "[::ffff:127.0.0.1]", tcp: row(v4one, own+4242), want: "foreign"},
		{name: "unbracketed ::1 is refused", host: "::1", tcp6: row(v6one, own), want: "foreign"},
		{name: "non-loopback name is refused", host: "gateway.local", tcp: row(v4one, own), want: "foreign"},
	} {
		t.Run(test.name, func(t *testing.T) {
			net := filepath.Join(t.TempDir(), "net")
			if err := os.Mkdir(net, 0o700); err != nil {
				t.Fatal(err)
			}
			const header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
			for name, rows := range map[string]string{"tcp": test.tcp, "tcp6": test.tcp6} {
				if err := os.WriteFile(filepath.Join(net, name), []byte(header+rows), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			script := `set -euo pipefail; . "$1"
status=0; defenseclaw_api_listener_unproven "$3:18960" "$2" "$4" || status=$?
case "$status" in 0) echo foreign ;; 1) echo send ;; 2) echo free ;; *) echo unexpected ;; esac`
			out, err := exec.Command("bash", "-c", script, "bash", helper, net, test.host, filepath.Join(filepath.Dir(net), "absent-lsof")).CombinedOutput()
			if err != nil {
				t.Fatalf("bash: %v\n%s", err, out)
			}
			if got := strings.TrimSpace(string(out)); got != test.want {
				t.Fatalf("listener status = %q, want %q", got, test.want)
			}
		})
	}
}
