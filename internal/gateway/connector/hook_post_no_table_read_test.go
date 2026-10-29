// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1453 (lead design, round c): a per-user hook reads no socket table
// before it sends. The native helper proves the owner of the connection it
// sends on before it writes a byte (GAP-1135 settle loop, GAP-1435 never
// trust a provisional UID 0), so the shell checks only the address and the
// helper. Only a call that got no answer classifies the listener, once, so
// cold start, the outage rule and the foreign-listener refusal keep their
// old outcomes.

const postStubPrologue = `set -uo pipefail
. "$1"
DEFENSECLAW_AGENT_HOME="$2"
DEFENSECLAW_HOME="$2/.defenseclaw"
unset DEFENSECLAW_MANAGED_HOOK DEFENSECLAW_HOOK_SOCKET
_dc_hook_elapsed_ms() { _DC_ELAPSED_MS="${DC_TEST_ELAPSED_MS:-0}"; }
curl() { echo curl-ran >> "$DC_TEST_MARKER"; return 7; }
`

// classifierStub replaces the socket-table classifier with one that records
// each call and returns DC_TEST_LISTENER.
const classifierStub = `defenseclaw_api_listener_unproven() { echo "classify $1" >> "$DC_TEST_MARKER"; return "${DC_TEST_LISTENER:-1}"; }
`

type postFixture struct {
	dir, hardening, home, bin, marker, hookDir string
}

func newPostFixture(t *testing.T) postFixture {
	t.Helper()
	hardening, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	f := postFixture{dir: dir, hardening: filepath.Join(dir, "_hardening.sh"), home: filepath.Join(dir, "home"), marker: filepath.Join(dir, "marker")}
	f.bin = filepath.Join(f.home, ".local", "bin")
	if err := os.WriteFile(f.hardening, hardening, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.bin, 0o700); err != nil {
		t.Fatal(err)
	}
	// The hook's .gateway-helper record names this account's gateway
	// folder (GAP-1755).
	f.hookDir = writeShellPostRecordForTest(t, f.home)
	return f
}

// helper installs NAME in ~/.local/bin; it records its argv and exits with
// DC_TEST_HELPER_EXIT, printing an allow answer when that is 0.
func (f postFixture) helper(t *testing.T, name string) {
	t.Helper()
	body := "#!/bin/sh\ncat >/dev/null\necho \"helper " + name + " $*\" >> \"$DC_TEST_MARKER\"\n" +
		"[ \"${DC_TEST_HELPER_EXIT:-0}\" = 0 ] || exit \"$DC_TEST_HELPER_EXIT\"\nprintf '{\"action\":\"allow\"}\\n200'\n"
	if err := os.WriteFile(filepath.Join(f.bin, name), []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
}

func (f postFixture) run(t *testing.T, script string, env ...string) (string, string) {
	t.Helper()
	_ = os.Remove(f.marker)
	cmd := exec.Command("bash", "-c", script, "bash", f.hardening, f.home)
	cmd.Env = append(os.Environ(), append([]string{"HOME=" + f.home, "HOOK_DIR=" + f.hookDir, "DC_TEST_MARKER=" + f.marker}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bash: %v\n%s", err, out)
	}
	marker, _ := os.ReadFile(f.marker)
	return string(out), string(marker)
}

// Every per-user hook sends through defenseclaw_gateway_post with no
// separate listener preflight, and names a foreign listener through the
// shared reason only after a call failed.
func TestHostHooksReadNoSocketTableBeforeSending(t *testing.T) {
	entries, err := hookFS.ReadDir("hooks")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
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
		if strings.Contains(text, "defenseclaw_api_listener_unproven") {
			t.Errorf("%s classifies the listener on every call; the native helper's connected-peer proof decides (GAP-1453)", name)
		}
		if !strings.Contains(text, `defenseclaw_gateway_post "http://${API_ADDR}`) {
			continue
		}
		checked++
		if !strings.Contains(text, `fail_unreachable "$(defenseclaw_gateway_unreachable_reason 2>/dev/null || printf 'gateway unreachable')"`) {
			t.Errorf("%s does not name a foreign listener after a failed per-user call", name)
		}
	}
	if checked != 12 {
		t.Fatalf("checked %d per-user hook scripts, want 12", checked)
	}
}

// A healthy call reads no socket table: the classifier is never called and
// the helper gets the request. Every loopback spelling the helper dials, and
// both the light helper and the gateway CLI fallback.
func TestPerUserGatewayPostReadsNoSocketTableBeforeTheHelper(t *testing.T) {
	for _, helper := range []string{"defenseclaw-hook-post", "defenseclaw-gateway"} {
		for _, addr := range []string{"127.0.0.1:18960", "127.0.0.2:18960", "localhost:18960", "LocalHost:18960", "[::1]:18960", "[::ffff:127.0.0.1]:18960"} {
			t.Run(helper+"/"+addr, func(t *testing.T) {
				f := newPostFixture(t)
				f.helper(t, helper)
				if helper == "defenseclaw-hook-post" {
					f.helper(t, "defenseclaw-gateway")
				}
				script := postStubPrologue + classifierStub + `API_ADDR='` + addr + `'
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Content-Type: application/json' -H 'Authorization: Bearer secret'; echo " rc=$?"`
				out, marker := f.run(t, script)
				if out != "{\"action\":\"allow\"}\n200 rc=0\n" {
					t.Fatalf("post output = %q (marker %q)", out, marker)
				}
				if strings.Contains(marker, "classify") || strings.Contains(marker, "curl-ran") {
					t.Fatalf("a healthy per-user call classified the listener or ran curl: %q", marker)
				}
				if !strings.Contains(marker, "helper "+helper+" hook-post --api-addr "+addr+" ") {
					t.Fatalf("the expected helper did not post: %q", marker)
				}
			})
		}
	}
}

// A call that was not answered is classified once and keeps the outcome the
// send-time preflight gave: no listener is a cold start (7, the only outage),
// a foreign or unknown listener fails closed (1), this account's listener
// keeps the helper's failure (1), a call with no time left keeps 28. An
// address the helper refuses never starts it, and an impossible port stays
// a free port.
func TestPerUserGatewayPostClassifiesOnlyAnUnsentCall(t *testing.T) {
	cases := []struct {
		name, addr, helper, helperExit, listener, elapsed string
		want                                              string
		helperRuns, classifies                            bool
	}{
		{"refused, no listener: cold start", "127.0.0.1:18960", "defenseclaw-hook-post", "7", "2", "0", "rc=7", true, true},
		{"refused, own listener: closed", "127.0.0.1:18960", "defenseclaw-hook-post", "7", "1", "0", "rc=1", true, true},
		// The helper's own refusal is final: a later table read that no
		// longer shows the foreign listener is no cold start (T12b loop 2).
		{"peer refused, foreign: closed", "127.0.0.1:18960", "defenseclaw-hook-post", "1", "0", "0", "rc=1", true, false},
		{"peer refused, own: closed", "127.0.0.1:18960", "defenseclaw-hook-post", "1", "1", "0", "rc=1", true, false},
		{"peer refused, now free: closed", "[::1]:18960", "defenseclaw-hook-post", "1", "2", "0", "rc=1", true, false},
		{"helper panic, now free: closed", "127.0.0.1:18960", "defenseclaw-hook-post", "2", "2", "0", "rc=1", true, false},
		{"helper killed, now free: closed", "127.0.0.1:18960", "defenseclaw-hook-post", "137", "2", "0", "rc=1", true, false},
		{"helper timeout code, now free: closed", "127.0.0.1:18960", "defenseclaw-hook-post", "28", "2", "0", "rc=1", true, false},
		{"gateway CLI fallback peer refused, now free: closed", "localhost:18960", "defenseclaw-gateway", "1", "2", "0", "rc=1", true, false},
		{"gateway CLI fallback refused, free", "localhost:18960", "defenseclaw-gateway", "7", "2", "0", "rc=7", true, true},
		{"helper cannot run, free", "127.0.0.1:18960", "defenseclaw-hook-post", "126", "2", "0", "rc=7", true, true},
		{"helper not found, free", "127.0.0.1:18960", "defenseclaw-hook-post", "127", "2", "0", "rc=7", true, true},
		{"no helper installed, free", "127.0.0.1:18960", "", "", "2", "0", "rc=7", false, true},
		{"no helper installed, own", "127.0.0.1:18960", "", "", "1", "0", "rc=1", false, true},
		{"no helper installed, foreign", "127.0.0.1:18960", "", "", "0", "0", "rc=1", false, true},
		{"no time left, own", "127.0.0.1:18960", "defenseclaw-hook-post", "0", "1", "9000", "rc=28", false, true},
		{"no time left, free", "127.0.0.1:18960", "defenseclaw-hook-post", "0", "2", "9000", "rc=7", false, true},
		{"no time left, foreign", "127.0.0.1:18960", "defenseclaw-hook-post", "0", "0", "9000", "rc=1", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newPostFixture(t)
			if tc.helper != "" {
				f.helper(t, tc.helper)
			}
			script := postStubPrologue + classifierStub + `API_ADDR='` + tc.addr + `'
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Authorization: Bearer secret'; echo "rc=$?"`
			out, marker := f.run(t, script, "DC_TEST_HELPER_EXIT="+tc.helperExit, "DC_TEST_LISTENER="+tc.listener, "DC_TEST_ELAPSED_MS="+tc.elapsed)
			if strings.TrimSpace(out) != tc.want {
				t.Fatalf("status = %q, want %q (marker %q)", out, tc.want, marker)
			}
			if got := strings.Contains(marker, "helper "); got != tc.helperRuns {
				t.Fatalf("helper ran = %v, want %v: %q", got, tc.helperRuns, marker)
			}
			if got := strings.Count(marker, "classify"); (got == 1) != tc.classifies || got > 1 {
				t.Fatalf("classifier calls = %d, want one=%v: %q", got, tc.classifies, marker)
			}
			if strings.Contains(marker, "curl-ran") {
				t.Fatalf("a per-user call ran curl: %q", marker)
			}
		})
	}
	// The real classifier, which reads no table for these addresses.
	for _, tc := range []struct{ addr, want string }{
		{"10.0.0.1:18960", "rc=1"},
		{"example.com:18960", "rc=1"},
		{"[fe80::1%eth0]:18960", "rc=1"},
		{"0.0.0.0:18960", "rc=1"},
		{"127.0.0.1:99999", "rc=7"},
		{"127.0.0.1:0", "rc=7"},
	} {
		t.Run("address "+tc.addr, func(t *testing.T) {
			f := newPostFixture(t)
			f.helper(t, "defenseclaw-hook-post")
			script := postStubPrologue + `API_ADDR='` + tc.addr + `'
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Authorization: Bearer secret'; echo "rc=$?"`
			out, marker := f.run(t, script)
			if strings.TrimSpace(out) != tc.want || marker != "" {
				t.Fatalf("status = %q, want %q; helper or curl ran: %q", out, tc.want, marker)
			}
		})
	}
}

// The reviewer's race end to end (T12b loop 2): a foreign listener took the
// connection, the helper refused its owner, and the listener unbound before
// any socket table read. The restart wait must end on the refusal (1), never
// on the outage status (7) that a default per-user install lets through, and
// must not cold-start or classify the listener. A genuine refusal (helper 7)
// with no listener is still the cold start.
func TestPerUserPeerRefusalIsNeverAnOutageAfterTheListenerLeaves(t *testing.T) {
	for _, tc := range []struct{ helper, exit, want string }{
		{"defenseclaw-hook-post", "1", "rc=1 transport=1"},
		{"defenseclaw-gateway", "1", "rc=1 transport=1"},
		{"defenseclaw-hook-post", "7", "rc=7 transport=7"},
	} {
		t.Run(tc.helper+"/exit "+tc.exit, func(t *testing.T) {
			f := newPostFixture(t)
			f.helper(t, tc.helper)
			script := postStubPrologue + classifierStub + `API_ADDR=127.0.0.1:18960
defenseclaw_gateway_cold_start() { echo cold-start >> "$DC_TEST_MARKER"; }
sleep() { :; }
_post() { defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Authorization: Bearer secret' >/dev/null; }
status=0; _post || status=$?
defenseclaw_await_gateway "$status" _post; echo "rc=$? transport=$_DC_TRANSPORT_STATUS"`
			out, marker := f.run(t, script, "DC_TEST_HELPER_EXIT="+tc.exit, "DC_TEST_LISTENER=2")
			if strings.TrimSpace(out) != tc.want {
				t.Fatalf("restart wait = %q, want %q (marker %q)", out, tc.want, marker)
			}
			refusal := tc.exit != "7"
			if refusal && (strings.Contains(marker, "classify") || strings.Contains(marker, "cold-start")) {
				t.Fatalf("a refused peer was classified or cold-started: %q", marker)
			}
			if !refusal && !strings.Contains(marker, "cold-start") {
				t.Fatalf("a refused connection did not cold-start the gateway: %q", marker)
			}
		})
	}
	// A helper that could not start under the memory limit sent nothing, so
	// the table read still decides.
	f := newPostFixture(t)
	f.helper(t, "defenseclaw-hook-post")
	script := postStubPrologue + classifierStub + `API_ADDR=127.0.0.1:18960
_DC_HOOK_NATIVE_VMEM_LIMIT=not-a-number
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Authorization: Bearer secret'; echo "rc=$?"`
	out, marker := f.run(t, script, "DC_TEST_LISTENER=2")
	if strings.TrimSpace(out) != "rc=7" || strings.Contains(marker, "helper ") || strings.Count(marker, "classify") != 1 {
		t.Fatalf("helper that could not start: status %q, marker %q", out, marker)
	}
}

// A managed or socket hook never classifies a per-user listener.
func TestManagedGatewayPostDoesNotClassifyAPerUserListener(t *testing.T) {
	f := newPostFixture(t)
	f.helper(t, "defenseclaw-hook-post")
	for _, setup := range []string{"DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_HOOK_SOCKET=/run/defenseclaw/hook.sock"} {
		script := postStubPrologue + classifierStub + setup + `
API_ADDR=127.0.0.1:18960
defenseclaw_gateway_post "http://${API_ADDR}/api/v1/claude-code/hook" 4 '{}' -H 'Authorization: Bearer secret'; echo "rc=$?"`
		out, marker := f.run(t, script, "DC_TEST_LISTENER=2")
		if strings.TrimSpace(out) != "rc=7" || marker != "curl-ran\n" {
			t.Fatalf("%s: status %q, marker %q; want curl's own status and no classification", setup, out, marker)
		}
		reason, marker := f.run(t, postStubPrologue+classifierStub+setup+"\nAPI_ADDR=127.0.0.1:18960\ndefenseclaw_gateway_unreachable_reason", "DC_TEST_LISTENER=0")
		if reason != "gateway unreachable" || marker != "" {
			t.Fatalf("%s: reason %q, marker %q", setup, reason, marker)
		}
	}
}

// The failure reason names another account's listener and the port setup
// command; every other failure keeps "gateway unreachable", which the hooks'
// next-step and notice text key on.
func TestGatewayUnreachableReasonNamesAForeignListener(t *testing.T) {
	f := newPostFixture(t)
	for _, tc := range []struct{ listener, want string }{
		{"0", "127.0.0.1:18960 is not proven to be this account's gateway; no token or payload was sent to it. Another account may hold the port. Run `defenseclaw setup gateway --api-port <free-port>` to choose a free port"},
		{"1", "gateway unreachable"},
		{"2", "gateway unreachable"},
	} {
		out, marker := f.run(t, postStubPrologue+classifierStub+"API_ADDR=127.0.0.1:18960\ndefenseclaw_gateway_unreachable_reason", "DC_TEST_LISTENER="+tc.listener)
		if out != tc.want || marker != "classify 127.0.0.1:18960\n" {
			t.Fatalf("listener %s: reason %q, marker %q", tc.listener, out, marker)
		}
	}
	// A hook rendered by this build against an older helper without the
	// function still fails with the plain reason.
	out, _ := f.run(t, `unset -f defenseclaw_gateway_unreachable_reason; printf '%s' "$(defenseclaw_gateway_unreachable_reason 2>/dev/null || printf 'gateway unreachable')"`)
	if out != "gateway unreachable" {
		t.Fatalf("missing helper function: reason %q", out)
	}
}
