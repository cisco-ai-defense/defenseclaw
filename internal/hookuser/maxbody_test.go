// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookuser

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// shellCapFunctions is the shell hooks' body-cap reader from _hardening.sh
// (_dc_stdin_cap and _dc_read_stdin_exact), with its logging stubbed: the
// code the shell hook runs to refuse an over-cap body.
func shellCapFunctions(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "internal", "gateway", "connector", "hooks", "_hardening.sh"))
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	for _, name := range []string{"_dc_stdin_cap", "_dc_read_stdin_exact"} {
		src := string(data)
		start := strings.Index(src, "\n"+name+"() {\n")
		if start < 0 {
			t.Fatalf("%s not found in _hardening.sh", name)
		}
		end := strings.Index(src[start+1:], "\n}\n")
		if end < 0 {
			t.Fatalf("%s has no end in _hardening.sh", name)
		}
		out.WriteString(src[start+1 : start+1+end+3])
	}
	out.WriteString("_dc_stdin_refused() { :; }\n_dc_stdin_over_transport() { return 1; }\n")
	return out.String()
}

// shellRefuses reports whether the shell hook's reader refuses payload with
// DEFENSECLAW_HOOK_MAX_BODY set to value (unset when value is empty).
func shellRefuses(t *testing.T, functions, value string, payload []byte) bool {
	t.Helper()
	script := functions + "_dc_stdin_cap\n_dc_read_stdin_exact \"$_DC_STDIN_CAP\" fail_closed >/dev/null\n"
	cmd := exec.Command("bash", "-c", script)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	if value != "" {
		cmd.Env = append(cmd.Env, "DEFENSECLAW_HOOK_MAX_BODY="+value)
	}
	cmd.Stdin = bytes.NewReader(payload)
	err := cmd.Run()
	if err == nil {
		return false
	}
	if exit, ok := err.(*exec.ExitError); ok && exit.ExitCode() >= 3 {
		return true
	}
	t.Fatalf("shell cap reader: %v", err)
	return false
}

// TestGAP0578NativeHookHonoursLoweredBodyCap: the native per-user Claude
// Code hook applies DEFENSECLAW_HOOK_MAX_BODY as the shell hook it replaces
// does (rel-1-0-6:GAP-0578). A lowered cap refuses an over-cap call with a
// fail-closed hook-failures row and sends nothing to the gateway; a call
// under it, a raised cap and an invalid value keep the built-in cap and the
// gateway's verdict. For the same value and payload, the shell hook's reader
// refuses exactly when the native hook does.
func TestGAP0578NativeHookHonoursLoweredBodyCap(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is required for the shell twin")
	}
	functions := shellCapFunctions(t)
	home := filepath.Join(t.TempDir(), ".defenseclaw")
	hooks := filepath.Join(home, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hooks, ".hook-claudecode.token"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"action":"allow"}`)
	}))
	defer server.Close()
	addr := strings.TrimPrefix(server.URL, "http://")
	event := func(command string) []byte {
		return []byte(`{"hook_event_name":"PreToolUse","session_id":"session","tool_name":"Bash","tool_input":{"command":` + fmt.Sprintf("%q", command) + `}}`)
	}
	payloads := map[string][]byte{
		"one-word":  event("echo ok"),
		"600-words": event("echo" + strings.Repeat(" word", 600)),
	}
	failureLog := filepath.Join(home, "logs", "hook-failures.jsonl")
	failureRows := func() string {
		data, _ := os.ReadFile(failureLog)
		return string(data)
	}
	t.Setenv("DEFENSECLAW_HOME", "")
	for _, tc := range []struct {
		value  string
		refuse map[string]bool
	}{
		{"", nil},
		{"16", map[string]bool{"one-word": true, "600-words": true}},
		{"0016", map[string]bool{"one-word": true, "600-words": true}},
		{"2048", map[string]bool{"600-words": true}},
		{"1048575", nil},
		{"1048576", nil},
		// Raised: the built-in cap stays.
		{"1048577", nil},
		{"2000000", nil},
		{"99999999", nil},
		{"9223372036854775807", nil},
		// Invalid: the built-in cap stays.
		{"abc", nil},
		{"+16", nil},
		{" 16", nil},
		{"16 ", nil},
		{"-1", nil},
		{"16k", nil},
		{"0x10", nil},
	} {
		for name, payload := range payloads {
			t.Run(fmt.Sprintf("cap=%q/%s", tc.value, name), func(t *testing.T) {
				if tc.value == "" {
					t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "")
					_ = os.Unsetenv("DEFENSECLAW_HOOK_MAX_BODY")
				} else {
					t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", tc.value)
				}
				before, rows := requests.Load(), failureRows()
				var out, errOut bytes.Buffer
				code := run(home, addr, bytes.NewReader(payload), &out, &errOut, time.Now())
				sent := requests.Load() != before
				added := strings.TrimPrefix(failureRows(), rows)
				want := tc.refuse[name]
				if want {
					if code != 2 || sent || !strings.Contains(added, "stdin body exceeded cap") ||
						!strings.Contains(added, "fail_closed") {
						t.Fatalf("over the lowered cap: exit %d, sent %v, row %q, stderr %q", code, sent, added, errOut.String())
					}
				} else if code != 0 || !sent || added != "" {
					t.Fatalf("built-in cap or under the cap: exit %d, sent %v, row %q, stdout %q, stderr %q",
						code, sent, added, out.String(), errOut.String())
				}
				if shell := shellRefuses(t, functions, tc.value, payload); shell != want {
					t.Fatalf("shell hook refuses=%v, native refuses=%v", shell, want)
				}
			})
		}
	}
	// Zero is not a positive integer: the native hook keeps the built-in
	// cap (the registry's type). The shell reader reads it as a zero cap,
	// which only refuses more.
	t.Run("cap=0", func(t *testing.T) {
		t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "0")
		before := requests.Load()
		var out, errOut bytes.Buffer
		if code := run(home, addr, bytes.NewReader(payloads["one-word"]), &out, &errOut, time.Now()); code != 0 || requests.Load() == before {
			t.Fatalf("zero cap: exit %d, stderr %q", code, errOut.String())
		}
	})
}
