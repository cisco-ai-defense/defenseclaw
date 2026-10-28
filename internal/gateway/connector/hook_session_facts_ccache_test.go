// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// GAP-1139: a new kinit into the same FILE credential cache changes the
// principal while every session variable stays the same. The shell hook
// reuses the cached session facts only while the credential cache is not
// newer than them; an unchanged cache still reuses them.
func TestShellHookSessionFactsFollowANewKinitIntoTheSameCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks report identity from hookexec, not from the shell helper")
	}
	shell := systemBashForTest(t)
	helperPath := materializeHookAssetForTest(t, "hooks/_hardening.sh")
	home := t.TempDir()
	ccache := filepath.Join(t.TempDir(), "krb5cc_test")
	if err := os.WriteFile(ccache, []byte("ticket"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "defenseclaw-hook")
	script := "#!/bin/sh\n[ \"$1 $2\" = \"hook session-facts\" ] || exit 1\nprintf 'v1;k=ssh;ca=192.0.2.10;krb=bob@EXAMPLE.TEST'\n"
	if err := os.WriteFile(binary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	const connection = "192.0.2.10 50000 192.0.2.20 22"
	envKey := "FILE:" + ccache + "||" + connection + "|"
	cache := filepath.Join(home, ".defenseclaw", "session-facts.json")
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{"expires_at": time.Now().Add(4 * time.Minute).Unix(), "key": "k", "env_key": envKey, "header": "v1;k=ssh;ca=192.0.2.10;krb=alice@EXAMPLE.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, record, 0o600); err != nil {
		t.Fatal(err)
	}
	run := func() string {
		command := exec.Command(shell, "-c", `set -e; source "$0"; defenseclaw_session_facts_full`, helperPath)
		command.Env = append(withoutSessionFactsEnv(os.Environ()),
			"HOME="+home, "SSH_CONNECTION="+connection, "KRB5CCNAME=FILE:"+ccache,
			"DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_SESSION_FACTS_BIN="+binary)
		out, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("helper failed: %v\n%s", err, out)
		}
		return string(out)
	}
	now := time.Now()
	if err := os.Chtimes(ccache, now.Add(-time.Minute), now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := run(); got != "v1;k=ssh;ca=192.0.2.10;krb=alice@EXAMPLE.TEST" {
		t.Fatalf("an unchanged credential cache: facts = %q, want the cached ones", got)
	}
	if err := os.Chtimes(ccache, now.Add(time.Minute), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := run(); got != "v1;k=ssh;ca=192.0.2.10;krb=bob@EXAMPLE.TEST" {
		t.Fatalf("a credential cache newer than the cached facts: facts = %q, want the new principal", got)
	}
}

// The same for the OpenCode plugin's own cache: the stand-in gateway binary
// answers alice and then, as a new kinit into the same cache would, writes
// bob into the cache. The plugin runs the binary again, once, and sends bob.
func TestOpenCodePluginSessionFactsFollowANewKinitIntoTheSameCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in gateway binary is a shell script")
	}
	home := t.TempDir()
	ccache := filepath.Join(t.TempDir(), "krb5cc_test")
	if err := os.WriteFile(ccache, []byte("alice"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "bin", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	calls := filepath.Join(home, "calls")
	script := "#!/bin/sh\n[ \"$1 $2\" = \"hook session-facts\" ] || exit 1\n" +
		"echo x >> " + calls + "\nwho=$(cat " + ccache + ")\nprintf 'v1;k=ssh;ca=192.0.2.10;krb=%s@EXAMPLE.TEST' \"$who\"\n" +
		"[ \"$who\" = alice ] || exit 0\nsleep 0.05\nprintf bob > " + ccache + "\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.20 22")
	t.Setenv("KRB5CCNAME", "FILE:"+ccache)
	var mu sync.Mutex
	var facts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(body, &payload)
		if payload.Event == "tool.execute.before" {
			mu.Lock()
			facts = append(facts, r.Header.Get("X-DefenseClaw-Session-Facts"))
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
	}))
	t.Cleanup(server.Close)
	runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 2)
	mu.Lock()
	defer mu.Unlock()
	ran, _ := os.ReadFile(calls)
	if len(facts) != 2 || !strings.HasSuffix(facts[1], "krb=bob@EXAMPLE.TEST") || strings.Count(string(ran), "x") != 2 {
		t.Fatalf("session facts sent by the plugin = %q after %d binary runs, want bob last and 2 runs (one per cache state)",
			facts, strings.Count(string(ran), "x"))
	}
}

// The warm KCM cache path uses shell builtins for expiry, with no find or
// native helper. Expired records still refresh identity rather than reusing it.
func TestShellHookSessionFactsWarmCacheUsesNoPrograms(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Linux hook uses the Bash epoch clock")
	}
	shell := systemBashForTest(t)
	helper := materializeHookAssetForTest(t, "hooks/_hardening.sh")
	home := t.TempDir()
	cache := filepath.Join(home, ".defenseclaw", "session-facts.json")
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	ran := filepath.Join(bin, "program-ran")
	program := "#!/bin/sh\nprintf ran >> '" + ran + "'\nprintf 'v1;k=console;krb=bob@EXAMPLE.TEST'\n"
	for _, name := range []string{"find", "helper"} {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(program), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	run := func(expires int64) string {
		record, err := json.Marshal(map[string]any{"env_key": "KCM:|||", "header": "v1;k=console;krb=alice@EXAMPLE.TEST", "expires_at": expires})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cache, record, 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(shell, "-c", `source "$0"; defenseclaw_session_facts_full`, helper)
		cmd.Env = append(withoutSessionFactsEnv(os.Environ()), "PATH="+bin,
			"HOME="+home, "KRB5CCNAME=KCM:", "DEFENSECLAW_MANAGED_HOOK=1",
			"DEFENSECLAW_SESSION_FACTS_BIN="+filepath.Join(bin, "helper"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		return string(out)
	}
	if got := run(time.Now().Add(4 * time.Minute).Unix()); got != "v1;k=console;krb=alice@EXAMPLE.TEST" {
		t.Fatalf("fresh cache = %q", got)
	}
	if _, err := os.Stat(ran); !os.IsNotExist(err) {
		t.Fatalf("warm cache executed a program: %v", err)
	}
	if got := run(time.Now().Add(-time.Second).Unix()); got != "v1;k=console;krb=bob@EXAMPLE.TEST" {
		t.Fatalf("expired cache = %q", got)
	}
}
