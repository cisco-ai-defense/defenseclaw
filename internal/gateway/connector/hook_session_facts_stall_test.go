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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// A credential cache on a stalled network or FUSE mount does not hold the
// shell hook: the check that it changed since the cached session facts (a
// find here that never answers) is given a second, and the hook then sends
// the session variables alone, without running the binary, which would wait
// on the same cache.
func TestShellHookSessionFactsSkipAStalledCredentialCache(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows hooks report identity from hookexec, not from the shell helper")
	}
	shell := systemBashForTest(t)
	helperPath := materializeHookAssetForTest(t, "hooks/_hardening.sh")
	realFind, err := exec.LookPath("find")
	if err != nil {
		t.Skip("no find")
	}
	home := t.TempDir()
	ccache := filepath.Join(t.TempDir(), "krb5cc_test")
	if err := os.WriteFile(ccache, []byte("ticket"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(ccache, old, old); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	stalledFind := "#!/bin/sh\nfor a in \"$@\"; do [ \"$a\" = -newer ] && exec sleep 10; done\nexec " + realFind + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "find"), []byte(stalledFind), 0o755); err != nil {
		t.Fatal(err)
	}
	ran := filepath.Join(home, "ran")
	binary := filepath.Join(t.TempDir(), "defenseclaw-hook")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\ntouch "+ran+"\nprintf 'v1;k=ssh;ca=192.0.2.10;krb=bob@EXAMPLE.TEST'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	const connection = "192.0.2.10 50000 192.0.2.20 22"
	cache := filepath.Join(home, ".defenseclaw", "session-facts.json")
	if err := os.MkdirAll(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{"expires_at": time.Now().Add(4 * time.Minute).Unix(), "key": "k", "env_key": "FILE:" + ccache + "||" + connection + "|", "header": "v1;k=ssh;ca=192.0.2.10;krb=alice@EXAMPLE.TEST"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, record, 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(shell, "-c", `set -e; source "$0"; defenseclaw_session_facts_full`, helperPath)
	command.Env = append(withoutSessionFactsEnv(os.Environ()),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		"HOME="+home, "SSH_CONNECTION="+connection, "KRB5CCNAME=FILE:"+ccache,
		"DEFENSECLAW_MANAGED_HOOK=1", "DEFENSECLAW_SESSION_FACTS_BIN="+binary)
	started := time.Now()
	out, err := command.CombinedOutput()
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, out)
	}
	if elapsed > 4*time.Second {
		t.Fatalf("a stalled credential cache held the hook %s, want about 1 s", elapsed)
	}
	if string(out) != "" {
		t.Fatalf("a stalled credential cache: facts = %q, want none (the session variables alone follow)", out)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("a stalled credential cache ran the session facts binary")
	}
}

// openCodeStalledCacheHarness runs the OpenCode plugin with a credential
// cache that never answers a stat: statSync spins for 3 s on it (as a
// blocking stat on a stalled mount holds the event loop), the async stat
// never settles.
const openCodeStalledCacheHarness = `
import { pathToFileURL } from "node:url";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
const stalled = process.env.KRB5CCNAME.slice(5);
const statSync = fs.statSync;
fs.statSync = function (path, ...rest) {
  if (String(path) === stalled) { const end = Date.now() + 3000; while (Date.now() < end) {} }
  return statSync.call(this, path, ...rest);
};
const stat = fs.promises.stat;
fs.promises.stat = function (path, ...rest) {
  if (String(path) === stalled) return new Promise(() => {});
  return stat.call(this, path, ...rest);
};
syncBuiltinESMExports();
const client = { tui: { showToast: async () => true } };
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await loaded.DefenseClaw({ directory: "", client });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
const started = Date.now();
for (let i = 0; i < 2; i++) {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" + i }, { args: { command: "echo marker" } });
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
console.log("elapsed:" + (Date.now() - started));
`

// The OpenCode plugin's credential cache check does not hold the agent's
// event loop either: a stat that has not answered in 250 ms reads as a
// stall, the call goes on with the session variables alone, and a later
// call does not wait on the same stat again.
func TestOpenCodePluginSessionFactsSkipAStalledCredentialCache(t *testing.T) {
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
	ran := filepath.Join(home, "ran")
	script := "#!/bin/sh\n[ \"$1 $2\" = \"hook session-facts\" ] || exit 1\ntouch " + ran + "\nprintf 'v1;k=ssh;ca=192.0.2.10;krb=alice@EXAMPLE.TEST'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.20 22")
	t.Setenv("KRB5CCNAME", "FILE:"+ccache)
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
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
	lines := runNodeHarness(t, openCodeStalledCacheHarness, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", openCodePluginTestData(t, server)))
	elapsed := -1
	for _, line := range lines {
		if v, ok := strings.CutPrefix(line, "elapsed:"); ok {
			elapsed, _ = strconv.Atoi(v)
		}
	}
	if elapsed < 0 || elapsed > 1500 {
		t.Fatalf("two tool calls with a stalled credential cache took %d ms, want well under 1.5 s; output %q", elapsed, lines)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(facts) != 2 || facts[0] != "v1;k=ssh;ca=192.0.2.10" || facts[1] != facts[0] {
		t.Fatalf("session facts sent = %q, want the session variables alone on both calls", facts)
	}
	if _, err := os.Stat(ran); err == nil {
		t.Fatal("a stalled credential cache ran the session facts binary")
	}
}

// An idle OpenCode session can wake while the Kerberos cache or its reader is
// slow. Its first actionable hook must reach the gateway inside the hook
// budget with the available SSH facts; a principal is optional (GAP-0744).
func TestOpenCodeIdleWakeAnswersWhilePrincipalReaderStalls(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in session-facts binary is a shell script")
	}
	home := t.TempDir()
	ccache := filepath.Join(home, "krb5cc")
	if err := os.WriteFile(ccache, []byte("ticket"), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(home, ".local", "bin", "defenseclaw-gateway")
	if err := os.MkdirAll(filepath.Dir(binary), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nsleep 3\nprintf 'v1;k=ssh;krb=late@EXAMPLE.TEST'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("KRB5CCNAME", "FILE:"+ccache)
	t.Setenv("SSH_CONNECTION", "192.0.2.10 50000 192.0.2.20 22")
	t.Setenv("SSH_TTY", "")
	t.Setenv("XDG_SESSION_ID", "")
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
		_, _ = io.WriteString(w, `{"action":"allow","mode":"observe"}`)
	}))
	defer server.Close()
	harness := `
import { pathToFileURL } from "node:url";
const plugin = await (await import(pathToFileURL(process.argv[1]).href)).DefenseClaw({ directory: "", client: { tui: { showToast: async () => true } } });
const started = Date.now();
try { await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" }, { args: { command: "echo marker" } }); }
catch (error) { console.log("block:" + String(error && error.message || error)); }
console.log("elapsed:" + (Date.now() - started));
`
	lines := runNodeHarness(t, harness, writeRenderedPlugin(t, "opencode-plugin.js", "defenseclaw.mjs", openCodePluginTestData(t, server)))
	elapsed := -1
	for _, line := range lines {
		if v, ok := strings.CutPrefix(line, "elapsed:"); ok {
			elapsed, _ = strconv.Atoi(v)
		}
	}
	if elapsed < 0 || elapsed > 1500 {
		t.Fatalf("idle wake took %d ms, want a gateway answer within 1.5s; output %q", elapsed, lines)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(facts) != 1 || facts[0] != "v1;k=ssh;ca=192.0.2.10" {
		t.Fatalf("idle wake session facts = %q, want the available SSH facts", facts)
	}
}
