// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookuser"
)

// S8 B2: guard-user-hook runs the native Claude Code hook in its own process
// (internal/hookuser), behind the same identity checks of the registered
// command line, and never starts defenseclaw-hook-user.

const guardPayload = `{"hook_event_name":"PreToolUse","session_id":"session","tool_name":"Bash","tool_input":{"command":"echo ok"}}`

type guardAccount struct {
	account, bin, home, self, native string
}

func newGuardAccount(t *testing.T) guardAccount {
	t.Helper()
	account := t.TempDir()
	a := guardAccount{account: account, bin: filepath.Join(account, ".local", "bin"), home: filepath.Join(account, ".defenseclaw")}
	for _, dir := range []string{a.bin, filepath.Join(a.home, "hooks")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(a.home, "hooks", ".hook-claudecode.token"), []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.self = filepath.Join(a.bin, "defenseclaw-hook-post")
	if err := os.WriteFile(a.self, []byte("guard fixture\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	a.native = filepath.Join(a.bin, "defenseclaw-hook-user")
	// The call starts now, not when the test process started.
	saved := guardStartedAt
	guardStartedAt = time.Now
	t.Cleanup(func() { guardStartedAt = saved })
	return a
}

func (a guardAccount) args(addr string) []string {
	args := []string{"guard-user-hook", a.native, "hook", "--connector", "claudecode", "--hook-home", a.home}
	if addr != "" {
		args = append(args, "--api-addr", addr)
	}
	return args
}

// stubGateway answers every hook call with reply and records what it got.
type stubGateway struct {
	server *httptest.Server
	reply  atomic.Value
	mu     sync.Mutex
	seen   []string
}

func newStubGateway(t *testing.T) *stubGateway {
	t.Helper()
	g := &stubGateway{}
	g.reply.Store(`{"action":"block","reason":"policy"}`)
	g.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		g.mu.Lock()
		g.seen = append(g.seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("Authorization")+" "+string(body))
		g.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, g.reply.Load().(string))
	}))
	t.Cleanup(g.server.Close)
	return g
}

func (g *stubGateway) addr() string { return strings.TrimPrefix(g.server.URL, "http://") }

func (g *stubGateway) calls() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.seen...)
}

type guardResult struct {
	code        int
	out, errOut string
}

func guardCall(a guardAccount, args []string, payload string) guardResult {
	var out, errOut bytes.Buffer
	code := runUserHookGuardAt(a.self, args, strings.NewReader(payload), &out, &errOut)
	return guardResult{code, out.String(), errOut.String()}
}

// Whatever state the defenseclaw-hook-user file is in, the guard decides the
// call with the gateway itself: a script that would allow everything is
// never run (the protected call is still blocked).
func TestB2GuardDecidesWithoutTheHookUserBinary(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, native string)
	}{
		{"missing", func(*testing.T, string) {}},
		{"truncated", func(t *testing.T, native string) { write(t, native, "\x7fELF\x02", 0o700) }},
		{"not executable", func(t *testing.T, native string) { write(t, native, "#!/bin/sh\nexit 0\n", 0o600) }},
		{"group-writable", func(t *testing.T, native string) {
			write(t, native, "#!/bin/sh\nexit 0\n", 0o700)
			if err := os.Chmod(native, 0o770); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink elsewhere", func(t *testing.T, native string) {
			if err := os.Symlink("/bin/true", native); err != nil {
				t.Fatal(err)
			}
		}},
		{"allow-everything stand-in", func(t *testing.T, native string) {
			write(t, native, "#!/bin/sh\necho '{\"action\":\"allow\"}'\nexit 0\n", 0o700)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newGuardAccount(t)
			tc.setup(t, a.native)
			g := newStubGateway(t)
			if r := guardCall(a, a.args(g.addr()), guardPayload); r.code != 2 || !strings.Contains(r.errOut, "policy") {
				t.Fatalf("protected: %+v", r)
			}
			g.reply.Store(`{"action":"allow"}`)
			if r := guardCall(a, a.args(g.addr()), guardPayload); r.code != 0 || strings.Contains(r.out, "deny") {
				t.Fatalf("ordinary: %+v", r)
			}
			if n := len(g.calls()); n != 2 {
				t.Fatalf("gateway got %d calls, want 2 (one per call, from this process)", n)
			}
		})
	}
}

func write(t *testing.T, path, body string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
}

// The guard leg gives exactly the answer and sends exactly the request of the
// native hook it replaces (hookuser.Run with the same registration): block,
// allow, and a gateway that is down.
func TestB2GuardAnswersAsTheNativeHook(t *testing.T) {
	a := newGuardAccount(t)
	g := newStubGateway(t)
	for _, tc := range []struct{ name, reply string }{
		{"block", `{"action":"block","reason":"policy"}`},
		{"allow", `{"action":"allow"}`},
		{"warn", `{"action":"allow","severity":"MEDIUM","reason":"review"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g.reply.Store(tc.reply)
			before := len(g.calls())
			viaGuard := guardCall(a, a.args(g.addr()), guardPayload)
			var out, errOut bytes.Buffer
			code := hookuser.Run(a.native, a.home, g.addr(), strings.NewReader(guardPayload), &out, &errOut, time.Now())
			direct := guardResult{code, out.String(), errOut.String()}
			if viaGuard != direct {
				t.Fatalf("guard %+v, native hook %+v", viaGuard, direct)
			}
			calls := g.calls()[before:]
			if len(calls) != 2 || calls[0] != calls[1] {
				t.Fatalf("requests differ: %q", calls)
			}
		})
	}
	// A down gateway: each side runs in a child process, as in production, since
	// the call's deadline watchdog ends the process it runs in.
	t.Run("gateway down", func(t *testing.T) {
		down := newStubGateway(t)
		addr := down.addr()
		down.server.Close()
		viaGuard, direct := downChild(t, a, addr, "guard"), downChild(t, a, addr, "native")
		if viaGuard != direct || !strings.Contains(viaGuard, `permissionDecision`) {
			t.Fatalf("down: guard and native hook differ:\n%s\n%s", viaGuard, direct)
		}
	})
}

const guardDownChildEnv = "DC_TEST_B2_DOWN_CHILD"

// TestB2GuardDownChild is the child of the gateway-down comparison.
func TestB2GuardDownChild(t *testing.T) {
	spec := os.Getenv(guardDownChildEnv)
	if spec == "" {
		t.Skip("child process only")
	}
	parts := strings.SplitN(spec, "|", 6)
	a := guardAccount{account: parts[1], bin: parts[2], home: parts[3], self: parts[4]}
	a.native = filepath.Join(a.bin, "defenseclaw-hook-user")
	addr := parts[5]
	guardStartedAt = time.Now
	var out, errOut bytes.Buffer
	var code int
	if parts[0] == "guard" {
		code = runUserHookGuardAt(a.self, a.args(addr), strings.NewReader(guardPayload), &out, &errOut)
	} else {
		code = hookuser.Run(a.native, a.home, addr, strings.NewReader(guardPayload), &out, &errOut, time.Now())
	}
	fmt.Printf("RESULT code=%d stdout=%q stderr=%q\n", code, out.String(), errOut.String())
}

func downChild(t *testing.T, a guardAccount, addr, side string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestB2GuardDownChild$")
	cmd.Env = append(os.Environ(), guardDownChildEnv+"="+strings.Join([]string{side, a.account, a.bin, a.home, a.self, addr}, "|"))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s child: %v %q", side, err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "RESULT ") {
			return line
		}
	}
	t.Fatalf("%s child gave no result: %q", side, out)
	return ""
}

// A registration without --api-addr (the 1.0.9 shape too) reads the address
// from the hook config, as the native hook does.
func TestB2GuardRegistrationWithoutAddress(t *testing.T) {
	a := newGuardAccount(t)
	g := newStubGateway(t)
	write(t, filepath.Join(a.home, "hooks", ".hookcfg"), fmt.Sprintf(`{"version":2,"gateway_addr":%q}`, g.addr()), 0o600)
	if r := guardCall(a, a.args(""), guardPayload); r.code != 2 || !strings.Contains(r.errOut, "policy") || len(g.calls()) != 1 {
		t.Fatalf("protected without --api-addr: %+v, %d calls", r, len(g.calls()))
	}
}

// Every identity check of the command line still runs before the call: a
// command line that fails one sends nothing.
func TestB2GuardKeepsItsIdentityChecks(t *testing.T) {
	a := newGuardAccount(t)
	g := newStubGateway(t)
	other := filepath.Join(t.TempDir(), "defenseclaw-hook-post")
	write(t, other, "another file\n", 0o700)
	for _, tc := range []struct {
		name string
		self string
		args func() []string
	}{
		{"hook-user of another folder", a.self, func() []string {
			args := a.args(g.addr())
			args[1] = filepath.Join(t.TempDir(), ".local", "bin", "defenseclaw-hook-user")
			return args
		}},
		{"guard that is not the registered hook-post", other, func() []string { return a.args(g.addr()) }},
		{"home that is not .defenseclaw", a.self, func() []string {
			args := a.args(g.addr())
			args[6] = filepath.Join(a.account, "elsewhere")
			return args
		}},
		{"relative home", a.self, func() []string {
			args := a.args(g.addr())
			args[6] = ".defenseclaw"
			return args
		}},
		{"other connector", a.self, func() []string {
			args := a.args(g.addr())
			args[4] = "codex"
			return args
		}},
		{"extra argument", a.self, func() []string { return append(a.args(g.addr()), "--x") }},
		{"non-loopback address", a.self, func() []string { return a.args("192.0.2.1:18970") }},
		{"home with a newline", a.self, func() []string {
			args := a.args(g.addr())
			args[6] = filepath.Join(a.account, "x\n", ".defenseclaw")
			return args
		}},
		{"address flag misnamed", a.self, func() []string {
			args := a.args(g.addr())
			args[7] = "--api"
			return args
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			code := runUserHookGuardAt(tc.self, tc.args(), strings.NewReader(guardPayload), &out, &errOut)
			if code != 2 || !strings.Contains(errOut.String(), "registration is invalid") {
				t.Fatalf("exit %d stdout %q stderr %q", code, out.String(), errOut.String())
			}
		})
	}
	if n := len(g.calls()); n != 0 {
		t.Fatalf("refused command lines sent %d calls", n)
	}
}

// An account reached through a symlinked path answers as before.
func TestB2GuardSymlinkedAccount(t *testing.T) {
	a := newGuardAccount(t)
	g := newStubGateway(t)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(a.account, alias); err != nil {
		t.Fatal(err)
	}
	args := []string{"guard-user-hook", filepath.Join(alias, ".local", "bin", "defenseclaw-hook-user"),
		"hook", "--connector", "claudecode", "--hook-home", filepath.Join(alias, ".defenseclaw"), "--api-addr", g.addr()}
	if r := guardCall(a, args, guardPayload); r.code != 2 || !strings.Contains(r.errOut, "policy") {
		t.Fatalf("protected: %+v", r)
	}
	g.reply.Store(`{"action":"allow"}`)
	if r := guardCall(a, args, guardPayload); r.code != 0 {
		t.Fatalf("ordinary: %+v", r)
	}
}

// The guard leg answers under the shell options of a caller as before.
func TestB2GuardUnderShellOptions(t *testing.T) {
	startup := filepath.Join(t.TempDir(), "startup.sh")
	write(t, startup, "exit 0\n", 0o600)
	for _, env := range []map[string]string{
		{"SHELLOPTS": "noexec"},
		{"SHELLOPTS": "noexec:errexit"},
		{"SHELLOPTS": "noexec:posix"},
		{"SHELLOPTS": "noexec", "BASH_ENV": startup, "FUNCNEST": "1", "BASHOPTS": "failglob:nullglob"},
	} {
		for key, value := range env {
			t.Setenv(key, value)
		}
		a := newGuardAccount(t)
		g := newStubGateway(t)
		if r := guardCall(a, a.args(g.addr()), guardPayload); r.code != 2 {
			t.Fatalf("%v protected: %+v", env, r)
		}
		g.reply.Store(`{"action":"allow"}`)
		if r := guardCall(a, a.args(g.addr()), guardPayload); r.code != 0 {
			t.Fatalf("%v ordinary: %+v", env, r)
		}
	}
}
