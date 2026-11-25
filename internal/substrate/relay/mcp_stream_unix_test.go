// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// The mcp/NAME stream tests (B3.3 S4b) drive the relay only through its
// route, its socket and the files it writes, so each one fails on a relay
// without the bridge (502a5cb209) by what it does, not by a missing name.

type mcpEnv struct {
	t    *testing.T
	home string
	ws   string
	tok  func(scope string) string
}

// newMCPEnv serves a relay for connector with HOME at a short folder (a
// unix socket path is at most ~104 bytes).
func newMCPEnv(t *testing.T, connector string) *mcpEnv {
	t.Helper()
	home, err := os.MkdirTemp("", "mcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(home) })
	t.Setenv("HOME", home)
	s, _, ec := testServer(t, []string{"sh"})
	s.opts.Config.Relay.Connector = connector
	s.opts.Config.Relay.ClaudeStateFile = filepath.Join(home, ".claude.json")
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &mcpEnv{t: t, home: home,
		ws: "ws" + strings.TrimPrefix(srv.URL, "http") + "/dcrelay/1/mcp/",
		tok: func(scope string) string {
			return ec.token(t, claims(time.Now(), func(c map[string]any) { c["dc.scope"] = scope }), TokenType)
		}}
}

func (e *mcpEnv) sock(name string) string {
	return filepath.Join(e.home, ".defenseclaw-mcp", name+".sock")
}

// open opens the stream for name and waits for its socket.
func (e *mcpEnv) open(name string) *websocket.Conn {
	e.t.Helper()
	conn, resp, err := portDial(e.ws+name, e.tok("mcp:"+name))
	if err != nil {
		e.t.Fatalf("open mcp/%s: %v %v", name, resp, err)
	}
	e.t.Cleanup(func() { _ = conn.Close() })
	mcpWait(e.t, "socket "+name, func() bool {
		fi, err := os.Lstat(e.sock(name))
		return err == nil && fi.Mode()&fs.ModeSocket != 0
	})
	return conn
}

// shim connects an agent client to name and waits for the open control
// (the relay has configured the agent and serves the stream).
func (e *mcpEnv) shim(name string, ws *websocket.Conn) net.Conn {
	e.t.Helper()
	var c net.Conn
	mcpWait(e.t, "shim "+name+" connected", func() bool {
		var err error
		c, err = net.Dial("unix", e.sock(name))
		return err == nil
	})
	e.t.Cleanup(func() { _ = c.Close() })
	mcpWantControl(e.t, ws, `{"type":"open"}`)
	return c
}

func mcpWait(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if ok() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func mcpRead(t *testing.T, ws *websocket.Conn) (int, string) {
	t.Helper()
	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	kind, p, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return kind, string(p)
}

func mcpWantControl(t *testing.T, ws *websocket.Conn, want string) {
	t.Helper()
	if kind, got := mcpRead(t, ws); kind != websocket.TextMessage || got != want {
		t.Fatalf("control %d %q, want text %q", kind, got, want)
	}
}

func mcpGone(t *testing.T, path string) {
	t.Helper()
	mcpWait(t, path+" removed", func() bool {
		_, err := os.Lstat(path)
		return errors.Is(err, fs.ErrNotExist)
	})
}

// TestMCPStreamScopeRequired: mcp/NAME opens only with a token scoped
// mcp:NAME; a port token, another name's token or a terminal token is
// refused (403) and a name outside MCPNameRE is not a route (404).
func TestMCPStreamScopeRequired(t *testing.T) {
	e := newMCPEnv(t, "claudecode")
	for _, scope := range []string{"port:3000", "mcp:other", ""} {
		_, resp, err := portDial(e.ws+"notes", e.tok(scope))
		if err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
			t.Fatalf("scope %q: %v %v, want 403", scope, resp, err)
		}
	}
	for _, bad := range []string{"Notes", "a.b", strings.Repeat("a", 33), "-x"} {
		_, resp, err := portDial(e.ws+bad, e.tok("mcp:"+bad))
		if err == nil || resp == nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("name %q: %v %v, want 404", bad, resp, err)
		}
	}
	e.open("notes")
}

// TestMCPSocketModes: the socket is HOME/.defenseclaw-mcp/NAME.sock, the
// folder 0700 (an existing looser one is tightened), the socket 0600, both
// owned by the agent's user (here the relay's own: not separated), a stale
// socket is replaced, anything else at the path refuses the stream, and
// the socket goes when the stream ends.
func TestMCPSocketModes(t *testing.T) {
	e := newMCPEnv(t, "claudecode")
	dir := filepath.Join(e.home, ".defenseclaw-mcp")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stale, err := net.ListenUnix("unix", &net.UnixAddr{Name: e.sock("notes"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	stale.SetUnlinkOnClose(false)
	_ = stale.Close() // a socket file nobody listens on
	ws := e.open("notes")
	e.shim("notes", ws) // the stale socket was replaced by a live one
	for _, c := range []struct {
		path string
		mode fs.FileMode
		sock bool
	}{{dir, 0o700, false}, {e.sock("notes"), 0o600, true}} {
		fi, err := os.Lstat(c.path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != c.mode || (fi.Mode()&fs.ModeSocket != 0) != c.sock {
			t.Fatalf("%s mode %v, want %v socket=%v", c.path, fi.Mode(), c.mode, c.sock)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != os.Getuid() || int(st.Gid) != os.Getgid() {
			t.Fatalf("%s owner %+v, want %d:%d", c.path, fi.Sys(), os.Getuid(), os.Getgid())
		}
	}
	_ = ws.Close()
	mcpGone(t, e.sock("notes"))

	// A regular file at the socket path is left alone and the stream refused.
	keep := e.sock("plain")
	if err := os.WriteFile(keep, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	conn, resp, err := portDial(e.ws+"plain", e.tok("mcp:plain"))
	if err != nil {
		t.Fatalf("open: %v %v", resp, err)
	}
	defer conn.Close()
	mcpWantControl(t, conn, `{"type":"error","code":"mcp_unavailable"}`)
	if b, err := os.ReadFile(keep); err != nil || string(b) != "mine" {
		t.Fatalf("the file at the socket path changed: %q %v", b, err)
	}
}

// TestMCPOneStreamPerName: a second stream for a bridged name gets
// mcp_busy and ends; another name opens; the name is free again once its
// stream ends.
func TestMCPOneStreamPerName(t *testing.T) {
	e := newMCPEnv(t, "claudecode")
	first := e.open("notes")
	second, resp, err := portDial(e.ws+"notes", e.tok("mcp:notes"))
	if err != nil {
		t.Fatalf("second: %v %v", resp, err)
	}
	mcpWantControl(t, second, `{"type":"error","code":"mcp_busy"}`)
	_ = second.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, _, err := second.ReadMessage(); err == nil {
		t.Fatal("the busy stream stayed open")
	}
	e.open("gh")
	_ = first.Close()
	mcpGone(t, e.sock("notes"))
	var again *websocket.Conn
	mcpWait(t, "notes free again", func() bool {
		c, _, err := portDial(e.ws+"notes", e.tok("mcp:notes"))
		if err != nil {
			return false
		}
		_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if _, _, err := c.ReadMessage(); err == nil {
			_ = c.Close() // still busy
			return false
		}
		again = c
		return true
	})
	defer again.Close()
}

// TestMCPOneShimAtATime: one agent client at a time (a second is closed at
// once); its disconnect is a close control; a WebSocket error control drops
// it; the next client is served.
func TestMCPOneShimAtATime(t *testing.T) {
	e := newMCPEnv(t, "claudecode")
	ws := e.open("notes")
	a := e.shim("notes", ws)
	b, err := net.Dial("unix", e.sock("notes"))
	if err != nil {
		t.Fatal(err)
	}
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := b.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("second shim served: %d %v", n, err)
	}
	_ = a.Close()
	mcpWantControl(t, ws, `{"type":"close"}`)
	c := e.shim("notes", ws)
	if err := ws.WriteMessage(websocket.TextMessage, []byte(`{"type":"error","code":"laptop_gone"}`)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("shim kept after an error control: %d %v", n, err)
	}
	mcpWantControl(t, ws, `{"type":"close"}`)
	e.shim("notes", ws)
}

// TestMCPLineFraming: each line the agent writes is one binary frame, byte
// for byte without its "\n" or "\r\n" (odd bytes and escapes included);
// each laptop frame is one line for the agent. A frame with whitespace
// newlines is compacted to one line; one that would still be two lines (a
// raw newline inside a string) is dropped, never split.
func TestMCPLineFraming(t *testing.T) {
	e := newMCPEnv(t, "claudecode")
	ws := e.open("notes")
	c := e.shim("notes", ws)
	lines := []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
		"{\"a\":\"\\u2028 \\\" \\\\n \xc3\xa9 \xff\",  \"b\" : 1.50e+1 }",
	}
	if _, err := c.Write([]byte(lines[0] + "\n" + lines[1] + "\r\n")); err != nil {
		t.Fatal(err)
	}
	for _, want := range lines {
		if kind, got := mcpRead(t, ws); kind != websocket.BinaryMessage || got != want {
			t.Fatalf("frame %d %q, want binary %q", kind, got, want)
		}
	}
	r := bufio.NewReader(c)
	next := func() string {
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		l, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("agent read: %q %v", l, err)
		}
		return l
	}
	for _, f := range []struct{ frame, line string }{
		{`{"id":1,"result":{"x":"\n "}}`, `{"id":1,"result":{"x":"\n "}}` + "\n"},
		{"{\n  \"id\": 2,\r\n  \"result\": {}\n}", `{"id":2,"result":{}}` + "\n"},
		{"{\"id\":3,\"result\":\"a\nb\"}", ""}, // dropped
		{"\n", ""},                             // dropped
		{`{"id":4}`, `{"id":4}` + "\n"},
	} {
		if err := ws.WriteMessage(websocket.BinaryMessage, []byte(f.frame)); err != nil {
			t.Fatal(err)
		}
		if f.line == "" {
			continue
		}
		if got := next(); got != f.line {
			t.Fatalf("frame %q reached the agent as %q, want %q", f.frame, got, f.line)
		}
	}
}

// TestMCPAgentEntry: while a stream is up the agent's user-scope MCP
// configuration names the mcp-stdio shim for NAME (Claude Code
// ~/.claude.json mcpServers, OpenCode opencode.json mcp, Codex
// config.toml [mcp_servers.NAME]); when it ends the entry goes and the rest
// of the file is as it was. A same-name entry that is not the relay's is
// left alone and survives the stream.
func TestMCPAgentEntry(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	shim := []any{exe, "mcp-stdio", "notes"}
	type check func(t *testing.T, raw []byte)
	jsonEntry := func(key string, want func(m map[string]any) bool) check {
		return func(t *testing.T, raw []byte) {
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("%q: %v", raw, err)
			}
			m, _ := doc[key].(map[string]any)
			n, _ := m["notes"].(map[string]any)
			if n == nil || !want(n) {
				t.Fatalf("no bridge entry under %s: %s", key, raw)
			}
		}
	}
	argv := func(m map[string]any) []any {
		var out []any
		if c, ok := m["command"].(string); ok {
			out = append(out, c)
		} else {
			out, _ = m["command"].([]any)
		}
		a, _ := m["args"].([]any)
		return append(out, a...)
	}
	same := func(a, b []any) bool { x, _ := json.Marshal(a); y, _ := json.Marshal(b); return string(x) == string(y) }
	cases := []struct {
		connector, file, before string
		on                      check
		foreign                 string
	}{
		{"claudecode", ".claude.json", `{"keep":1,"mcpServers":{"other":{"command":"x"}}}`,
			jsonEntry("mcpServers", func(m map[string]any) bool { return m["type"] == "stdio" && same(argv(m), shim) }),
			`{"mcpServers":{"notes":{"command":"/usr/bin/foreign"}}}`},
		{"opencode", ".config/opencode/opencode.json", `{"theme":"x","mcp":{"other":{"type":"local","command":["x"]}}}`,
			jsonEntry("mcp", func(m map[string]any) bool {
				return m["type"] == "local" && m["enabled"] == true && same(argv(m), shim)
			}),
			`{"mcp":{"notes":{"type":"remote","url":"https://example.test"}}}`},
		{"codex", ".codex/config.toml", "model = \"x\"\n\n[mcp_servers.other]\ncommand = \"y\"\n",
			func(t *testing.T, raw []byte) {
				want := "[mcp_servers.notes]\ncommand = " + jsonQuote(exe) + "\nargs = [\"mcp-stdio\", \"notes\"]\n"
				if !strings.Contains(string(raw), want) {
					t.Fatalf("no codex block %q in %q", want, raw)
				}
			},
			"[mcp_servers.notes]\ncommand = \"/usr/bin/foreign\"\n"},
	}
	for _, c := range cases {
		t.Run(c.connector, func(t *testing.T) {
			for _, before := range []string{c.before, c.foreign} {
				e := newMCPEnv(t, c.connector)
				path := filepath.Join(e.home, c.file)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
					t.Fatal(err)
				}
				ws := e.open("notes")
				e.shim("notes", ws)
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if before == c.foreign {
					if string(raw) != before {
						t.Fatalf("a foreign entry was changed: %q -> %q", before, raw)
					}
				} else {
					c.on(t, raw)
				}
				_ = ws.Close()
				mcpGone(t, e.sock("notes"))
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if c.connector == "codex" || before == c.foreign {
					if string(after) != before {
						t.Fatalf("after the stream %q, want the file as before %q", after, before)
					}
					continue
				}
				var got, want map[string]any
				_ = json.Unmarshal(after, &got)
				_ = json.Unmarshal([]byte(before), &want)
				if x, _ := json.Marshal(got); string(x) != mustJSON(want) {
					t.Fatalf("after the stream %s, want %s", x, mustJSON(want))
				}
			}
		})
	}
}

func jsonQuote(s string) string { b, _ := json.Marshal(s); return string(b) }
func mustJSON(v any) string     { b, _ := json.Marshal(v); return string(b) }
