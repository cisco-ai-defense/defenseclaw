// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// MCP stream bounds (B3.3). A binary message is one JSON-RPC message; the
// gateway refuses one over message_max_bytes (S4a), the relay never reads
// more than mcpReadLimit.
const (
	mcpReadLimit = 4 << 20
	// MCPSocketDir is the folder under the agent's home that holds one
	// socket per bridged server, NAME.sock (dir 0700, socket 0600, both
	// the agent's user).
	MCPSocketDir = ".defenseclaw-mcp"
	// MCPErrBusy is the control code when the name already has a stream.
	MCPErrBusy = "mcp_busy"
)

// MCPControl is a text (control) message of an mcp stream: open (the
// agent's shim connected), close (it disconnected), error (CODE).
type MCPControl struct {
	Type string `json:"type"`
	Code string `json:"code,omitempty"`
}

// mcpSocketPath is the socket of NAME under home.
func mcpSocketPath(home, name string) string {
	return filepath.Join(home, MCPSocketDir, name+".sock")
}

// serveMCP bridges one laptop MCP server to the agent (B3.3), under a token
// scoped to mcp:NAME only (dc.scope). While the stream is up the relay
// listens on the agent's socket for NAME and the agent's user-scope MCP
// configuration names the mcp-stdio shim; both go when the stream ends.
func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !MCPNameRE.MatchString(name) {
		http.Error(w, "relay: an MCP server name is a-z, 0-9, _ and -, up to 32", http.StatusNotFound)
		return
	}
	if _, ok := s.authScope(w, r, "mcp", true, "mcp:"+name); !ok {
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(mcpReadLimit)
	b := &mcpBridge{conn: conn, log: s.log, name: name}
	if !s.mcpTake(name) {
		b.control(MCPControl{Type: "error", Code: MCPErrBusy})
		return
	}
	defer s.mcpRelease(name)
	home, err := os.UserHomeDir()
	if err != nil {
		s.log.Warn("relay.mcp_refused", "name", name, "error", err.Error())
		b.control(MCPControl{Type: "error", Code: "mcp_unavailable"})
		return
	}
	ln, err := s.mcpListen(home, name)
	if err != nil {
		s.log.Warn("relay.mcp_refused", "name", name, "error", err.Error())
		b.control(MCPControl{Type: "error", Code: "mcp_unavailable"})
		return
	}
	b.ln = ln
	defer s.mcpUnlisten(ln, home, name)
	if err := s.mcpConfigure(home, name, true); err != nil {
		// The bridge still serves a client the agent configures itself.
		s.log.Warn("relay.mcp_config", "name", name, "error", err.Error())
	} else {
		defer func() {
			if err := s.mcpConfigure(home, name, false); err != nil {
				s.log.Warn("relay.mcp_config", "name", name, "error", err.Error())
			}
		}()
	}
	s.log.Info("relay.mcp_open", "name", name)
	b.run()
	s.log.Info("relay.mcp_close", "name", name)
}

// mcpTake marks name as bridged; false when it already is.
func (s *Server) mcpTake(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mcpOpen == nil {
		s.mcpOpen = map[string]bool{}
	}
	if s.mcpOpen[name] {
		return false
	}
	s.mcpOpen[name] = true
	return true
}

func (s *Server) mcpRelease(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mcpOpen, name)
}

// mcpListen makes the agent's socket for name, with the agent's file
// permissions (a separated relay takes the agent's file-system identity,
// so a link the agent planted is followed only as far as the agent could).
func (s *Server) mcpListen(home, name string) (ln *net.UnixListener, err error) {
	path := mcpSocketPath(home, name)
	run := func() { ln, err = listenMCPSocket(path) }
	if !s.opts.sep.withAgentFS(run) {
		return nil, errors.New("relay: the agent's identity could not be taken")
	}
	return ln, err
}

func (s *Server) mcpUnlisten(ln *net.UnixListener, home, name string) {
	_ = ln.Close()
	s.opts.sep.withAgentFS(func() { _ = removeMCPSocket(mcpSocketPath(home, name)) })
}

func listenMCPSocket(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("relay: %s is not a folder", dir)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	if err := removeMCPSocket(path); err != nil {
		return nil, err
	}
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	ln.SetUnlinkOnClose(false)
	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// removeMCPSocket removes a stale socket at path; anything else there is
// left alone and refused.
func removeMCPSocket(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSocket == 0 {
		return fmt.Errorf("relay: %s is not a socket", path)
	}
	return os.Remove(path)
}

// mcpBridge is one mcp stream: the WebSocket to the gateway and at most one
// connected shim.
type mcpBridge struct {
	conn *websocket.Conn
	log  interface {
		Warn(string, ...any)
		Info(string, ...any)
	}
	name string
	ln   *net.UnixListener

	wmu   sync.Mutex
	mu    sync.Mutex
	shim  net.Conn
	ended bool
}

func (b *mcpBridge) control(c MCPControl) error {
	raw, _ := json.Marshal(c)
	return b.write(websocket.TextMessage, raw)
}

func (b *mcpBridge) write(kind int, p []byte) error {
	b.wmu.Lock()
	defer b.wmu.Unlock()
	_ = b.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return b.conn.WriteMessage(kind, p)
}

// run serves the stream until the WebSocket ends. No pings: idle_close
// counts bytes (S2B-6).
func (b *mcpBridge) run() {
	go b.accept()
	for {
		kind, rd, err := b.conn.NextReader()
		if err != nil {
			break
		}
		msg, err := io.ReadAll(rd)
		if err != nil {
			break
		}
		if kind == websocket.TextMessage {
			var c MCPControl
			if json.Unmarshal(msg, &c) == nil && c.Type == "error" {
				b.dropShim()
			}
			continue
		}
		line, ok := mcpLine(msg)
		if !ok {
			b.log.Warn("relay.mcp_frame_dropped", "name", b.name, "reason", "not one JSON-RPC message")
			continue
		}
		b.mu.Lock()
		shim := b.shim
		b.mu.Unlock()
		if shim == nil {
			continue // no agent client yet: nothing to deliver to
		}
		_ = shim.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := shim.Write(line); err != nil {
			b.dropShim()
		}
	}
	b.mu.Lock()
	b.ended = true
	shim := b.shim
	b.mu.Unlock()
	_ = b.ln.Close()
	if shim != nil {
		_ = shim.Close()
	}
}

// mcpLine is a laptop message as one stdio line for the agent: the frame
// and a newline. MCP's stdio framing is one message per line, so a frame
// with a raw newline would reach the agent as two messages; such a frame
// has its whitespace between tokens removed (json.Compact, which changes
// no token), and a frame that still is not one line (a newline inside a
// string is not valid JSON) is refused.
func mcpLine(frame []byte) ([]byte, bool) {
	if bytes.ContainsAny(frame, "\r\n") {
		var c bytes.Buffer
		if err := json.Compact(&c, frame); err != nil {
			return nil, false
		}
		frame = c.Bytes()
	}
	if len(bytes.TrimSpace(frame)) == 0 {
		return nil, false
	}
	out := make([]byte, 0, len(frame)+1)
	return append(append(out, frame...), '\n'), true
}

// accept serves one shim at a time: a second client while one is connected
// is closed at once.
func (b *mcpBridge) accept() {
	for {
		c, err := b.ln.Accept()
		if err != nil {
			return
		}
		b.mu.Lock()
		if b.shim != nil || b.ended {
			b.mu.Unlock()
			_ = c.Close()
			continue
		}
		b.shim = c
		b.mu.Unlock()
		if b.control(MCPControl{Type: "open"}) != nil {
			b.dropShim()
			continue
		}
		go b.fromShim(c)
	}
}

// fromShim sends each line the agent writes as one binary message, byte
// for byte without its newline. A line over mcpReadLimit is dropped.
func (b *mcpBridge) fromShim(c net.Conn) {
	r := bufio.NewReaderSize(c, 64<<10)
	for {
		line, err := readMCPLine(r, mcpReadLimit)
		if len(line) > 0 {
			if werr := b.write(websocket.BinaryMessage, line); werr != nil {
				break
			}
		}
		if errors.Is(err, errMCPLineTooLong) {
			b.log.Warn("relay.mcp_frame_dropped", "name", b.name, "reason", "line too long")
			continue
		}
		if err != nil {
			break
		}
	}
	b.mu.Lock()
	mine := b.shim == c
	if mine {
		b.shim = nil
	}
	b.mu.Unlock()
	_ = c.Close()
	if mine {
		_ = b.control(MCPControl{Type: "close"})
	}
}

func (b *mcpBridge) dropShim() {
	b.mu.Lock()
	shim := b.shim
	b.mu.Unlock()
	if shim != nil {
		_ = shim.Close() // fromShim sends close
	}
}

var errMCPLineTooLong = errors.New("relay: MCP line too long")

// readMCPLine reads one line without its "\n" (and a "\r" before it). A
// line over max is drained to its end and errMCPLineTooLong returned.
func readMCPLine(r *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	over := false
	for {
		chunk, err := r.ReadSlice('\n')
		if !over {
			if len(line)+len(chunk) > max+1 {
				over, line = true, nil
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if over {
			if err == nil {
				return nil, errMCPLineTooLong
			}
			return nil, err
		}
		line = bytes.TrimSuffix(line, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		return line, err
	}
}

// MCPStdio is the agent side of a bridge (`defenseclaw-actor-relay
// mcp-stdio NAME`): the agent starts it as a stdio MCP server, and it
// copies stdin to the socket and the socket to stdout unchanged.
func MCPStdio(name string, stdin io.Reader, stdout, stderr io.Writer) int {
	if !MCPNameRE.MatchString(name) {
		fmt.Fprintf(stderr, "defenseclaw-actor-relay mcp-stdio: %q is not an MCP server name\n", name)
		return 2
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, "defenseclaw-actor-relay mcp-stdio:", err)
		return 1
	}
	c, err := net.Dial("unix", mcpSocketPath(home, name))
	if err != nil {
		fmt.Fprintf(stderr, "the laptop MCP server %s is not bridged right now\n", name)
		return 1
	}
	defer c.Close()
	// Stdin ends: half-close, and the relay ends the connection. The
	// relay ends it: the shim exits, whatever stdin does.
	go func() {
		_, _ = io.Copy(c, stdin)
		if uc, ok := c.(*net.UnixConn); ok {
			_ = uc.CloseWrite()
		}
	}()
	_, _ = io.Copy(stdout, c)
	return 0
}
