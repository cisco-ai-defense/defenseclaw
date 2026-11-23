// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

const (
	// MCPLineMax is the longest JSON-RPC line the launcher carries from a
	// laptop server (1 MiB). A longer line is dropped with one warning; the
	// gateway's own limit (mcp_bridge.message_max_bytes) applies as well.
	MCPLineMax = 1 << 20
	// mcpReadLimit is the largest frame read from the stream.
	mcpReadLimit = 4 << 20
	// mcpKillGrace is how long a child has after SIGTERM before SIGKILL.
	mcpKillGrace = 5 * time.Second
	// mcpStdinQueue is how many frames wait for a child that is slow to
	// read its input before the child is judged stuck.
	mcpStdinQueue = 256
	// mcpDrainGrace bounds how long output a child left in its pipes is read
	// after the child ended (a grandchild may hold the pipe open).
	mcpDrainGrace = 2 * time.Second
)

// MCPRefusal is an MCP stream the gateway refused on open: its HTTP status
// and reason code (the code is also in the audit row).
type MCPRefusal struct {
	Status int
	Reason string
	Name   string
	Target Target
}

func (e *MCPRefusal) Error() string {
	for _, m := range MCPMessages {
		if m.Code == e.Reason && m.Where == "gateway" {
			return MCPLine(e.Reason, e.Name)
		}
	}
	return routeError(e.Status, nil, e.Target).Error()
}

// Unwrap returns the attach error kind of the status (ErrNotSignedIn, ...).
func (e *MCPRefusal) Unwrap() error { return routeError(e.Status, nil, e.Target).Kind }

// Transient reports a refusal a short wait can cure: the agent's relay is
// not up yet.
func (e *MCPRefusal) Transient() bool {
	if e.Reason == "relay_unreachable" {
		return true
	}
	if e.Reason != "" {
		return false
	}
	switch e.Status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// DialMCP opens the stream of one MCP server through the gateway.
func (tu *Tunnel) DialMCP(ctx context.Context, name string) (*websocket.Conn, error) {
	conn, ref, err := tu.dialStream(ctx, relay.RouteMCP+"/"+name)
	if ref != nil {
		return nil, &MCPRefusal{Status: ref.Status, Reason: ref.Reason, Name: name, Target: tu.target}
	}
	return conn, err
}

// MCPStreamError is a control message that ends the stream: the agent's
// relay says why (mcp_busy: another launcher bridges this NAME).
type MCPStreamError struct{ Code string }

func (e *MCPStreamError) Error() string {
	if l := MCPLine(e.Code, "NAME"); l != "" {
		return l
	}
	return "the agent's relay ended the stream: " + safetext.Line(e.Code)
}

// MCPServe is one bridged server on an open stream.
type MCPServe struct {
	Spec MCPSpec
	// Note shows a line on the person's terminal, already prefixed
	// "[mcp NAME] ". It must be safe for concurrent use.
	Note func(string)
	// OnChild is called with the PID of every process started and returns
	// the function that removes its record once it ends (launcherpresence).
	OnChild func(pid int) (remove func())
	// KillGrace is how long a child has after SIGTERM (default 5 s).
	KillGrace time.Duration
	// MaxLine is the longest line carried from the child (default MCPLineMax).
	MaxLine int
}

type mcpChild struct {
	proc   *mcpProc
	in     chan []byte
	done   chan struct{} // closed once the child and its readers are gone
	killed atomic.Bool
}

type mcpSession struct {
	o    MCPServe
	conn *websocket.Conn
	wmu  sync.Mutex
	mu   sync.Mutex
	cur  *mcpChild
	lim  mcpLimiter
}

// ServeMCP carries one MCP server over conn until the stream ends or ctx
// ends. It starts the command on the relay's open message (a fresh process
// each time), sends each line the command prints as one binary frame, writes
// each binary frame to the command as one line, and kills the command on the
// relay's close message. It writes no ping and no data of its own besides
// the error control message. Every child is gone when it returns. It returns
// nil when the stream ends and a *MCPStreamError when the relay ends it.
func ServeMCP(ctx context.Context, conn *websocket.Conn, o MCPServe) error {
	if o.KillGrace <= 0 {
		o.KillGrace = mcpKillGrace
	}
	if o.MaxLine <= 0 {
		o.MaxLine = MCPLineMax
	}
	if o.Note == nil {
		o.Note = func(string) {}
	}
	s := &mcpSession{o: o, conn: conn, lim: newMCPLimiter(time.Now)}
	conn.SetReadLimit(mcpReadLimit)
	// Idle close counts bytes: a pong would be a byte, and the launcher
	// sends no ping of its own.
	conn.SetPingHandler(func(string) error { return nil })
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	defer func() {
		s.stopCurrent()
		_ = conn.Close()
	}()
	for {
		kind, rd, err := conn.NextReader()
		if err != nil {
			// The stream ended (the shim side, the gateway, the network or
			// ctx): there is nothing more to serve.
			return nil
		}
		if kind == websocket.BinaryMessage {
			b, err := io.ReadAll(rd)
			if err != nil {
				return nil
			}
			s.toChild(b)
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rd, 512))
		var m struct {
			Type string `json:"type"`
			Code string `json:"code"`
		}
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		switch m.Type {
		case "open":
			s.open()
		case "close":
			s.stopCurrent()
		case "error":
			return &MCPStreamError{Code: m.Code}
		}
	}
}

func (s *mcpSession) note(line string) {
	s.o.Note("[mcp " + s.o.Spec.Name + "] " + line)
}

func (s *mcpSession) write(kind int, b []byte) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_ = s.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	return s.conn.WriteMessage(kind, b)
}

// sendError tells the relay the command failed, so it closes the shim.
func (s *mcpSession) sendError(code string) {
	b, _ := json.Marshal(map[string]string{"type": "error", "code": code})
	_ = s.write(websocket.TextMessage, b)
}

func (s *mcpSession) current() *mcpChild {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cur
}

// open starts a fresh child; one that still runs is killed first.
func (s *mcpSession) open() {
	s.stopCurrent()
	argv := s.o.Spec.Argv
	cmd := exec.Command(argv[0], argv[1:]...)
	inR, inW, err1 := os.Pipe()
	outR, outW, err2 := os.Pipe()
	errR, errW, err3 := os.Pipe()
	if err := errors.Join(err1, err2, err3); err != nil {
		for _, f := range []*os.File{inR, inW, outR, outW, errR, errW} {
			if f != nil {
				_ = f.Close()
			}
		}
		s.note("could not start: " + safetext.Line(err.Error()))
		s.sendError("mcp_command_failed")
		return
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW
	proc, err := startMCP(cmd)
	// The child holds its ends now; ours of those must close either way, or
	// the pipes never report the end.
	_ = inR.Close()
	_ = outW.Close()
	_ = errW.Close()
	if err != nil {
		_ = inW.Close()
		_ = outR.Close()
		_ = errR.Close()
		s.note("could not start: " + safetext.Line(err.Error()))
		s.sendError("mcp_command_failed")
		return
	}
	c := &mcpChild{proc: proc, in: make(chan []byte, mcpStdinQueue), done: make(chan struct{})}
	s.mu.Lock()
	s.cur = c
	s.mu.Unlock()
	remove := func() {}
	if s.o.OnChild != nil {
		if r := s.o.OnChild(cmd.Process.Pid); r != nil {
			remove = r
		}
	}
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); s.pumpStdout(c, outR) }()
	go func() { defer readers.Done(); s.pumpStderr(errR) }()
	go s.pumpStdin(c, inW)
	go func() {
		werr := cmd.Wait()
		// Windows: end what the command left running (its job), so the
		// pipes close and the record goes only with the whole tree.
		proc.release()
		drained := make(chan struct{})
		go func() { readers.Wait(); close(drained) }()
		select {
		case <-drained:
		case <-time.After(mcpDrainGrace):
			_ = outR.Close()
			_ = errR.Close()
			<-drained
		}
		_ = inW.Close()
		_ = outR.Close()
		_ = errR.Close()
		remove()
		close(c.done)
		if c.killed.Load() {
			return
		}
		s.mu.Lock()
		if s.cur == c {
			s.cur = nil
		}
		s.mu.Unlock()
		s.note("the command ended" + exitText(werr))
		s.sendError("mcp_command_failed")
	}()
}

func exitText(err error) string {
	var ee *exec.ExitError
	switch {
	case err == nil:
		return ""
	case errors.As(err, &ee):
		return " (" + safetext.Line(ee.Error()) + ")"
	}
	return " (" + safetext.Line(err.Error()) + ")"
}

// stopCurrent kills the running child, if any, and waits until it is gone.
func (s *mcpSession) stopCurrent() {
	s.mu.Lock()
	c := s.cur
	s.cur = nil
	s.mu.Unlock()
	if c != nil {
		s.kill(c)
	}
}

// kill ends c: SIGTERM, then SIGKILL after the grace (Windows: the job at
// once), and waits until it and its readers are gone.
func (s *mcpSession) kill(c *mcpChild) {
	c.killed.Store(true)
	c.proc.terminate()
	select {
	case <-c.done:
		return
	case <-time.After(s.o.KillGrace):
	}
	c.proc.kill()
	<-c.done
}

// pumpStdout turns the child's lines into binary frames.
func (s *mcpSession) pumpStdout(c *mcpChild, r io.Reader) {
	br := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	over := false
	for {
		chunk, err := br.ReadSlice('\n')
		switch {
		case !over && len(line)+len(chunk) > s.o.MaxLine+1:
			over = true
			line = line[:0]
		case !over:
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err == nil || len(line) > 0 || over {
			if over {
				s.note("dropped one line longer than " + strconv.Itoa(s.o.MaxLine) + " bytes")
			} else if msg := bytes.TrimSpace(line); len(msg) > 0 && s.current() == c && !c.killed.Load() {
				if s.write(websocket.BinaryMessage, msg) != nil {
					return
				}
			}
			line, over = line[:0], false
		}
		if err != nil {
			return
		}
	}
}

// pumpStderr shows the child's stderr, rate-limited. It is local to this
// computer and is not audited.
func (s *mcpSession) pumpStderr(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4<<10), 64<<10)
	for sc.Scan() {
		line := safetext.Line(sc.Text())
		if line == "" {
			continue
		}
		if len(line) > 500 {
			line = line[:500] + "…"
		}
		ok, skipped := s.lim.allow()
		if !ok {
			continue
		}
		if skipped > 0 {
			s.note(fmt.Sprintf("%d stderr lines skipped", skipped))
		}
		s.note(line)
	}
	// A line too long for the scanner ends the scan: keep draining so the
	// child never blocks on a full pipe.
	_, _ = io.Copy(io.Discard, r)
}

// pumpStdin writes queued frames to the child, one line each.
func (s *mcpSession) pumpStdin(c *mcpChild, w io.WriteCloser) {
	for {
		select {
		case b := <-c.in:
			if _, err := w.Write(b); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

// toChild hands one binary frame to the child as a line. With no child the
// frame is dropped (the shim is not connected).
func (s *mcpSession) toChild(b []byte) {
	c := s.current()
	if c == nil {
		return
	}
	if bytes.IndexByte(b, '\n') >= 0 {
		var buf bytes.Buffer
		if json.Compact(&buf, b) != nil {
			return
		}
		b = buf.Bytes()
	}
	line := make([]byte, 0, len(b)+1)
	line = append(append(line, b...), '\n')
	select {
	case c.in <- line:
	default:
		// The child reads nothing: it is stuck, so end it.
		s.note("the command does not read its input; stopping it")
		go func() {
			s.mu.Lock()
			own := s.cur == c
			if own {
				s.cur = nil
			}
			s.mu.Unlock()
			if own {
				s.kill(c)
				s.sendError("mcp_command_failed")
			}
		}()
	}
}

// mcpLimiter lets a burst of stderr lines through and then a few a second.
type mcpLimiter struct {
	mu      sync.Mutex
	now     func() time.Time
	tokens  float64
	last    time.Time
	skipped int
}

const (
	mcpStderrBurst = 20
	mcpStderrRate  = 5.0 // lines per second
)

func newMCPLimiter(now func() time.Time) mcpLimiter {
	return mcpLimiter{now: now, tokens: mcpStderrBurst, last: now()}
}

// allow reports whether a line may be shown, and how many lines were
// skipped since the last one shown.
func (l *mcpLimiter) allow() (ok bool, skipped int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	t := l.now()
	l.tokens += t.Sub(l.last).Seconds() * mcpStderrRate
	if l.tokens > mcpStderrBurst {
		l.tokens = mcpStderrBurst
	}
	l.last = t
	if l.tokens < 1 {
		l.skipped++
		return false, 0
	}
	l.tokens--
	skipped, l.skipped = l.skipped, 0
	return true, skipped
}

// MCPBridgeOptions starts the bridges of one run or connect.
type MCPBridgeOptions struct {
	Tunnel *Tunnel
	Specs  []MCPSpec
	// Note shows a line on the person's terminal (safe for concurrent use).
	Note func(string)
	// OnChild is MCPServe.OnChild with the server's name.
	OnChild func(name string, pid int) (remove func())
	// Wait is how long a stream refused only because the agent's relay is
	// not up yet is retried (0: no retry).
	Wait time.Duration
	// Sleep waits between tries (default: a timer that ctx can cut short).
	Sleep func(ctx context.Context, d time.Duration) error
	// KillGrace is passed to every ServeMCP.
	KillGrace time.Duration
}

// MCPBridges are the open streams of one launcher.
type MCPBridges struct {
	// Opened and Refused count the servers by how the open went.
	Opened, Refused int
	cancel          context.CancelFunc
	wg              sync.WaitGroup
}

// StartMCPBridges opens every server's stream, one after the other, and
// serves each on its own goroutine. A refused stream prints its line and the
// others go on. Close ends them all and kills every child.
func StartMCPBridges(ctx context.Context, o MCPBridgeOptions) *MCPBridges {
	ctx, cancel := context.WithCancel(ctx)
	b := &MCPBridges{cancel: cancel}
	if o.Note == nil {
		o.Note = func(string) {}
	}
	if o.Sleep == nil {
		o.Sleep = sleepCtx
	}
	for _, spec := range o.Specs {
		conn, err := dialMCPWithWait(ctx, o, spec.Name)
		if err != nil {
			b.Refused++
			if ctx.Err() == nil {
				o.Note("[mcp " + spec.Name + "] " + mcpRefusalText(err))
			}
			continue
		}
		b.Opened++
		serve := MCPServe{Spec: spec, Note: o.Note, KillGrace: o.KillGrace}
		if o.OnChild != nil {
			serve.OnChild = func(pid int) func() { return o.OnChild(spec.Name, pid) }
		}
		b.wg.Add(1)
		go func() {
			defer b.wg.Done()
			err := ServeMCP(ctx, conn, serve)
			if ctx.Err() != nil {
				return
			}
			line := "the bridge ended. Run the command again to bring it back."
			var se *MCPStreamError
			if errors.As(err, &se) {
				line = strings.ReplaceAll(se.Error(), "NAME", spec.Name)
			}
			o.Note("[mcp " + spec.Name + "] " + line)
		}()
	}
	return b
}

// Close ends every stream and returns once every child is gone.
func (b *MCPBridges) Close() {
	b.cancel()
	b.wg.Wait()
}

func mcpRefusalText(err error) string {
	var ref *MCPRefusal
	if errors.As(err, &ref) {
		return ref.Error()
	}
	return safetext.Line(err.Error())
}

func dialMCPWithWait(ctx context.Context, o MCPBridgeOptions, name string) (*websocket.Conn, error) {
	deadline := time.Now().Add(o.Wait)
	delay := 500 * time.Millisecond
	for {
		conn, err := o.Tunnel.DialMCP(ctx, name)
		var ref *MCPRefusal
		if err == nil || !errors.As(err, &ref) || !ref.Transient() || time.Now().Add(delay).After(deadline) {
			return conn, err
		}
		if o.Sleep(ctx, delay) != nil {
			return nil, ctx.Err()
		}
		if delay < 4*time.Second {
			delay *= 2
		}
	}
}
