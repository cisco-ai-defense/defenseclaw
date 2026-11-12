// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

const (
	pollWait     = 25 * time.Second
	pollIdle     = 60 * time.Second
	wsPing       = 20 * time.Second
	warmBudget   = 2 * time.Second
	exitInterval = time.Second
)

// Options configure a Server.
type Options struct {
	Config   kit.Config
	Verifier Verifier
	Log      *slog.Logger
	// Warm pre-connects the hook helper for the connector (kit.Warm).
	Warm func(ctx context.Context, connector string) error
	// SetUnattended marks the actor's hooks unattended (kit.SetUnattended).
	SetUnattended func(ctx context.Context) error
	// TmuxDir is where the tmux socket lives (default kit.HelperDir()).
	TmuxDir string
}

// Server is the relay. NewServer has no side effect: the golden snapshot of
// a template holds a relay that has only bound its port. Everything else
// (directories, the tmux session, the hook helper, session IDs) starts on
// the first authenticated request after a resume (E5).
type Server struct {
	opts Options
	log  *slog.Logger

	initOnce sync.Once
	initErr  error
	tmux     *Tmux
	session  string

	mu    sync.Mutex
	polls map[string]*pollAttachment
	tasks map[string]*task
	// lastWarm is how long the last pre-connect took (E6 measurements).
	lastWarm time.Duration
}

// NewServer builds a relay.
func NewServer(opts Options) *Server {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if opts.Warm == nil {
		opts.Warm = func(ctx context.Context, c string) error { return kit.Warm(ctx, c, warmBudget) }
	}
	if opts.SetUnattended == nil {
		opts.SetUnattended = func(ctx context.Context) error { return kit.SetUnattended(ctx, warmBudget) }
	}
	return &Server{opts: opts, log: log, polls: map[string]*pollAttachment{}, tasks: map[string]*task{}}
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func (s *Server) init() error {
	s.initOnce.Do(func() {
		dir := s.opts.TmuxDir
		if dir == "" {
			dir = kit.HelperDir()
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			s.initErr = err
			return
		}
		rc := s.opts.Config.Relay
		env := os.Environ()
		for k, v := range rc.Env {
			env = append(env, k+"="+v)
		}
		s.tmux = &Tmux{Bin: rc.Tmux, Socket: filepath.Join(dir, "tmux.sock"), Name: "dc",
			Workdir: rc.Workdir, Argv: rc.Interactive, Env: env, Status: filepath.Join(dir, "agent.exit")}
		s.session = newID()
		go s.watchResume()
	})
	return s.initErr
}

// watchResume re-warms the hook helper and recovers the tmux socket after a
// resume (a wall-clock jump).
func (s *Server) watchResume() {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := time.Now().Round(0)
	for range tick.C {
		now := time.Now().Round(0)
		gap := now.Sub(last)
		last = now
		if gap < 3*time.Second {
			continue
		}
		s.log.Info("relay.resume", "gap_ms", gap.Milliseconds())
		s.tmux.RecoverSocket()
		s.preconnect(context.Background())
	}
}

// preconnect makes sure the hook helper runs and holds a connection to the
// gateway before the agent gets input (E6). A failure is logged: the hooks
// then follow their fail mode.
func (s *Server) preconnect(ctx context.Context) time.Duration {
	c := s.opts.Config.Relay.Connector
	if c == "" {
		return 0
	}
	start := time.Now()
	ctx, cancel := context.WithTimeout(ctx, warmBudget)
	defer cancel()
	err := s.opts.Warm(ctx, c)
	d := time.Since(start)
	s.mu.Lock()
	s.lastWarm = d
	s.mu.Unlock()
	if err != nil {
		s.log.Warn("relay.preconnect", "connector", c, "ms", d.Milliseconds(), "error", err.Error())
	} else {
		s.log.Info("relay.preconnect", "connector", c, "ms", d.Milliseconds())
	}
	return d
}

// Handler is the relay's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// The wake-up probe of the actor template: no authentication, no state,
	// nothing started.
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("GET /dcrelay/1/ws", s.serveWS)
	mux.HandleFunc("POST /dcrelay/1/poll", s.pollOpen)
	mux.HandleFunc("GET /dcrelay/1/poll/{id}", s.pollRead)
	mux.HandleFunc("POST /dcrelay/1/poll/{id}", s.pollWrite)
	mux.HandleFunc("DELETE /dcrelay/1/poll/{id}", s.pollClose)
	mux.HandleFunc("POST /dcrelay/1/task", s.taskStart)
	mux.HandleFunc("GET /dcrelay/1/task/{id}", s.taskFollow)
	mux.HandleFunc("GET /dcrelay/1/status", s.status)
	return mux
}

// auth verifies the request's session token and audits the outcome.
func (s *Server) auth(w http.ResponseWriter, r *http.Request, what string) (Session, bool) {
	if s.opts.Verifier == nil {
		s.log.Warn("relay.refused", "what", what, "reason", "no session verifier configured")
		http.Error(w, "relay: no session verifier is configured", http.StatusServiceUnavailable)
		return Session{}, false
	}
	sess, err := s.opts.Verifier.Verify(r.Context(), r)
	if err != nil {
		s.log.Warn("relay.refused", "what", what, "reason", err.Error())
		http.Error(w, "relay: "+err.Error(), http.StatusUnauthorized)
		return Session{}, false
	}
	if err := s.init(); err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	s.log.Info("relay.accepted", "what", what, "person", sess.Person, "actor", sess.Actor, "actor_uid", sess.ActorUID, "jti", sess.TokenID)
	return sess, true
}

func termSize(r *http.Request) (uint16, uint16) {
	cols, rows := uint16(80), uint16(24)
	if n, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && n > 0 && n <= 1000 {
		cols = uint16(n)
	}
	if n, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && n > 0 && n <= 1000 {
		rows = uint16(n)
	}
	return cols, rows
}

// attachment is one tmux client on a PTY.
type attachment struct {
	pty  *os.File
	cmd  *exec.Cmd
	once sync.Once
	done chan struct{}
}

func (a *attachment) close() {
	a.once.Do(func() {
		if a.cmd.Process != nil {
			_ = a.cmd.Process.Kill()
		}
		a.pty.Close()
		_ = a.cmd.Wait()
		close(a.done)
	})
}

// open pre-connects the hook helper, starts the agent's session if needed
// and attaches a tmux client to it.
func (s *Server) open(ctx context.Context, cols, rows uint16) (*attachment, error) {
	s.preconnect(ctx)
	if _, err := s.tmux.Ensure(ctx, cols, rows); err != nil {
		return nil, err
	}
	cmd := s.tmux.AttachCmd()
	p, err := startPTY(cmd, cols, rows)
	if err != nil {
		return nil, err
	}
	return &attachment{pty: p, cmd: cmd, done: make(chan struct{})}, nil
}

// watchExit sends the agent's exit status once its pane dies, and ends the
// session so the next attachment starts the agent again.
func (s *Server) watchExit(a *attachment, send func(Control)) {
	t := time.NewTicker(exitInterval)
	defer t.Stop()
	for {
		select {
		case <-a.done:
			return
		case <-t.C:
		}
		if code, dead := s.tmux.PaneExit(context.Background()); dead {
			send(Control{Type: CtlExit, Code: &code})
			s.tmux.Kill(context.Background())
			a.close()
			return
		}
	}
}

// input applies one client frame to an attachment. It reports false when
// the client detached.
func input(a *attachment, frame []byte, send func(Control)) bool {
	t, p, err := Decode(frame)
	if err != nil {
		send(Control{Type: CtlError, Message: err.Error()})
		return true
	}
	switch t {
	case FrameData:
		_, _ = a.pty.Write(p)
	case FrameResize:
		if rs, err := DecodeResize(p); err == nil {
			_ = setSize(a.pty, rs.Cols, rs.Rows)
		} else {
			send(Control{Type: CtlError, Message: err.Error()})
		}
	case FrameControl:
		c, err := DecodeControl(p)
		if err != nil {
			send(Control{Type: CtlError, Message: err.Error()})
			return true
		}
		switch c.Type {
		case CtlDetach:
			return false
		case CtlPing:
			send(Control{Type: CtlPong})
		}
	}
	return true
}

func (s *Server) hello() Control {
	mode := kit.ModeInteract
	return Control{Type: CtlHello, Version: Version, Session: s.session, Mode: mode}
}

var upgrader = websocket.Upgrader{
	// Only the protocol name is ever echoed, never the token subprotocol.
	Subprotocols:    []string{Subprotocol},
	ReadBufferSize:  32 << 10,
	WriteBufferSize: 32 << 10,
	// Authentication is a bearer token, never a cookie, so a cross-origin
	// page gains nothing from an Origin it controls.
	CheckOrigin: func(*http.Request) bool { return true },
}

func (s *Server) serveWS(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r, "ws"); !ok {
		return
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()
	conn.SetReadLimit(MaxFrame + 1)
	var wmu sync.Mutex
	write := func(frame []byte) error {
		wmu.Lock()
		defer wmu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		return conn.WriteMessage(websocket.BinaryMessage, frame)
	}
	send := func(c Control) { _ = write(EncodeControl(c)) }
	cols, rows := termSize(r)
	a, err := s.open(r.Context(), cols, rows)
	if err != nil {
		send(Control{Type: CtlError, Message: err.Error()})
		return
	}
	defer a.close()
	send(s.hello())
	go s.watchExit(a, send)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := a.pty.Read(buf)
			if n > 0 {
				if write(Encode(FrameData, buf[:n])) != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		a.close()
		wmu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "agent detached"), time.Now().Add(time.Second))
		wmu.Unlock()
		conn.Close()
	}()
	go func() {
		t := time.NewTicker(wsPing)
		defer t.Stop()
		for {
			select {
			case <-a.done:
				return
			case <-t.C:
				wmu.Lock()
				err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(5*time.Second))
				wmu.Unlock()
				if err != nil {
					return
				}
			}
		}
	}()
	for {
		mt, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		if !input(a, msg, send) {
			return
		}
	}
}

// pollAttachment is an attachment served over long-poll.
type pollAttachment struct {
	*attachment
	id       string
	person   string
	out      *ring
	mu       sync.Mutex
	lastSeen time.Time
}

func (p *pollAttachment) touch() {
	p.mu.Lock()
	p.lastSeen = time.Now()
	p.mu.Unlock()
}

func (s *Server) pollOpen(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll")
	if !ok {
		return
	}
	cols, rows := termSize(r)
	a, err := s.open(context.Background(), cols, rows)
	if err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p := &pollAttachment{attachment: a, id: newID(), person: sess.Person, out: newRing(s.opts.Config.Relay.OutputBufferBytes), lastSeen: time.Now()}
	p.out.Append(EncodeControl(s.hello()))
	s.mu.Lock()
	s.polls[p.id] = p
	s.mu.Unlock()
	send := func(c Control) { p.out.Append(EncodeControl(c)) }
	go s.watchExit(a, send)
	go func() {
		buf := make([]byte, 32<<10)
		for {
			n, err := a.pty.Read(buf)
			if n > 0 {
				p.out.Append(Encode(FrameData, buf[:n]))
			}
			if err != nil {
				break
			}
		}
		a.close()
		p.out.Close()
	}()
	go s.reapPoll(p)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": p.id, "cursor": 0, "version": Version})
}

func (s *Server) reapPoll(p *pollAttachment) {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-p.done:
		case <-t.C:
			p.mu.Lock()
			idle := time.Since(p.lastSeen)
			p.mu.Unlock()
			if idle < pollIdle {
				continue
			}
			p.close()
		}
		s.mu.Lock()
		delete(s.polls, p.id)
		s.mu.Unlock()
		return
	}
}

func (s *Server) pollFor(w http.ResponseWriter, r *http.Request, sess Session) *pollAttachment {
	s.mu.Lock()
	p := s.polls[r.PathValue("id")]
	s.mu.Unlock()
	if p == nil || p.person != sess.Person {
		// Another person's attachment is as absent as a closed one.
		http.Error(w, "relay: no such attachment", http.StatusNotFound)
		return nil
	}
	p.touch()
	return p
}

func (s *Server) pollRead(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll-read")
	if !ok {
		return
	}
	p := s.pollFor(w, r, sess)
	if p == nil {
		return
	}
	cursor, _ := strconv.ParseUint(r.URL.Query().Get("cursor"), 10, 64)
	ctx, cancel := context.WithTimeout(r.Context(), pollWait)
	defer cancel()
	data, next, reset, closed := p.out.Read(ctx, cursor)
	p.touch()
	var body []byte
	if reset {
		body = AppendStream(body, EncodeControl(Control{Type: CtlReset}))
	}
	body = append(body, data...)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Dcrelay-Cursor", strconv.FormatUint(next, 10))
	if closed && len(data) == 0 {
		w.WriteHeader(http.StatusGone)
		return
	}
	_, _ = w.Write(body)
}

func (s *Server) pollWrite(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll-write")
	if !ok {
		return
	}
	p := s.pollFor(w, r, sess)
	if p == nil {
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 4*MaxFrame))
	if err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusBadRequest)
		return
	}
	frames, err := SplitStream(raw)
	if err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusBadRequest)
		return
	}
	send := func(c Control) { p.out.Append(EncodeControl(c)) }
	for _, f := range frames {
		if !input(p.attachment, f, send) {
			p.close()
			break
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pollClose(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll-close")
	if !ok {
		return
	}
	if p := s.pollFor(w, r, sess); p != nil {
		p.close()
		w.WriteHeader(http.StatusNoContent)
	}
}

// status reports what a launcher's `status` shows: the session, whether
// the agent runs, the last pre-connect time and the tasks.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r, "status"); !ok {
		return
	}
	s.mu.Lock()
	tasks := map[string]any{}
	for id, t := range s.tasks {
		tasks[id] = t.summary()
	}
	warm := s.lastWarm
	s.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"version": Version, "session": s.session, "agent_running": s.tmux.Alive(r.Context()),
		"last_preconnect_ms": float64(warm.Microseconds()) / 1000, "tasks": tasks,
	})
}

// ErrTaskRunning means a task is already running in this actor.
var ErrTaskRunning = errors.New("a task is already running in this actor")

func expandHeadless(argv []string, prompt string) ([]string, error) {
	if len(argv) == 0 {
		return nil, errors.New("this connector has no headless mode: run it interactively")
	}
	out := make([]string, 0, len(argv))
	used := false
	for _, a := range argv {
		if a == "{prompt}" {
			out = append(out, prompt)
			used = true
			continue
		}
		out = append(out, a)
	}
	if !used {
		return nil, fmt.Errorf("the headless command %q has no {prompt}", strings.Join(argv, " "))
	}
	return out, nil
}
