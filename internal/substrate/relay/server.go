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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

const (
	pollWait   = 25 * time.Second
	pollIdle   = 60 * time.Second
	wsPing     = 20 * time.Second
	warmBudget = 2 * time.Second
	// maxPollsPerPerson and maxPolls cap open long-poll attachments
	// (GAP-0074): each holds an output ring.
	maxPollsPerPerson = 4
	maxPolls          = 16
)

// Options configure a Server.
type Options struct {
	Config   kit.Config
	Verifier Verifier
	Log      *slog.Logger
	// Warm makes one request to the gateway so the egress path is ready
	// before the agent gets input (E6); default kit.Transport.Warm.
	Warm func(ctx context.Context, connector string) error
	Now  func() time.Time
}

// Server is the relay. NewServer has no side effect: the golden snapshot of
// a template holds a relay that has only bound its port. Everything else
// (the agent, session IDs) starts on the first authenticated request after
// a resume (E5).
type Server struct {
	opts Options
	log  *slog.Logger

	initOnce sync.Once
	initErr  error
	agent    *Agent
	session  string

	mu    sync.Mutex
	polls map[string]*pollAttachment
	tasks map[string]*task
	// used are the session token IDs that opened an attachment or a task,
	// with their expiry: a token opens one (GAP-0070).
	used map[string]time.Time
	// lastWarm is how long the last pre-connect took (E6 measurements).
	lastWarm time.Duration
}

// NewServer builds a relay.
func NewServer(opts Options) *Server {
	log := opts.Log
	if log == nil {
		log = slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Server{opts: opts, log: log, polls: map[string]*pollAttachment{}, tasks: map[string]*task{}, used: map[string]time.Time{}}
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
		rc := s.opts.Config.Relay
		env := os.Environ()
		for k, v := range rc.Env {
			env = append(env, k+"="+v)
		}
		s.agent = &Agent{Argv: rc.Interactive, Dir: rc.Workdir, Env: env}
		if s.opts.Warm == nil {
			t, err := kit.NewTransport(s.opts.Config)
			if err != nil {
				s.initErr = err
				return
			}
			s.opts.Warm = t.Warm
		}
		s.session = newID()
		go s.watchResume()
	})
	return s.initErr
}

// watchResume pre-connects after a resume (a wall-clock jump), before the
// agent's next hook.
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
		s.preconnect(context.Background())
	}
}

// preconnect makes one request to the gateway so the actor's egress path to
// it is ready before the agent gets input (E6). A failure is logged: the
// hooks then follow their fail mode.
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

// auth verifies the request's session token and audits the outcome. With
// open set the token opens something (an attachment or a task) and may do
// so once.
func (s *Server) auth(w http.ResponseWriter, r *http.Request, what string, open bool) (Session, bool) {
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
	if open {
		if err := s.useToken(sess); err != nil {
			s.log.Warn("relay.refused", "what", what, "reason", err.Error(), "person", sess.Person, "jti", sess.TokenID)
			http.Error(w, "relay: "+err.Error(), http.StatusUnauthorized)
			return Session{}, false
		}
	}
	if err := s.init(); err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusInternalServerError)
		return Session{}, false
	}
	s.log.Info("relay.accepted", "what", what, "person", sess.Person, "actor", sess.Actor, "actor_uid", sess.ActorUID, "jti", sess.TokenID)
	return sess, true
}

// useToken records that sess's token opened something; a token opens one.
func (s *Server) useToken(sess Session) error {
	if sess.TokenID == "" {
		return errors.New("session token has no jti")
	}
	now := s.opts.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, exp := range s.used {
		if now.After(exp.Add(2 * time.Minute)) {
			delete(s.used, id)
		}
	}
	if _, seen := s.used[sess.TokenID]; seen {
		return errors.New("session token already used: the launcher asks for a new one")
	}
	s.used[sess.TokenID] = sess.Expires
	return nil
}

// untilExpiry is how long sess may stay attached.
func (s *Server) untilExpiry(sess Session) time.Duration {
	if sess.Expires.IsZero() {
		return time.Hour
	}
	return sess.Expires.Sub(s.opts.Now())
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

// open pre-connects, starts the agent if needed and attaches to it.
func (s *Server) open(ctx context.Context, cols, rows uint16) (*Attachment, error) {
	s.preconnect(ctx)
	return s.agent.Attach(cols, rows)
}

// input applies one client frame to an attachment. It reports false when
// the client detached.
func input(a *Attachment, frame []byte, send func(Control)) bool {
	t, p, err := Decode(frame)
	if err != nil {
		send(Control{Type: CtlError, Message: err.Error()})
		return true
	}
	switch t {
	case FrameData:
		_, _ = a.Write(p)
	case FrameResize:
		if rs, err := DecodeResize(p); err == nil {
			a.Resize(rs.Cols, rs.Rows)
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
	return Control{Type: CtlHello, Version: Version, Session: s.session, Mode: kit.ModeInteract}
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
	sess, ok := s.auth(w, r, "ws", true)
	if !ok {
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
	defer a.Close()
	send(s.hello())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ev := range a.Events {
			if ev.exit != nil {
				send(Control{Type: CtlExit, Code: ev.exit})
				continue
			}
			if write(Encode(FrameData, ev.data)) != nil {
				break
			}
		}
		wmu.Lock()
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "agent detached"), time.Now().Add(time.Second))
		wmu.Unlock()
		conn.Close()
	}()
	// The attachment ends with its token (GAP-0070); the launcher
	// reconnects with a new one.
	expiry := time.AfterFunc(s.untilExpiry(sess), func() {
		send(Control{Type: CtlError, Message: "session token expired"})
		a.Close()
	})
	defer expiry.Stop()
	go func() {
		t := time.NewTicker(wsPing)
		defer t.Stop()
		for {
			select {
			case <-done:
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
	*Attachment
	id       string
	person   string
	jti      string
	out      *ring
	mu       sync.Mutex
	lastSeen time.Time
	done     chan struct{}
	once     sync.Once
}

func (p *pollAttachment) touch() {
	p.mu.Lock()
	p.lastSeen = time.Now()
	p.mu.Unlock()
}

func (p *pollAttachment) end() {
	p.once.Do(func() {
		p.Attachment.Close()
		close(p.done)
	})
}

func (s *Server) pollOpen(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll", true)
	if !ok {
		return
	}
	s.mu.Lock()
	mine := 0
	for _, p := range s.polls {
		if p.person == sess.Person {
			mine++
		}
	}
	full := mine >= maxPollsPerPerson || len(s.polls) >= maxPolls
	s.mu.Unlock()
	if full {
		http.Error(w, "relay: too many long-poll attachments; close one first", http.StatusTooManyRequests)
		return
	}
	cols, rows := termSize(r)
	a, err := s.open(context.Background(), cols, rows)
	if err != nil {
		http.Error(w, "relay: "+err.Error(), http.StatusInternalServerError)
		return
	}
	p := &pollAttachment{Attachment: a, id: newID(), person: sess.Person, jti: sess.TokenID,
		out: newRing(s.opts.Config.Relay.OutputBufferBytes), lastSeen: time.Now(), done: make(chan struct{})}
	p.out.Append(EncodeControl(s.hello()))
	s.mu.Lock()
	s.polls[p.id] = p
	s.mu.Unlock()
	go func() {
		for ev := range a.Events {
			if ev.exit != nil {
				p.out.Append(EncodeControl(Control{Type: CtlExit, Code: ev.exit}))
				continue
			}
			p.out.Append(Encode(FrameData, ev.data))
		}
		p.out.Close()
		p.end()
	}()
	go s.reapPoll(p, s.untilExpiry(sess))
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"id": p.id, "cursor": 0, "version": Version})
}

// reapPoll ends an attachment that is idle or whose token expired.
func (s *Server) reapPoll(p *pollAttachment, life time.Duration) {
	expiry := time.NewTimer(life)
	defer expiry.Stop()
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-p.done:
			break loop
		case <-expiry.C:
			p.out.Append(EncodeControl(Control{Type: CtlError, Message: "session token expired"}))
			p.end()
			break loop
		case <-t.C:
			p.mu.Lock()
			idle := time.Since(p.lastSeen)
			p.mu.Unlock()
			if idle >= pollIdle {
				p.end()
				break loop
			}
		}
	}
	s.mu.Lock()
	delete(s.polls, p.id)
	s.mu.Unlock()
}

// pollFor is the attachment the request names; only the token that opened
// it may use it.
func (s *Server) pollFor(w http.ResponseWriter, r *http.Request, sess Session) *pollAttachment {
	s.mu.Lock()
	p := s.polls[r.PathValue("id")]
	s.mu.Unlock()
	if p == nil || p.person != sess.Person || p.jti != sess.TokenID {
		// Another person's (or token's) attachment is as absent as a
		// closed one.
		http.Error(w, "relay: no such attachment", http.StatusNotFound)
		return nil
	}
	p.touch()
	return p
}

func (s *Server) pollRead(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll-read", false)
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
	sess, ok := s.auth(w, r, "poll-write", false)
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
		if !input(p.Attachment, f, send) {
			p.end()
			break
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) pollClose(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll-close", false)
	if !ok {
		return
	}
	if p := s.pollFor(w, r, sess); p != nil {
		p.end()
		w.WriteHeader(http.StatusNoContent)
	}
}

// status reports what a launcher's `status` shows: the session, whether
// the agent runs, the last pre-connect time and the tasks.
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.auth(w, r, "status", false); !ok {
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
		"version": Version, "session": s.session, "agent_running": s.agent.Running(),
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
