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
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/signin"
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
	// Report sends a task's end to the gateway (TaskReportPath, GAP-0273,
	// GAP-0274); default GatewayReport over the kit transport.
	Report func(ctx context.Context, end TaskEnd) error
	// Headless tunes the task watchdog (tests); its Warm is Warm.
	Headless HeadlessOptions
	// Guard are the folders the relay watches (GAP-0120); nil is
	// kit.GuardedDirs of the connector in the relay's HOME, empty is none.
	Guard []string
	// Tamper reports a guard trip to the gateway, which audits it
	// (TamperReportPath, GAP-0120); default GatewayTamper over the kit
	// transport.
	Tamper func(ctx context.Context, connector, reason string) error
	// Certs is the TLS serving certificate of a kit that serves TLS
	// (B3.5); a resume asks for a new one ahead of the next attach.
	Certs *CertSource
	Now   func() time.Time
	// sep runs everything the relay starts as the agent's user (GAP-0116;
	// Main sets it from separate). nil: the relay's own user.
	sep *separation
	// mountinfo reads the actor's mount table (GAP-0368); nil is
	// readMountinfo (tests set it).
	mountinfo func() ([]byte, error)
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
	// servingSince is when the relay first served this actor (init): the
	// first authenticated request after the actor's first resume.
	servingSince time.Time
	agent        *Agent
	session      string

	mu    sync.Mutex
	polls map[string]*pollAttachment
	// mcpOpen holds the names with an mcp stream (one each, mcp.go);
	// mcpCfgMu serialises the agent MCP configuration edits.
	mcpOpen  map[string]bool
	mcpCfgMu sync.Mutex
	tasks    map[string]*task
	// used are the session token IDs that opened an attachment or a task,
	// with their expiry: a token opens one (GAP-0070).
	used map[string]time.Time
	// lastWarm is how long the last pre-connect took (E6 measurements).
	lastWarm time.Duration
	// inputs are the input counts of recent attachments by id, oldest
	// first in inputOrder (GAP-0170).
	inputs     map[string]*inputCount
	inputOrder []string

	// guardErr is set when a guarded folder moved (GAP-0120): the agent
	// was stopped and nothing starts again. taskCtx ends the running task
	// then.
	guardMu  sync.Mutex
	guardErr error
	taskCtx  context.Context
	taskStop context.CancelFunc
}

// maxInputCounts bounds the attachments whose input counts a reconnect can
// ask for; the oldest go first.
const maxInputCounts = 64

// inputCount is the DATA bytes the relay wrote to the agent from one
// attachment. It lives in the relay's memory, so it survives a suspend the
// way the agent's terminal does.
type inputCount struct {
	person string
	n      atomic.Int64
}

// countInput starts the input count of a new attachment of person and
// returns its id, with the count of the attachment resume names when it
// is this person's (nil when the relay does not know it).
func (s *Server) countInput(person, resume string) (string, *inputCount, *int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inputs == nil {
		s.inputs = map[string]*inputCount{}
	}
	var received *int64
	if c := s.inputs[resume]; resume != "" && c != nil && c.person == person {
		n := c.n.Load()
		received = &n
	}
	id, c := newID(), &inputCount{person: person}
	s.inputs[id] = c
	s.inputOrder = append(s.inputOrder, id)
	if over := len(s.inputOrder) - maxInputCounts; over > 0 {
		for _, old := range s.inputOrder[:over] {
			delete(s.inputs, old)
		}
		s.inputOrder = append([]string(nil), s.inputOrder[over:]...)
	}
	return id, c, received
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
		s.agent = &Agent{Argv: rc.Interactive, Dir: rc.Workdir, Env: env, sep: s.opts.sep}
		if f := rc.ClaudeStateFile; f != "" {
			root := relayWorkdir(rc.Workdir)
			sp := s.opts.sep
			s.agent.BeforeStart = func(dir string) {
				if dir == "" {
					dir = root
				}
				if sp != nil {
					// ~/.claude.json is the agent's file in the agent's
					// home: a relay that runs as root records the trust as
					// the agent's user, like every other file it writes for
					// the agent (GAP-0116), so the file stays the agent's
					// and a link the agent planted is not followed with
					// root's rights.
					if err := sp.claudeTrust(f, root, dir); err != nil {
						s.log.Warn("relay.claude_trust_failed", "error", err.Error())
					}
					return
				}
				if err := claudeTrust(f, root, dir); err != nil {
					s.log.Warn("relay.claude_trust_failed", "error", err.Error())
				}
			}
		}
		// E9: no agent that signs in to a vendor account in a managed
		// image; an open-source image says what the sign-in costs.
		d := s.signinDecision()
		if !d.Allowed {
			s.log.Warn("relay.signin_refused", "connector", rc.Connector, "reason", d.Code)
			s.initErr = &signinRefusal{msg: d.Message}
			return
		}
		if d.Warn {
			s.log.Warn("relay.signin_warning", "connector", rc.Connector)
			s.agent.Banner = d.Message
		}
		if s.opts.Warm == nil || s.opts.Report == nil {
			t, err := kit.NewTransport(s.opts.Config)
			if err != nil {
				s.initErr = err
				return
			}
			if s.opts.Warm == nil {
				s.opts.Warm = t.Warm
			}
			if s.opts.Report == nil {
				s.opts.Report = GatewayReport(t)
			}
			if s.opts.Tamper == nil {
				s.opts.Tamper = GatewayTamper(t)
			}
		}
		// The hook folders the agent could rename away are watched from
		// here on, before the agent first runs (GAP-0120).
		s.taskCtx, s.taskStop = context.WithCancel(context.Background())
		guard := s.opts.Guard
		if guard == nil {
			home := os.Getenv("HOME")
			if home == "" {
				home = kit.ActorHome // the kit's image HOME, as its start wrapper assumes
			}
			guard = kit.GuardedDirs(rc.Connector, home)
		}
		// No mount may hide the kit's files, also through a symlink in the
		// image that admission cannot see (GAP-0368).
		read := s.opts.mountinfo
		if read == nil {
			read = readMountinfo
		}
		info, err := read()
		if err != nil {
			s.refuseAtStart("relay.mount_refused", "DefenseClaw cannot read the actor's mounts ("+err.Error()+"), so it cannot tell that its hooks are in place; refusing to start the agent")
			return
		}
		hidden, err := kitMountRefusal(info, rc.Protected, guard)
		if err != nil {
			s.refuseAtStart("relay.mount_refused", "DefenseClaw cannot read the actor's mounts ("+err.Error()+"), so it cannot tell that its hooks are in place; refusing to start the agent")
			return
		}
		if hidden != "" {
			s.refuseAtStart("relay.mount_refused", "a volume is mounted at, above or below "+hidden+", which holds DefenseClaw's hooks or the image's system files, so the agent could run without its hooks or with other system files; refusing to start the agent (mount data folders below the working directory)")
			return
		}
		if err := watchGuardedAs(s.taskCtx, guard, s.guardBroken, s.opts.sep.agentCred()); err != nil {
			var degraded *guardDegraded
			if errors.As(err, &degraded) {
				// Fail closed (GAP-0369): without the watch a fast swap and
				// restore of the folder would go unseen.
				s.refuseAtStart("relay.guard_degraded", err.Error()+", so a move of it could go unseen; refusing to start the agent")
				return
			}
			s.log.Warn("relay.guard_refused", "connector", rc.Connector, "error", err.Error())
			s.initErr = &signinRefusal{msg: "DefenseClaw's hook folder is not in place (" + err.Error() + "); refusing to start the agent without its hooks"}
			return
		}
		s.session = newID()
		// When this relay began serving this actor (GAP-0412): every actor
		// of a template is restored from one golden snapshot, so the relay
		// process (PID 1, it answers the wake-up probe) has the snapshot's
		// start time in all of them; this is the actor's own.
		s.servingSince = s.opts.Now().UTC()
		go s.watchResume()
	})
	return s.initErr
}

// guardBroken stops the agent and its task for good when a guarded folder
// moved (GAP-0120): every process of the actor but the relay ends (a tool
// in a process group or session of its own too, GAP-0358), every attached
// terminal is told why and closed, and the gateway audits the trip. Every
// later attach is refused with the reason (410, GAP-0357).
func (s *Server) guardBroken(reason string) {
	msg := "DefenseClaw's hook-folder integrity guard stopped this agent: " + reason + ", so the agent could have run without DefenseClaw's hooks. The agent cannot be started again; delete it and start a new one"
	s.guardMu.Lock()
	s.guardErr = &guardStopped{msg: msg}
	s.guardMu.Unlock()
	connector := s.opts.Config.Relay.Connector
	if strings.HasPrefix(reason, guardWatchEnded) {
		s.log.Error("relay.guard_degraded", "connector", connector, "reason", reason)
	}
	s.log.Warn("relay.guard_tamper", "connector", connector, "reason", reason)
	s.taskStop()
	if n := stopActorProcesses(s.agent.pid(), func() { s.agent.Stop(msg) }); n > 0 {
		s.log.Warn("relay.guard_stopped_processes", "connector", connector, "processes", n)
	}
	if s.opts.Tamper != nil {
		go func() {
			if err := reportTamper(context.Background(), s.opts.Tamper, connector, reason); err != nil {
				s.log.Warn("relay.guard_report", "connector", connector, "error", err.Error())
			}
		}()
	}
}

// refuseAtStart refuses the agent for good before it first runs, because
// DefenseClaw cannot keep its hooks in place (a mount over them, a guard
// watch that cannot be set): the reason is logged as event, answered to
// every attach (403) and audited as HIGH on the tamper route.
func (s *Server) refuseAtStart(event, reason string) {
	connector := s.opts.Config.Relay.Connector
	s.log.Error(event, "connector", connector, "reason", reason)
	s.initErr = &signinRefusal{msg: reason}
	if s.opts.Tamper != nil {
		go func() {
			if err := reportTamper(context.Background(), s.opts.Tamper, connector, reason); err != nil {
				s.log.Warn("relay.guard_report", "connector", connector, "error", err.Error())
			}
		}()
	}
}

// guardStopped is the refusal of every attachment after a guard trip.
type guardStopped struct{ msg string }

func (e *guardStopped) Error() string { return e.msg }

// StoppedHeader marks a relay answer for an agent the guard stopped (410).
const StoppedHeader = "X-Dcrelay-Stopped"

func (s *Server) guardError() error {
	s.guardMu.Lock()
	defer s.guardMu.Unlock()
	return s.guardErr
}

// signinRefusal is the E9 refusal of an agent that signs in to a vendor
// account, in a managed image, and the guard's refusal (GAP-0120).
type signinRefusal struct{ msg string }

func (e *signinRefusal) Error() string { return e.msg }

// signinDecision is E9 for this image: the connector's vendor API key
// variable counts as bound when the actor carries it (a placeholder; egress
// adds the real key).
func (s *Server) signinDecision() signin.Decision {
	rc := s.opts.Config.Relay
	var bound []string
	if k := signin.KeyEnv(rc.Connector); k != "" {
		if _, ok := rc.Env[k]; ok || os.Getenv(k) != "" {
			bound = append(bound, k)
		}
	}
	return signin.Evaluate(rc.Connector, s.opts.Config.Managed, bound)
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
		if c := s.opts.Certs; c != nil {
			if err := c.Warm(context.Background()); err != nil {
				s.log.Warn("relay.tls_cert", "state", "renew_failed", "reason", err.Error())
			}
		}
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
	mux.HandleFunc("GET "+Path(RouteWS), s.serveWS)
	mux.HandleFunc("POST "+Path(RoutePoll), s.pollOpen)
	mux.HandleFunc("GET "+Path(RoutePoll+"/{id}"), s.pollRead)
	mux.HandleFunc("POST "+Path(RoutePoll+"/{id}"), s.pollWrite)
	mux.HandleFunc("DELETE "+Path(RoutePoll+"/{id}"), s.pollClose)
	mux.HandleFunc("POST "+Path(RouteTask), s.taskStart)
	mux.HandleFunc("GET "+Path(RouteTask+"/{id}"), s.taskFollow)
	mux.HandleFunc("GET "+Path(RouteStatus), s.status)
	mux.HandleFunc("POST "+Path(RouteExec), s.fileExec)
	mux.HandleFunc("PUT "+Path(RouteFiles), s.filePut)
	mux.HandleFunc("GET "+Path(RouteFiles), s.fileGet)
	mux.HandleFunc("GET "+Path(RoutePort+"/{port}"), s.servePort)
	mux.HandleFunc("GET "+Path(RouteMCP+"/{name}"), s.serveMCP)
	return mux
}

// auth verifies the request's session token and audits the outcome. With
// open set the token opens something (an attachment or a task) and may do
// so once.
func (s *Server) auth(w http.ResponseWriter, r *http.Request, what string, open bool) (Session, bool) {
	return s.authScope(w, r, what, open, "")
}

// authScope is auth for a route that serves one token scope (B3 dc.scope):
// "" for the terminal, task and file routes, "port:N" or "mcp:NAME" for a
// stream. A token serves only the routes of its own scope, so a stream token
// never opens a terminal and a terminal token never opens a stream.
func (s *Server) authScope(w http.ResponseWriter, r *http.Request, what string, open bool, scope string) (Session, bool) {
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
	if sess.Scope != scope {
		s.log.Warn("relay.refused", "what", what, "reason", "token scope", "scope", sess.Scope, "person", sess.Person, "jti", sess.TokenID)
		http.Error(w, "relay: the session token is not for this route", http.StatusForbidden)
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
		status := http.StatusInternalServerError
		var refused *signinRefusal
		if errors.As(err, &refused) {
			// A rule, not a fault: the person is told why (E9).
			status = http.StatusForbidden
		}
		http.Error(w, "relay: "+err.Error(), status)
		return Session{}, false
	}
	if err := s.guardError(); err != nil && (open || what == "status") {
		// 410, not 403: the launcher tells "stopped for good" from "not
		// yours" by the status and says why (GAP-0357). The status route
		// answers the same, so the launcher's probe after a refused
		// WebSocket does not take it for a proxy that blocks the upgrade.
		s.log.Warn("relay.refused", "what", what, "reason", "hook folder moved", "person", sess.Person)
		w.Header().Set(StoppedHeader, "guard")
		http.Error(w, "relay: "+err.Error(), http.StatusGone)
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

// startDir applies the dir query parameter of an attach: the folder the
// agent starts in when it is not running yet. It answers 400 itself when
// the folder is refused.
func (s *Server) startDir(w http.ResponseWriter, r *http.Request) bool {
	q := r.URL.Query().Get("dir")
	if q == "" {
		return true
	}
	d, err := s.projectDir(q)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	s.agent.UseDir(d)
	return true
}

// open pre-connects, starts the agent if needed and attaches to it.
func (s *Server) open(ctx context.Context, cols, rows uint16) (*Attachment, error) {
	s.preconnect(ctx)
	return s.agent.Attach(cols, rows)
}

// input applies one client frame to an attachment. It reports false when
// the client detached.
func input(a *Attachment, in *inputCount, frame []byte, send func(Control)) bool {
	t, p, err := Decode(frame)
	if err != nil {
		send(Control{Type: CtlError, Message: err.Error()})
		return true
	}
	switch t {
	case FrameData:
		n, _ := a.Write(p)
		in.n.Add(int64(n))
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

// hello is the first message of an attachment: its input count id, and
// what the relay got from the attachment the client resumes (GAP-0170).
func (s *Server) hello(input string, received *int64) Control {
	return Control{Type: CtlHello, Version: Version, Session: s.session, Mode: kit.ModeInteract, Input: input, Received: received,
		Warning: s.warning()}
}

// warning is the E9 warning of this agent, "" when there is none.
func (s *Server) warning() string {
	if s.agent == nil {
		return ""
	}
	return s.agent.Banner
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
	if !ok || !s.startDir(w, r) {
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
	inID, in, received := s.countInput(sess.Person, r.URL.Query().Get("resume"))
	send(s.hello(inID, received))
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
		send(Control{Type: CtlError, Message: SessionExpiredMessage})
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
		if !input(a, in, msg, send) {
			return
		}
	}
}

// pollAttachment is an attachment served over long-poll.
type pollAttachment struct {
	*Attachment
	id       string
	person   string
	in       *inputCount
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
		p.Close() // the embedded Attachment
		close(p.done)
	})
}

func (s *Server) pollOpen(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "poll", true)
	if !ok || !s.startDir(w, r) {
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
	inID, in, received := s.countInput(sess.Person, r.URL.Query().Get("resume"))
	p := &pollAttachment{Attachment: a, id: newID(), person: sess.Person, in: in,
		out: newRing(s.opts.Config.Relay.OutputBufferBytes), lastSeen: time.Now(), done: make(chan struct{})}
	p.out.Append(EncodeControl(s.hello(inID, received)))
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
			p.out.Append(EncodeControl(Control{Type: CtlError, Message: SessionExpiredMessage}))
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

// pollFor is the attachment the request names; only the person who opened
// it may use it, and only with its random id. It is not bound to the token
// that opened it: through the gateway every request carries a fresh session
// token, so a token binding refused every read and write after the open and
// the launcher piled up attachments until the cap (GAP-0414).
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
		if !input(p.Attachment, p.in, f, send) {
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
		"last_preconnect_ms": float64(warm.Microseconds()) / 1000, "tasks": tasks, "workdir": relayWorkdir(s.opts.Config.Relay.Workdir),
		"state_root": s.stateRoot(), "signin_warning": s.warning(), "serving_since": s.servingSince.Format(time.RFC3339Nano),
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
