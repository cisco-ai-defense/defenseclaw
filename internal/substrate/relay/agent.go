// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
)

// Agent is the agent's terminal session, held by the relay itself: the relay
// is the parent of the agent and holds its PTY master, so the session
// survives every attachment, suspend and resume, and the relay reads the
// agent's exit status from wait.
//
// There is no multiplexer socket (no tmux): the agent runs as the same user
// as the relay, and anything the relay listened on the agent could connect to
// and type into the person's terminal, answering its own permission prompts
// (substrate-1 GAP-0048). The PTY master is a close-on-exec descriptor of a
// process the agent cannot read or trace (the relay makes itself
// non-dumpable, harden_linux.go).
type Agent struct {
	Argv []string
	Dir  string
	Env  []string

	mu      sync.Mutex
	cmd     *exec.Cmd
	pty     *os.File
	running bool
	cols    uint16
	rows    uint16
	scroll  []byte
	subs    map[int]*subscriber
	nextSub int
	lastErr error
}

// scrollbackBytes is the output a new attachment gets first.
const scrollbackBytes = 256 << 10

// subscriberQueue bounds the frames waiting for a slow attachment; one that
// falls behind is closed and reattaches.
const subscriberQueue = 1024

// event is one item for an attachment: output, or the agent's exit.
type event struct {
	data []byte
	exit *int
}

type subscriber struct {
	ch     chan event
	closed bool
}

// ErrAgentNotRunning is returned when the agent cannot be started.
var ErrAgentNotRunning = errors.New("relay: the agent is not running")

// Running reports whether the agent runs.
func (a *Agent) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.running
}

// start starts the agent on a new PTY of cols x rows. Called with a.mu held.
func (a *Agent) start(cols, rows uint16) error {
	if len(a.Argv) == 0 {
		return errors.New("relay: no agent command configured")
	}
	cmd := exec.Command(a.Argv[0], a.Argv[1:]...)
	cmd.Dir = a.Dir
	cmd.Env = append(append([]string{}, a.Env...), "TERM=xterm-256color")
	p, err := startPTY(cmd, cols, rows)
	if err != nil {
		a.lastErr = err
		return err
	}
	a.cmd, a.pty, a.running, a.cols, a.rows = cmd, p, true, cols, rows
	a.scroll = nil
	go a.pump(cmd, p)
	return nil
}

// pump copies the agent's output to the scrollback and every attachment,
// then reports the agent's exit.
func (a *Agent) pump(cmd *exec.Cmd, p *os.File) {
	buf := make([]byte, 32<<10)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			chunk := append([]byte(nil), buf[:n]...)
			a.mu.Lock()
			a.scroll = append(a.scroll, chunk...)
			if over := len(a.scroll) - scrollbackBytes; over > 0 {
				a.scroll = append([]byte(nil), a.scroll[over:]...)
			}
			for id, s := range a.subs {
				select {
				case s.ch <- event{data: chunk}:
				default:
					// Fell behind: it reattaches and gets the scrollback.
					close(s.ch)
					s.closed = true
					delete(a.subs, id)
				}
			}
			a.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	code := exitCode(cmd.Wait())
	a.mu.Lock()
	a.running = false
	p.Close()
	for id, s := range a.subs {
		c := code
		select {
		case s.ch <- event{exit: &c}:
		default:
		}
		close(s.ch)
		s.closed = true
		delete(a.subs, id)
	}
	a.mu.Unlock()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return 1
}

// Attachment is one client's view of the agent's terminal.
type Attachment struct {
	agent *Agent
	id    int
	// Events delivers output (the scrollback first) and, last, the exit.
	Events <-chan event
	once   sync.Once
}

// Attach starts the agent if it is not running and subscribes to it. The
// scrollback comes first, then the terminal is resized (twice when the size
// does not change) so a full-screen program redraws.
func (a *Agent) Attach(cols, rows uint16) (*Attachment, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.running {
		if err := a.start(cols, rows); err != nil {
			return nil, err
		}
	}
	if a.subs == nil {
		a.subs = map[int]*subscriber{}
	}
	s := &subscriber{ch: make(chan event, subscriberQueue)}
	if len(a.scroll) > 0 {
		s.ch <- event{data: append([]byte(nil), a.scroll...)}
	}
	a.nextSub++
	id := a.nextSub
	a.subs[id] = s
	if cols == a.cols && rows == a.rows && rows > 1 {
		_ = setSize(a.pty, cols, rows-1)
	}
	_ = setSize(a.pty, cols, rows)
	a.cols, a.rows = cols, rows
	return &Attachment{agent: a, id: id, Events: s.ch}, nil
}

// Write types into the agent's terminal.
func (t *Attachment) Write(p []byte) (int, error) {
	t.agent.mu.Lock()
	defer t.agent.mu.Unlock()
	if !t.agent.running {
		return 0, ErrAgentNotRunning
	}
	return t.agent.pty.Write(p)
}

// Resize sets the terminal size (the newest attachment's size wins).
func (t *Attachment) Resize(cols, rows uint16) {
	t.agent.mu.Lock()
	defer t.agent.mu.Unlock()
	if t.agent.running {
		_ = setSize(t.agent.pty, cols, rows)
		t.agent.cols, t.agent.rows = cols, rows
	}
}

// Close detaches; the agent keeps running.
func (t *Attachment) Close() {
	t.once.Do(func() {
		t.agent.mu.Lock()
		defer t.agent.mu.Unlock()
		if s, ok := t.agent.subs[t.id]; ok {
			delete(t.agent.subs, t.id)
			if !s.closed {
				close(s.ch)
				s.closed = true
			}
		}
	})
}
