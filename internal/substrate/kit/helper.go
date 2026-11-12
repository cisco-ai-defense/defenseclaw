// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// The resident helper keeps the kit's connection to the actor listener warm
// between hook calls. Each hook process is short-lived; without the helper
// every call pays a new TCP and TLS handshake through egress (about 30 ms,
// GAP-0010). The helper listens on a socket in a private directory under
// TMPDIR and, on Linux, on an abstract socket too: on microVM a socket file
// can vanish across suspend (GAP-0001), an abstract name cannot.
//
// The helper is a transport only. The gateway trusts the injected JWT, not
// the helper; a client still refuses a helper that is not this same binary.

const (
	helperDirPrefix  = "defenseclaw-actor-"
	helperSocketName = "hook.sock"
	maxHelperFrame   = 8 << 20
	// resumeGap is the wall-clock jump the helper reads as a resume.
	resumeGap = 3 * time.Second
)

type helperRequest struct {
	Op        string  `json:"op"` // post, warm, mode, ping, skills
	Request   Request `json:"request,omitempty"`
	Connector string  `json:"connector,omitempty"`
	Mode      string  `json:"mode,omitempty"`
}

type helperResponse struct {
	Response Response `json:"response"`
	// Unreachable is set when no attempt got an answer.
	Unreachable bool   `json:"unreachable,omitempty"`
	Error       string `json:"error,omitempty"`
	// Mode is the helper's run mode (unattended once set, for good).
	Mode string `json:"mode"`
	// FailMode is the outage mode the gateway last named ("" before it
	// answered once).
	FailMode string `json:"fail_mode,omitempty"`
	// Skills are the skill-folder fingerprints the gateway has seen (op
	// skills).
	Skills map[string]string `json:"skills,omitempty"`
	PID    int               `json:"pid"`
}

// HelperDir is the private directory of the helper's socket.
func HelperDir() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("%s%d", helperDirPrefix, os.Getuid()))
}

// ensurePrivateDir creates dir 0700 or checks that an existing one is a real
// directory of this user that nobody else can enter.
func ensurePrivateDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if uid, _, _ := fileOwner(info); uid != os.Getuid() {
		return fmt.Errorf("%s is not owned by this user", dir)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is open to other users", dir)
	}
	return nil
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(b)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

func readFrame(r io.Reader, v any) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(n[:])
	if size > maxHelperFrame {
		return errors.New("helper frame too large")
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Helper is the resident helper.
type Helper struct {
	cfg       Config
	transport *Transport
	log       *slog.Logger

	mu       sync.Mutex
	mode     string
	failMode string
	warm     map[string]bool
	skills   map[string]string
}

// NewHelper builds a helper; it makes no connection until asked.
func NewHelper(cfg Config, log *slog.Logger) (*Helper, error) {
	t, err := NewTransport(cfg)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Helper{cfg: cfg, transport: t, log: log, mode: ModeInteract, warm: map[string]bool{}, skills: map[string]string{}}, nil
}

// Serve listens on the helper sockets until ctx ends. It returns
// errHelperRunning when another helper already serves this user.
func (h *Helper) Serve(ctx context.Context) error {
	dir := HelperDir()
	if err := ensurePrivateDir(dir); err != nil {
		return fmt.Errorf("actor hook helper: %w", err)
	}
	listeners, err := listenHelper(filepath.Join(dir, helperSocketName))
	if err != nil {
		return err
	}
	go h.watchResume(ctx)
	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(l net.Listener) {
			defer wg.Done()
			go func() { <-ctx.Done(); l.Close() }()
			for {
				conn, err := l.Accept()
				if err != nil {
					if ctx.Err() != nil {
						return
					}
					var ne net.Error
					if errors.As(err, &ne) && ne.Timeout() {
						continue
					}
					return
				}
				go h.handle(ctx, conn)
			}
		}(l)
	}
	wg.Wait()
	return ctx.Err()
}

func (h *Helper) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	if !peerIsSameUser(conn) {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var req helperRequest
	if err := readFrame(conn, &req); err != nil {
		return
	}
	resp := h.do(ctx, req)
	_ = writeFrame(conn, resp)
}

func (h *Helper) currentMode() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.mode
}

func (h *Helper) do(ctx context.Context, req helperRequest) helperResponse {
	out := helperResponse{PID: os.Getpid()}
	switch req.Op {
	case "ping":
	case "skills":
		h.mu.Lock()
		out.Skills = make(map[string]string, len(h.skills))
		for k, v := range h.skills {
			out.Skills[k] = v
		}
		h.mu.Unlock()
	case "mode":
		// A helper's mode only ever tightens.
		if req.Mode == ModeUnattend {
			h.mu.Lock()
			h.mode = ModeUnattend
			h.mu.Unlock()
		}
	case "warm":
		if err := h.transport.Warm(ctx, req.Connector); err != nil {
			out.Unreachable = true
			out.Error = err.Error()
		} else {
			h.mu.Lock()
			h.warm[req.Connector] = true
			h.mu.Unlock()
		}
	case "post":
		r := req.Request
		if r.Header == nil {
			r.Header = map[string]string{}
		}
		if h.currentMode() == ModeUnattend {
			r.Header["X-DefenseClaw-Actor-Mode"] = ModeUnattend
		}
		resp, err := h.transport.Post(ctx, r)
		out.Response = resp
		h.learn(resp)
		if err == nil && resp.Status >= 200 && resp.Status < 300 && len(r.SkillCommit) > 0 {
			h.mu.Lock()
			for k, v := range r.SkillCommit {
				h.skills[k] = v
			}
			h.mu.Unlock()
		}
		if err != nil {
			out.Unreachable = errors.Is(err, ErrUnreachable)
			out.Error = err.Error()
		}
	default:
		out.Error = "unknown op"
	}
	out.Mode = h.currentMode()
	h.mu.Lock()
	out.FailMode = h.failMode
	h.mu.Unlock()
	return out
}

// learn keeps what the gateway said about this actor's run: the mode only
// tightens, the outage mode is the gateway's (the registration decides it).
func (h *Helper) learn(resp Response) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if resp.Mode == ModeUnattend {
		h.mode = ModeUnattend
	}
	switch resp.FailMode {
	case "open", "closed":
		h.failMode = resp.FailMode
	}
}

// watchResume reads a wall-clock jump as a resume from a snapshot: the
// kept-alive connections then lead nowhere, so they are dropped and the
// connectors already warmed are warmed again before the next hook (E6).
func (h *Helper) watchResume(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	last := time.Now().Round(0)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := time.Now().Round(0)
		gap := now.Sub(last)
		last = now
		if gap < resumeGap {
			continue
		}
		h.log.Info("resume detected", "gap", gap.String())
		h.Rewarm(ctx)
	}
}

// Rewarm drops kept-alive connections and warms every connector warmed
// before.
func (h *Helper) Rewarm(ctx context.Context) {
	h.transport.Reset()
	h.mu.Lock()
	var names []string
	for c := range h.warm {
		names = append(names, c)
	}
	h.mu.Unlock()
	for _, c := range names {
		_ = h.transport.Warm(ctx, c)
	}
}

// errNoHelper means no usable helper answered.
var errNoHelper = errors.New("no actor hook helper")

// callHelper sends one request to the running helper.
func callHelper(ctx context.Context, req helperRequest, budget time.Duration) (helperResponse, error) {
	conn, err := dialHelper(filepath.Join(HelperDir(), helperSocketName))
	if err != nil {
		return helperResponse{}, errNoHelper
	}
	defer conn.Close()
	if !peerIsThisBinary(conn) {
		return helperResponse{}, fmt.Errorf("%w: the helper socket is served by another program", errNoHelper)
	}
	deadline := time.Now().Add(budget)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	if err := writeFrame(conn, req); err != nil {
		return helperResponse{}, errNoHelper
	}
	var resp helperResponse
	if err := readFrame(conn, &resp); err != nil {
		// The helper took the request and did not answer: the request may
		// have reached the gateway, so the caller does not repeat it
		// without the helper's idempotency key; it is an outage.
		return helperResponse{Unreachable: true, Error: "helper did not answer: " + err.Error()}, nil
	}
	return resp, nil
}

// helperPath is the helper's program: the installed hook binary, so that the
// relay (another binary) starts and accepts the same helper the hooks use; a
// test binary, which has no installed kit, serves as its own helper.
var helperPath = func() (string, error) {
	if _, err := os.Stat(HookBinary); err == nil {
		return HookBinary, nil
	}
	return os.Executable()
}

// StartHelper starts a detached helper (the hook binary with --serve) and
// does not wait for it.
func StartHelper() error {
	self, err := helperPath()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "--serve")
	cmd.Dir = "/"
	cmd.Env = helperEnv()
	cmd.SysProcAttr = detachedAttr()
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// helperEnv is the only environment the helper inherits: the agent's
// variables (proxies, loaders, CA overrides) never reach it.
func helperEnv() []string {
	env := []string{"PATH=/usr/bin:/bin"}
	for _, k := range []string{"TMPDIR", "HOME", ModeEnv} {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// EnsureHelper returns once a helper answers, starting one if none does,
// within budget.
func EnsureHelper(ctx context.Context, budget time.Duration) error {
	if _, err := callHelper(ctx, helperRequest{Op: "ping"}, budget); err == nil {
		return nil
	}
	if err := StartHelper(); err != nil {
		return err
	}
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		if _, err := callHelper(ctx, helperRequest{Op: "ping"}, budget); err == nil {
			return nil
		}
		time.Sleep(10 * time.Millisecond)
	}
	return errNoHelper
}

// Warm makes sure a helper runs and has a connection to the actor listener
// for connector (the relay calls it on every attach and resume, E6).
func Warm(ctx context.Context, connector string, budget time.Duration) error {
	if err := EnsureHelper(ctx, budget); err != nil {
		return err
	}
	resp, err := callHelper(ctx, helperRequest{Op: "warm", Connector: connector}, budget)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

// SetUnattended tells the helper this actor runs unattended (fail closed for
// good). The relay calls it before a --task run starts.
func SetUnattended(ctx context.Context, budget time.Duration) error {
	if err := EnsureHelper(ctx, budget); err != nil {
		return err
	}
	_, err := callHelper(ctx, helperRequest{Op: "mode", Mode: ModeUnattend}, budget)
	return err
}
