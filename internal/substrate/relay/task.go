// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// A task is one headless run (`defenseclaw substrate run --task`): the
// connector's headless command with the task text, unattended, so every
// hook fails closed (D8). It runs on its own: a launcher that disconnects
// (--detach) leaves it running and follows it again later.
//
// Nobody watches an unattended run, so the relay bounds it (GAP-0273): a
// task that makes no progress for relay.task_stall_ms (DefaultTaskStall) is
// ended with ExitStalled and a line that says why, and every task end is
// reported to the gateway (TaskReportPath), which audits it and lets the
// controller free the actor's worker (GAP-0274).

// ExitStalled is the exit code of a task the relay ended because it made no
// progress for the stall bound (the timeout(1) convention).
const ExitStalled = 124

// ExitInterrupted is the exit code of a task whose agent exited 0 although
// the cluster gateway did not answer some of its hook calls (GAP-0326):
// those calls failed closed, so the steps they guarded may not have run.
// It is EX_TEMPFAIL (sysexits.h): a temporary failure, run it again.
const ExitInterrupted = 75

// TaskReportPath is the actor listener route a relay reports a task end to.
const TaskReportPath = "/api/v1/substrate/relay/task"

const (
	// stallTick is how often the watchdog samples the agent.
	stallTick = 30 * time.Second
	// stallIO is the agent tree's I/O per tick that counts as progress,
	// and 1% of a core over the tick the CPU time. An agent stuck on a model
	// request that never answers uses about 0.2% of a core and a few hundred
	// bytes a minute (Claude Code 2.1.322, measured for GAP-0273); a live
	// model stream reads far more than stallIO.
	stallIO = 16 << 10
	// stopGrace is how long a stalled agent gets between TERM and KILL.
	stopGrace = 10 * time.Second
	// drainBudget is how long the output pipes may stay open after the
	// agent exited (a background child of the agent holding them).
	drainBudget = 5 * time.Second
	// reportBudget bounds the task-end report and its retries.
	reportBudget = 2 * time.Minute
)

// TaskRequest starts a task. The headless command is the template's; a
// request carries only the task text, which must be the text the launcher
// registered (its SHA-256 is the session's TaskDigest, GAP-0071).
type TaskRequest struct {
	Prompt string `json:"prompt"`
	// Dir is the folder the task runs in (the copy of the project,
	// GAP-0163): inside the relay working directory; "" for the workdir.
	Dir string `json:"dir,omitempty"`
}

// TaskDigest is the registration's digest of a task text.
func TaskDigest(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(sum[:])
}

// TaskEvent is one NDJSON line of a task's log.
type TaskEvent struct {
	Type string `json:"type"` // start, stdout, stderr, exit, error
	Data string `json:"data,omitempty"`
	Code *int   `json:"code,omitempty"`
	ID   string `json:"id,omitempty"`
	TS   string `json:"ts"`
}

// TaskEnd is how a task ended: the exit code, whether the relay ended it
// for making no progress, and the reason it gave. It is the body of the
// report to the gateway.
type TaskEnd struct {
	ExitCode   int    `json:"exit_code"`
	Stalled    bool   `json:"stalled,omitempty"`
	Cause      string `json:"cause,omitempty"`
	DurationMS int64  `json:"duration_ms"`
}

// Usage is the agent tree's CPU time and I/O bytes so far.
type Usage struct {
	CPU time.Duration
	IO  uint64
}

// HeadlessOptions are RunHeadless's connections to the outside.
type HeadlessOptions struct {
	// Warm pre-connects before the agent starts and probes the gateway
	// when the task stalls; nil skips both.
	Warm func(context.Context, string) error
	// Stall overrides the configuration's no-progress bound, Tick the
	// watchdog's sample period (tests).
	Stall, Tick time.Duration
	// Usage reads the agent tree's usage (tests); default the /proc tree of
	// the agent (procTree: its descendants and its process group, Linux;
	// elsewhere only output counts).
	Usage func(pid int) (Usage, bool)
	// sep runs the agent as its own user (GAP-0116); nil runs it as the
	// relay's user.
	sep *separation
}

type task struct {
	id      string
	person  string
	started time.Time
	log     *ring
	mu      sync.Mutex
	code    *int
}

func (t *task) summary() map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	return map[string]any{"started": t.started.UTC().Format(time.RFC3339), "exit_code": t.code, "running": t.code == nil}
}

func (t *task) emit(e TaskEvent) {
	e.TS = time.Now().UTC().Format(time.RFC3339Nano)
	b, _ := json.Marshal(e)
	t.log.Append(append(b, '\n'))
}

// retryNotice is an agent line that only says the agent is retrying a model
// call (Claude Code's stream-json api_retry): it is not progress, or an
// agent whose every attempt hangs would never stall (GAP-0273).
func retryNotice(line string) bool {
	return strings.Contains(line, `"subtype":"api_retry"`)
}

// RunHeadless runs the connector's headless command for prompt, writes each
// TaskEvent to emit and returns how the task ended. The agent and its hooks
// run unattended (fail closed, D8); the gateway path is warmed first. A task
// that makes no progress for the stall bound is ended (ExitStalled).
func RunHeadless(ctx context.Context, cfg kit.Config, req TaskRequest, o HeadlessOptions, emit func(TaskEvent)) TaskEnd {
	start := time.Now()
	end := func(code int) TaskEnd {
		return TaskEnd{ExitCode: code, DurationMS: time.Since(start).Milliseconds()}
	}
	argv, err := expandHeadless(cfg.Relay.Headless, req.Prompt)
	if err != nil {
		emit(TaskEvent{Type: "error", Data: err.Error()})
		e := end(2)
		e.Cause = err.Error()
		return e
	}
	connector := cfg.Relay.Connector
	if connector != "" && o.Warm != nil {
		wctx, cancel := context.WithTimeout(ctx, warmBudget)
		if err := o.Warm(wctx, connector); err != nil {
			emit(TaskEvent{Type: "stderr", Data: "defenseclaw: the gateway did not answer the pre-connect: " + err.Error()})
		}
		cancel()
	}
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = cfg.Relay.Workdir
	if req.Dir != "" {
		cmd.Dir = req.Dir // checked by the caller (Server.projectDir)
	}
	cmd.Env = append(os.Environ(), kit.ModeEnv+"="+kit.ModeUnattend)
	for k, v := range cfg.Relay.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	// The hooks record here each call the gateway did not answer; set last,
	// so the template's environment cannot point it elsewhere (GAP-0326).
	faults := ""
	if f, ferr := os.CreateTemp("", "defenseclaw-task-faults-*"); ferr == nil {
		faults = f.Name()
		f.Close()
		defer os.Remove(faults)
		cmd.Env = append(cmd.Env, kit.TaskFaultsEnv+"="+faults)
	}
	cmd.Stdin = nil
	// The agent gets a process group of its own; the watchdog measures and
	// stops its whole process tree, tools in sessions of their own too
	// (procTree, GAP-0289).
	setProcessGroup(cmd)
	o.sep.asAgent(cmd)
	cmd.Cancel = func() error { return killProcessGroup(cmd) }
	// Own pipes, not StdoutPipe: the relay must not wait forever on a pipe
	// that a child of the agent keeps open after the agent exited.
	outR, outW, err := os.Pipe()
	if err != nil {
		emit(TaskEvent{Type: "error", Data: err.Error()})
		return end(127)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		outR.Close()
		outW.Close()
		emit(TaskEvent{Type: "error", Data: err.Error()})
		return end(127)
	}
	cmd.Stdout, cmd.Stderr = outW, errW
	if err := cmd.Start(); err != nil {
		for _, f := range []*os.File{outR, outW, errR, errW} {
			f.Close()
		}
		emit(TaskEvent{Type: "error", Data: err.Error()})
		return end(127)
	}
	outW.Close()
	errW.Close()
	var progress atomic.Int64
	var wg sync.WaitGroup
	pump := func(kind string, r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			line := sc.Text()
			if !retryNotice(line) {
				progress.Add(1)
			}
			emit(TaskEvent{Type: kind, Data: line})
		}
	}
	wg.Add(2)
	go pump("stdout", outR)
	go pump("stderr", errR)

	exited := make(chan struct{})
	var stalled atomic.Pointer[string]
	go watch(cmd, connector, cfg.Relay.TaskStall(), o, &progress, exited, func(cause string) {
		stalled.Store(&cause)
		emit(TaskEvent{Type: "error", Data: "defenseclaw: " + cause})
	})
	waitErr := cmd.Wait()
	close(exited)
	drained := make(chan struct{})
	go func() { wg.Wait(); close(drained) }()
	select {
	case <-drained:
	case <-time.After(drainBudget):
		outR.Close()
		errR.Close()
		<-drained
	}
	outR.Close()
	errR.Close()
	code := 0
	if waitErr != nil {
		var ee *exec.ExitError
		if errors.As(waitErr, &ee) {
			code = exitCodeOf(ee.ProcessState)
		} else {
			code = 1
		}
	}
	if c := stalled.Load(); c != nil {
		e := end(ExitStalled)
		e.Stalled, e.Cause = true, *c
		return e
	}
	e := end(code)
	if n, first := kit.ReadTaskFaults(faults); n > 0 {
		e.Cause = interruptedCause(n, first, code)
		if code == 0 {
			e.ExitCode = ExitInterrupted
		}
		emit(TaskEvent{Type: "error", Data: "defenseclaw: " + e.Cause})
	}
	return e
}

// interruptedCause says why a task whose hooks met a gateway outage is not a
// success (GAP-0326): the agent's own exit 0 cannot tell.
func interruptedCause(n int, first kit.TaskFault, code int) string {
	calls := "1 hook call"
	if n > 1 {
		calls = fmt.Sprintf("%d hook calls", n)
	}
	cause := fmt.Sprintf("the cluster gateway did not answer %s during the task (the first: %s at %s); "+
		"they failed closed, so the steps they guarded may not have run", calls, first.Event, first.At)
	if code == 0 {
		cause += fmt.Sprintf(". The agent exited 0, but the task is ended with exit code %d: run it again", ExitInterrupted)
	}
	return cause
}

// watch ends the agent when it makes no progress for stall: no output line
// (retry notices aside) and less than 1% of a core and stallIO of use in its
// process tree in every tick. A tick much later than planned is a suspend
// and resume of the actor, not a stall. A stalled task is stopped whole:
// TERM to the group and the tree, then KILL after stopGrace.
func watch(cmd *exec.Cmd, connector string, stall time.Duration, o HeadlessOptions, progress *atomic.Int64, exited <-chan struct{}, stalled func(string)) {
	tick := o.Tick
	if tick <= 0 {
		tick = stallTick
	}
	if o.Stall > 0 {
		stall = o.Stall
	}
	pid := cmd.Process.Pid
	tree := newProcTree(pid)
	tree.asAgent(o.sep)
	usage := o.Usage
	cpuMin := tick / 100
	t := time.NewTicker(tick)
	defer t.Stop()
	prev, havePrev := tree.usage()
	if usage != nil {
		prev, havePrev = usage(pid)
	}
	lastTick, last := time.Now(), time.Now()
	for {
		select {
		case <-exited:
			return
		case now := <-t.C:
			if now.Sub(lastTick) > 3*tick {
				last = now // the actor was suspended
			}
			lastTick = now
			if progress.Swap(0) > 0 {
				last = now
			}
			// The tree is walked every tick, whoever measures it, so a tool
			// whose parent exits stays known and is stopped with the rest.
			u, ok := tree.usage()
			if usage != nil {
				u, ok = usage(pid)
			}
			if ok {
				// A child that exited takes its counts with it: only growth
				// counts.
				if havePrev && (u.CPU-prev.CPU >= cpuMin || (u.IO > prev.IO && u.IO-prev.IO >= stallIO)) {
					last = now
				}
				prev, havePrev = u, true
			}
			if now.Sub(last) < stall {
				continue
			}
			probe := "the gateway was not checked"
			if o.Warm != nil && connector != "" {
				wctx, cancel := context.WithTimeout(context.Background(), warmBudget)
				probe = "the cluster gateway answers, so the agent is stuck on a connection of its own"
				if err := o.Warm(wctx, connector); err != nil {
					probe = "the cluster gateway does not answer (" + err.Error() + ")"
				}
				cancel()
			}
			stalled(fmt.Sprintf("the task made no progress for %s (no output, CPU or I/O); %s. The task is ended with exit code %d.",
				stall.Round(time.Second), probe, ExitStalled))
			// The tree first, while the agent still holds its children.
			tree.signal(syscall.SIGTERM)
			_ = termProcessGroup(cmd)
			select {
			case <-exited:
			case <-time.After(stopGrace):
				_ = killProcessGroup(cmd)
			}
			// What outlived the agent (tools in sessions of their own) goes
			// too: a stalled task leaves nothing running.
			tree.signal(syscall.SIGKILL)
			return
		}
	}
}

// ReportTaskEnd sends end to the gateway with report, retrying an attempt
// without an answer, with a 5xx or with a 429 for up to reportBudget, and
// waiting at least an answer's Retry-After (GAP-0301: the agent shares the
// actor's request budget, so a 429 must not drop the relay's real end). A
// refusal (any other non-2xx, such as an older gateway without the route)
// is final.
func ReportTaskEnd(ctx context.Context, report func(context.Context, TaskEnd) error, end TaskEnd) error {
	ctx, cancel := context.WithTimeout(ctx, reportBudget)
	defer cancel()
	delay := 2 * time.Second
	for {
		err := report(ctx, end)
		if err == nil || errors.Is(err, errReportRefused) {
			return err
		}
		wait := delay
		var later *reportLater
		if errors.As(err, &later) && later.after > wait {
			wait = min(later.after, 30*time.Second)
		}
		select {
		case <-ctx.Done():
			return err
		case <-time.After(wait):
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

// reportLater is a report the gateway asked to send again (429 or 5xx),
// after at least after when it said so.
type reportLater struct {
	status int
	after  time.Duration
}

func (e *reportLater) Error() string { return fmt.Sprintf("task-end report: status %d", e.status) }

// retryAfter reads a Retry-After of seconds; a date or garbage is 0.
func retryAfter(v string) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(min(n, 300)) * time.Second
}

// errReportRefused is a task-end report the gateway answered with a status
// that a retry does not change.
var errReportRefused = errors.New("the gateway refused the task-end report")

// GatewayReport posts a task end to the actor listener over t.
func GatewayReport(t *kit.Transport) func(context.Context, TaskEnd) error {
	return func(ctx context.Context, end TaskEnd) error {
		body, _ := json.Marshal(end)
		resp, err := t.Post(ctx, kit.Request{Path: TaskReportPath, Body: body})
		switch {
		case err != nil:
			return err
		case resp.Status >= 200 && resp.Status < 300:
			return nil
		case resp.Status >= 500 || resp.Status == http.StatusTooManyRequests:
			return &reportLater{status: resp.Status, after: retryAfter(resp.RetryAfter)}
		}
		return fmt.Errorf("%w (status %d)", errReportRefused, resp.Status)
	}
}

func (s *Server) taskStart(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "task", true)
	if !ok {
		return
	}
	var req TaskRequest
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil || req.Prompt == "" {
		http.Error(w, "relay: a task is {\"prompt\": ...} and nothing else", http.StatusBadRequest)
		return
	}
	if req.Dir != "" {
		d, err := s.projectDir(req.Dir)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		req.Dir = d
	}
	if sess.TaskDigest == "" || TaskDigest(req.Prompt) != sess.TaskDigest {
		s.log.Warn("relay.refused", "what", "task", "reason", "task text is not the registered task", "person", sess.Person)
		http.Error(w, "relay: this task text is not the task this actor was registered for", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	for _, t := range s.tasks {
		t.mu.Lock()
		running := t.code == nil
		t.mu.Unlock()
		if running {
			s.mu.Unlock()
			http.Error(w, "relay: "+ErrTaskRunning.Error(), http.StatusConflict)
			return
		}
	}
	t := &task{id: newID(), person: sess.Person, started: time.Now(), log: newRing(4 << 20)}
	s.tasks[t.id] = t
	s.mu.Unlock()
	t.emit(TaskEvent{Type: "start", ID: t.id})
	go func() {
		o := s.opts.Headless
		o.Warm = s.opts.Warm
		o.sep = s.opts.sep
		end := RunHeadless(s.taskCtx, s.opts.Config, req, o, t.emit)
		code := end.ExitCode
		t.mu.Lock()
		t.code = &code
		t.mu.Unlock()
		t.emit(TaskEvent{Type: "exit", Code: &code})
		t.log.Close()
		if end.Stalled {
			s.log.Warn("relay.task_stalled", "task", t.id, "exit_code", code, "cause", end.Cause)
		}
		if s.opts.Report == nil {
			return
		}
		if err := ReportTaskEnd(context.Background(), s.opts.Report, end); err != nil {
			s.log.Warn("relay.task_report", "task", t.id, "exit_code", code, "error", err.Error())
		} else {
			s.log.Info("relay.task_report", "task", t.id, "exit_code", code)
		}
	}()
	s.follow(w, r, t, 0)
}

func (s *Server) taskFollow(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "task-follow", false)
	if !ok {
		return
	}
	s.mu.Lock()
	t := s.tasks[r.PathValue("id")]
	s.mu.Unlock()
	if t == nil || t.person != sess.Person {
		http.Error(w, "relay: no such task", http.StatusNotFound)
		return
	}
	cursor, _ := strconv.ParseUint(r.URL.Query().Get("cursor"), 10, 64)
	s.follow(w, r, t, cursor)
}

// follow streams a task's NDJSON log from cursor until it ends or the
// client goes away (the task keeps running).
func (s *Server) follow(w http.ResponseWriter, r *http.Request, t *task, cursor uint64) {
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("X-Dcrelay-Task", t.id)
	fl, _ := w.(http.Flusher)
	for {
		data, next, _, closed := t.log.Read(r.Context(), cursor)
		if r.Context().Err() != nil {
			return
		}
		frames, _ := SplitStream(data)
		for _, f := range frames {
			if _, err := w.Write(f); err != nil {
				return
			}
		}
		if fl != nil {
			fl.Flush()
		}
		cursor = next
		if closed {
			return
		}
	}
}
