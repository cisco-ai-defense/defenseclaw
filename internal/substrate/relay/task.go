// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package relay

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
)

// A task is one headless run (`defenseclaw substrate run --task`): the
// connector's headless command with the task text, unattended, so every
// hook fails closed (D8). It runs on its own: a launcher that disconnects
// (--detach) leaves it running and follows it again later.

// TaskRequest starts a task.
type TaskRequest struct {
	Prompt string   `json:"prompt"`
	Args   []string `json:"args,omitempty"`
}

// TaskEvent is one NDJSON line of a task's log.
type TaskEvent struct {
	Type string `json:"type"` // start, stdout, stderr, exit, error
	Data string `json:"data,omitempty"`
	Code *int   `json:"code,omitempty"`
	ID   string `json:"id,omitempty"`
	TS   string `json:"ts"`
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

// RunHeadless runs the connector's headless command for prompt, writes each
// TaskEvent to emit and returns the exit code. It marks the actor unattended
// and pre-connects the hook helper first.
func RunHeadless(ctx context.Context, cfg kit.Config, req TaskRequest, setUnattended func(context.Context) error,
	warm func(context.Context, string) error, emit func(TaskEvent)) int {
	argv, err := expandHeadless(cfg.Relay.Headless, req.Prompt)
	if err != nil {
		emit(TaskEvent{Type: "error", Data: err.Error()})
		return 2
	}
	// Unattended before anything runs: a hook must never see an
	// interactive fail mode during a task.
	if err := setUnattended(ctx); err != nil {
		emit(TaskEvent{Type: "error", Data: "the hook helper could not be marked unattended: " + err.Error()})
		return 2
	}
	if c := cfg.Relay.Connector; c != "" {
		wctx, cancel := context.WithTimeout(ctx, warmBudget)
		if err := warm(wctx, c); err != nil {
			emit(TaskEvent{Type: "stderr", Data: "defenseclaw: the gateway did not answer the pre-connect: " + err.Error()})
		}
		cancel()
	}
	argv = append(argv, req.Args...)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = cfg.Relay.Workdir
	cmd.Env = append(os.Environ(), kit.ModeEnv+"="+kit.ModeUnattend)
	for k, v := range cfg.Relay.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	cmd.Stdin = nil
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		emit(TaskEvent{Type: "error", Data: err.Error()})
		return 127
	}
	var wg sync.WaitGroup
	pump := func(kind string, r io.Reader) {
		defer wg.Done()
		sc := bufio.NewScanner(r)
		sc.Buffer(make([]byte, 64<<10), 4<<20)
		for sc.Scan() {
			emit(TaskEvent{Type: kind, Data: sc.Text()})
		}
	}
	wg.Add(2)
	go pump("stdout", stdout)
	go pump("stderr", stderr)
	wg.Wait()
	err = cmd.Wait()
	code := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else {
			code = 1
		}
	}
	return code
}

func (s *Server) taskStart(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "task")
	if !ok {
		return
	}
	var req TaskRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil || req.Prompt == "" {
		http.Error(w, "relay: a task needs a prompt", http.StatusBadRequest)
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
		code := RunHeadless(context.Background(), s.opts.Config, req, s.opts.SetUnattended, s.opts.Warm, t.emit)
		t.mu.Lock()
		t.code = &code
		t.mu.Unlock()
		t.emit(TaskEvent{Type: "exit", Code: &code})
		t.log.Close()
	}()
	s.follow(w, r, t, 0)
}

func (s *Server) taskFollow(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.auth(w, r, "task-follow")
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
