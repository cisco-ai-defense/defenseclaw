// Package localcontent provides a bounded local JSONL content scanner transport.
// SPDX-License-Identifier: Apache-2.0
package localcontent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

const MaxContentBytes = 256 * 1024

var ErrBusy = errors.New("local content scanner busy")
var ErrUnavailable = errors.New("local content scanner unavailable")
var ErrRefused = errors.New("local content request refused")

type Worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	gate   chan struct{}
	closed atomic.Bool
	once   sync.Once
	budget time.Duration
}

// Start loads one trusted, explicitly selected executable before serving requests.
// Context bounds startup only. Request cancellation kills and poisons the worker:
// a late reply can never become the next request's verdict.
func Start(ctx context.Context, executable string, args []string, budget time.Duration) (*Worker, error) {
	return StartConfigured(ctx, executable, args, budget, nil)
}

// StartConfigured sends trusted settings before awaiting the readiness handshake.
func StartConfigured(ctx context.Context, executable string, args []string, budget time.Duration, settings any) (*Worker, error) {
	if !filepath.IsAbs(executable) || budget <= 0 || budget > 5*time.Second {
		return nil, ErrUnavailable
	}
	cmd := exec.Command(executable, args...)
	cmd.Env = []string{"HF_HUB_OFFLINE=1", "TOKENIZERS_PARALLELISM=false", "PYTHONNOUSERSITE=1"}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	// Discard stderr: model paths and runtime diagnostics must not reach tool replies.
	cmd.Stderr = io.Discard
	w := &Worker{cmd: cmd, stdin: stdin, reader: bufio.NewReaderSize(stdout, 64*1024), gate: make(chan struct{}, 1), budget: budget}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() {
		if settings != nil {
			if e := json.NewEncoder(w.stdin).Encode(settings); e != nil {
				done <- e
				return
			}
		}
		line, e := w.line()
		var reply struct {
			Ready bool `json:"ready"`
		}
		if e == nil {
			e = json.Unmarshal(line, &reply)
			if !reply.Ready {
				e = ErrUnavailable
			}
		}
		done <- e
	}()
	select {
	case err := <-done:
		if err != nil {
			w.Close()
			return nil, ErrUnavailable
		}
		return w, nil
	case <-ctx.Done():
		w.Close()
		<-done
		return nil, ctx.Err()
	}
}

func (w *Worker) line() ([]byte, error) {
	line, err := w.reader.ReadSlice('\n')
	if err != nil {
		return nil, err
	}
	return line, nil
}

func (w *Worker) Close() error {
	w.once.Do(func() { w.closed.Store(true); _ = w.cmd.Process.Kill(); _ = w.stdin.Close(); _ = w.cmd.Wait() })
	return nil
}

func (w *Worker) Scan(ctx context.Context, text string) (float64, error) {
	if len(text) > MaxContentBytes {
		return 0, fmt.Errorf("local content size limit")
	}
	select {
	case w.gate <- struct{}{}:
		defer func() { <-w.gate }()
	default:
		return 0, ErrBusy
	}
	if w.closed.Load() {
		return 0, ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, w.budget)
	defer cancel()
	body, err := json.Marshal(map[string]string{"tool": "tool-response", "output": text})
	if err != nil {
		return 0, ErrUnavailable
	}
	type response struct {
		score float64
		err   error
	}
	done := make(chan response, 1)
	go func() {
		if _, err := w.stdin.Write(append(body, '\n')); err != nil {
			done <- response{err: ErrUnavailable}
			return
		}
		line, err := w.line()
		if err != nil {
			done <- response{err: ErrUnavailable}
			return
		}
		var reply struct {
			Reason string `json:"reason"`
			Wolf   struct {
				Status   string   `json:"status"`
				Score    *float64 `json:"score"`
				Complete bool     `json:"complete"`
			} `json:"wolf"`
		}
		parseErr := json.Unmarshal(line, &reply)
		if parseErr == nil && reply.Wolf.Status == "error" && (reply.Reason == "wolf:token_limit" || reply.Reason == "wolf:window_limit" || reply.Reason == "wolf:byte_limit") {
			done <- response{err: ErrRefused}
			return
		}
		if parseErr != nil || reply.Wolf.Status != "scored" || !reply.Wolf.Complete || reply.Wolf.Score == nil {
			done <- response{err: ErrUnavailable}
			return
		}
		v := *reply.Wolf.Score
		if math.IsNaN(v) || math.IsInf(v, 0) || v < 0 || v > 1 {
			done <- response{err: ErrUnavailable}
			return
		}
		done <- response{score: v}
	}()
	select {
	case r := <-done:
		if r.err != nil && !errors.Is(r.err, ErrRefused) {
			w.Close()
		}
		return r.score, r.err
	case <-ctx.Done():
		w.Close()
		<-done
		return 0, ctx.Err()
	}
}
