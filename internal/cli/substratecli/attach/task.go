// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package attach

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// TaskOptions configure RunTask.
type TaskOptions struct {
	Options
	Prompt string
	Args   []string
	// Emit sees every task event (default: stdout lines to Out, stderr and
	// error lines to Err).
	Emit func(relay.TaskEvent)
}

// TextEmitter prints a task's output: stdout lines to out, stderr and
// error lines to errw.
func TextEmitter(out, errw io.Writer) func(relay.TaskEvent) {
	return func(e relay.TaskEvent) {
		switch e.Type {
		case "stdout":
			fmt.Fprintln(out, e.Data)
		case "stderr":
			fmt.Fprintln(errw, e.Data)
		case "error":
			fmt.Fprintln(errw, "error: "+e.Data)
		}
	}
}

// RunTask starts a headless task in the actor (POST /dcrelay/1/task through
// the tunnel) and streams its events to Emit until the agent exits. When
// the stream drops it follows the task again from where it stopped
// (GET /dcrelay/1/task/{id}), so no event is lost or repeated. It returns
// the agent's exit code.
func RunTask(ctx context.Context, o TaskOptions) (int, error) {
	if strings.TrimSpace(o.Prompt) == "" {
		return -1, errors.New("a task needs a prompt")
	}
	if len(o.Args) > 0 {
		// The relay runs the template's headless command with the
		// registered task text only (GAP-0071).
		return -1, errors.New("a task takes no extra agent arguments: the template's headless command runs with the task text")
	}
	if err := o.Options.normalize(); err != nil {
		return -1, err
	}
	l := newLink(o.Options)
	defer l.close()
	emit := o.Emit
	if emit == nil {
		emit = TextEmitter(o.Out, o.Err)
	}
	var id string
	var cursor uint64
	track := func(e relay.TaskEvent) {
		if e.Type == "start" && e.ID != "" {
			id = e.ID
		}
		// The relay's task log is a stream of length-prefixed NDJSON lines;
		// the cursor is the byte offset after this event.
		b, _ := json.Marshal(e)
		cursor += uint64(4 + len(b) + 1)
		emit(e)
	}
	park := l.newParker()
	rec := newRetry(o.Backoff)
	force, unauthorized, failures := false, 0, 0
	for {
		g, err := l.grant(ctx, force)
		force = false
		if err != nil {
			var fe *fatalError
			if errors.As(err, &fe) || ctx.Err() != nil {
				return -1, ctxErr(ctx, unwrapFatal(err))
			}
		} else {
			code, rerr := relay.RunTask(ctx, l.tun.HTTPClient(), l.tun.BaseURL(), g.Token,
				relay.TaskRequest{Prompt: o.Prompt}, track)
			if rerr == nil {
				return code, nil
			}
			err = rerr
		}
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		if id != "" {
			return l.follow(ctx, id, cursor, emit)
		}
		var te *TunnelError
		if errors.As(err, &te) && !te.transient() {
			if te.Kind != ErrClusterFull {
				return -1, te
			}
			if werr := park.wait(ctx, te.RetryAfter); werr != nil {
				return -1, werr
			}
			continue
		}
		var de *dialError
		if errors.As(err, &de) && de.fatal {
			return -1, de
		}
		switch relayStatus(err) {
		case 503, 429:
			if werr := park.wait(ctx, 0); werr != nil {
				return -1, werr
			}
			continue
		case 401:
			if unauthorized++; unauthorized > 1 {
				return -1, tokenRefused(o.Target)
			}
			force = true
			continue
		case 403:
			return -1, statusError(403, nil, o.Target)
		case 404:
			return -1, statusError(404, nil, o.Target)
		case 409:
			return -1, fmt.Errorf("a task is already running in %s; follow it with: defenseclaw substrate logs %s -f", o.Target.Name, o.Target.Name)
		case 0:
		default:
			return -1, err
		}
		if failures++; failures >= o.Backoff.MaxAttempts {
			return -1, fmt.Errorf("could not start the task in %s after %d tries: %w", o.Target.Name, failures, err)
		}
		if serr := o.Sleep(ctx, rec.next()); serr != nil {
			return -1, ctxErr(ctx, serr)
		}
	}
}

func unwrapFatal(err error) error {
	var fe *fatalError
	if errors.As(err, &fe) {
		return fe.err
	}
	return err
}

// FollowTask streams a task's events from its start (`logs -f`) until it
// exits, reconnecting when the stream drops, and returns its exit code.
func FollowTask(ctx context.Context, o Options, id string, emit func(relay.TaskEvent)) (int, error) {
	if strings.TrimSpace(id) == "" {
		return -1, errors.New("no task id")
	}
	if err := o.normalize(); err != nil {
		return -1, err
	}
	l := newLink(o)
	defer l.close()
	if emit == nil {
		emit = TextEmitter(o.Out, o.Err)
	}
	return l.follow(ctx, id, 0, emit)
}

func (l *link) follow(ctx context.Context, id string, cursor uint64, emit func(relay.TaskEvent)) (int, error) {
	o := l.o
	rec := newRetry(o.Backoff)
	failures := 0
	for {
		resp, err := l.get(ctx, "/dcrelay/1/task/"+url.PathEscape(id)+"?cursor="+strconv.FormatUint(cursor, 10))
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return -1, ctx.Err()
			}
			if isFatal(err) {
				return -1, unwrapFatal(err)
			}
		case resp.StatusCode == http.StatusNotFound:
			resp.Body.Close()
			return -1, fmt.Errorf("no task %s in %s (it is not yours, or the actor started over)", id, o.Target.Name)
		case resp.StatusCode != http.StatusOK:
			err = responseError(resp, o.Target)
			resp.Body.Close()
			return -1, err
		default:
			progressed := false
			br := bufio.NewReaderSize(resp.Body, 64<<10)
			for {
				line, rerr := br.ReadBytes('\n')
				if len(line) > 0 && line[len(line)-1] == '\n' {
					cursor += uint64(4 + len(line))
					progressed = true
					var e relay.TaskEvent
					if json.Unmarshal(line, &e) == nil {
						emit(e)
						if e.Type == "exit" && e.Code != nil {
							resp.Body.Close()
							return *e.Code, nil
						}
					}
				}
				if rerr != nil {
					break
				}
			}
			resp.Body.Close()
			if progressed {
				rec.reset()
				failures = 0
			}
		}
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		if failures++; failures >= o.Backoff.MaxAttempts {
			return -1, fmt.Errorf("lost the task log of %s; the task keeps running. Follow it with: defenseclaw substrate logs %s -f", o.Target.Name, o.Target.Name)
		}
		if serr := o.Sleep(ctx, rec.next()); serr != nil {
			return -1, ctxErr(ctx, serr)
		}
	}
}

func isFatal(err error) bool {
	var fe *fatalError
	if errors.As(err, &fe) {
		return true
	}
	var te *TunnelError
	if errors.As(err, &te) {
		return te.Kind != ErrClusterFull && !te.transient()
	}
	var de *dialError
	return errors.As(err, &de) && de.fatal
}

// get sends an authenticated GET through the tunnel, waiting while the
// cluster is full and renewing a refused session token once. Any other
// answer is the caller's.
func (l *link) get(ctx context.Context, path string) (*http.Response, error) {
	park := l.newParker()
	force, unauthorized := false, 0
	for {
		g, err := l.grant(ctx, force)
		force = false
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.tun.BaseURL()+path, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+g.Token)
		resp, err := l.tun.HTTPClient().Do(req)
		if err != nil {
			var te *TunnelError
			if errors.As(err, &te) {
				if te.transient() {
					return nil, te
				}
				if te.Kind != ErrClusterFull {
					return nil, &fatalError{te}
				}
				if werr := park.wait(ctx, te.RetryAfter); werr != nil {
					return nil, &fatalError{werr}
				}
				continue
			}
			var de *dialError
			if errors.As(err, &de) {
				if de.fatal {
					return nil, &fatalError{de}
				}
				return nil, de
			}
			return nil, fmt.Errorf("could not reach the agent %s: %w", l.o.Target.Name, err)
		}
		switch resp.StatusCode {
		case http.StatusServiceUnavailable, http.StatusTooManyRequests:
			ra := parseRetryAfter(resp.Header.Get("Retry-After"), l.o.Now())
			drain(resp)
			if werr := park.wait(ctx, ra); werr != nil {
				return nil, &fatalError{werr}
			}
			continue
		case http.StatusUnauthorized:
			drain(resp)
			if unauthorized++; unauthorized > 1 {
				return nil, &fatalError{tokenRefused(l.o.Target)}
			}
			force = true
			continue
		case http.StatusForbidden:
			drain(resp)
			return nil, &fatalError{statusError(403, nil, l.o.Target)}
		}
		park.reset()
		return resp, nil
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// responseError describes an unexpected answer. The relay's error bodies
// are short plain text ("relay: ...") and carry no credentials.
func responseError(resp *http.Response, t Target) error {
	if resp.StatusCode == http.StatusNotFound {
		return statusError(404, nil, t)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := clean(strings.SplitN(string(b), "\n", 2)[0])
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("the agent %s answered %d: %s", t.Name, resp.StatusCode, msg)
}

// Status reads the relay's status (GET /dcrelay/1/status) through the
// tunnel: the session, whether the agent runs, the last pre-connect time
// and the tasks.
func Status(ctx context.Context, o Options) (map[string]any, error) {
	if err := o.normalize(); err != nil {
		return nil, err
	}
	l := newLink(o)
	defer l.close()
	resp, err := l.get(ctx, "/dcrelay/1/status")
	if err != nil {
		return nil, ctxErr(ctx, unwrapFatal(err))
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, responseError(resp, o.Target)
	}
	var m map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m); err != nil {
		return nil, fmt.Errorf("the agent %s sent a status that is not JSON", o.Target.Name)
	}
	return m, nil
}
