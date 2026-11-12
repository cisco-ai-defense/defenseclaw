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

	"github.com/defenseclaw/defenseclaw/internal/cli/substratecli/safetext"
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
// error lines to errw. The agent wrote them, so they are printed without
// terminal controls (safetext.Clean: no clipboard, title, hyperlink or
// cursor movement).
func TextEmitter(out, errw io.Writer) func(relay.TaskEvent) {
	return func(e relay.TaskEvent) {
		switch e.Type {
		case "stdout":
			fmt.Fprintln(out, safetext.Clean(e.Data))
		case "stderr":
			fmt.Fprintln(errw, safetext.Clean(e.Data))
		case "error":
			fmt.Fprintln(errw, "error: "+safetext.Line(e.Data))
		}
	}
}

// RunTask starts a headless task in the actor (POST /dcrelay/1/task through
// the attach route) and streams its events to Emit until the agent exits. When
// the stream drops it follows the task again from where it stopped
// (GET /dcrelay/1/task/{id}), so no event is lost or repeated. It returns
// the agent's exit code.
func RunTask(ctx context.Context, o TaskOptions) (int, error) {
	if strings.TrimSpace(o.Prompt) == "" {
		return -1, errors.New("a task needs a prompt")
	}
	if err := o.normalize(); err != nil {
		return -1, err
	}
	l, err := newLink(ctx, o.Options)
	if err != nil {
		return -1, err
	}
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
	failures := 0
	for {
		// The client puts the person's bearer on the request; the token
		// argument is not used for it.
		code, err := relay.RunTask(ctx, l.tun.HTTPClient(), l.tun.BaseURL(), "",
			relay.TaskRequest{Prompt: o.Prompt, Args: o.Args}, track)
		if err == nil {
			return code, nil
		}
		if ctx.Err() != nil {
			return -1, ctx.Err()
		}
		if id != "" {
			return l.follow(ctx, id, cursor, emit)
		}
		st := relayStatus(err)
		if st == http.StatusConflict {
			return -1, fmt.Errorf("a task is already running in %s; follow it with: defenseclaw substrate logs %s -f", o.Target.Name, o.Target.Name)
		}
		k, kerr := l.judge(err)
		switch {
		case k == outFatal:
			return -1, kerr
		case k == outWait:
			var re *RouteError
			errors.As(kerr, &re)
			if werr := park.wait(ctx, re); werr != nil {
				return -1, werr
			}
			continue
		case st != 0:
			// Another answer of the relay (a bad request, a server error).
			return -1, kerr
		}
		if failures++; failures >= o.Backoff.MaxAttempts {
			return -1, fmt.Errorf("could not start the task in %s after %d tries: %w", o.Target.Name, failures, kerr)
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
	l, err := newLink(ctx, o)
	if err != nil {
		return -1, err
	}
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
			fromRoute := routeAnswer(resp)
			resp.Body.Close()
			if fromRoute {
				return -1, routeError(http.StatusNotFound, nil, o.Target)
			}
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
	return errors.As(err, &fe)
}

// get sends a GET through the attach route, waiting while the cluster is
// full or the agent is starting. A refusal is fatal; any other answer is the
// caller's.
func (l *link) get(ctx context.Context, path string) (*http.Response, error) {
	park := l.newParker()
	for {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.tun.BaseURL()+path, nil)
		if err != nil {
			return nil, err
		}
		resp, err := l.tun.HTTPClient().Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			k, kerr := l.judge(err)
			if k == outFatal {
				return nil, &fatalError{kerr}
			}
			var be *bearerError
			var de *dialError
			if errors.As(kerr, &be) || errors.As(kerr, &de) {
				return nil, kerr
			}
			return nil, fmt.Errorf("could not reach the agent %s: %w", l.o.Target.Name, kerr)
		}
		switch resp.StatusCode {
		case http.StatusServiceUnavailable, http.StatusTooManyRequests, http.StatusBadGateway, http.StatusGatewayTimeout:
			re := routeError(resp.StatusCode, resp.Header, l.o.Target)
			drain(resp)
			if werr := park.wait(ctx, re); werr != nil {
				return nil, &fatalError{werr}
			}
			continue
		case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotImplemented:
			drain(resp)
			return nil, &fatalError{routeError(resp.StatusCode, nil, l.o.Target)}
		}
		park.reset()
		return resp, nil
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
}

// routeAnswer reports whether a response is an error of the gateway's
// route (a JSON {"error","reason"} body) rather than of the relay, whose
// error bodies are plain text. It reads the body.
func routeAnswer(resp *http.Response) bool {
	var e struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return json.Unmarshal(b, &e) == nil && (e.Error != "" || e.Reason != "")
}

// responseError describes an unexpected answer. The relay's error bodies
// are short plain text ("relay: ...") and the gateway's are JSON; neither
// carries credentials.
func responseError(resp *http.Response, t Target) error {
	if resp.StatusCode == http.StatusNotFound {
		return routeError(http.StatusNotFound, nil, t)
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	msg := safetext.Line(strings.SplitN(string(b), "\n", 2)[0])
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("the agent %s answered %d: %s", t.Name, resp.StatusCode, msg)
}

// Status reads the relay's status (GET /dcrelay/1/status) through the
// attach route: the session, whether the agent runs, the last pre-connect time
// and the tasks.
func Status(ctx context.Context, o Options) (map[string]any, error) {
	if err := o.normalize(); err != nil {
		return nil, err
	}
	l, err := newLink(ctx, o)
	if err != nil {
		return nil, err
	}
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
