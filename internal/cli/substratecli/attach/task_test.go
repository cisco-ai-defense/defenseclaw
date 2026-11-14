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
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/relay"
)

// tokenVerifier accepts the test session token (the real relay's KeyVerifier
// is tested in the relay package).
type tokenVerifier struct{}

var tokenSeq atomic.Int64

// testTask is the task text the test sessions are registered for.
const testTask = "fix it"

func (tokenVerifier) Verify(_ context.Context, r *http.Request) (relay.Session, error) {
	if relay.TokenFrom(r) != testToken {
		return relay.Session{}, errors.New("unknown token")
	}
	// Each request stands for a new session token (a token opens one task),
	// bound to the task text the tests run (GAP-0070, GAP-0071).
	return relay.Session{Person: "alice@example.test", Actor: testTarget.String(), ActorUID: "uid-1",
		TokenID: fmt.Sprintf("jti-%d", tokenSeq.Add(1)), TaskDigest: relay.TaskDigest(testTask)}, nil
}

// realRelay is the relay's own handler, with a headless command that
// prints, waits and exits 3.
func realRelay(t *testing.T) http.Handler {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the relay runs in Linux actors")
	}
	cfg := kit.DefaultConfig()
	cfg.Relay.Headless = []string{"sh", "-c", "echo one; sleep 1; echo two:$0; exit 3", "{prompt}"}
	s := relay.NewServer(relay.Options{Config: cfg, Verifier: tokenVerifier{},
		Log:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		Warm: func(context.Context, string) error { return nil },
	})
	return s.Handler()
}

type eventLog struct {
	mu     sync.Mutex
	events []relay.TaskEvent
}

func (l *eventLog) add(e relay.TaskEvent) {
	l.mu.Lock()
	l.events = append(l.events, e)
	l.mu.Unlock()
}

func (l *eventLog) summary() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var s []string
	for _, e := range l.events {
		s = append(s, e.Type+":"+e.Data)
	}
	return strings.Join(s, "|")
}

func TestRunTaskFollowsAfterDrop(t *testing.T) {
	r := newRig(t, realRelay(t))
	log := &eventLog{}
	var once sync.Once
	var id string
	o := TaskOptions{Options: r.options(), Prompt: "fix it", Emit: func(e relay.TaskEvent) {
		log.add(e)
		if e.Type == "start" {
			id = e.ID
		}
		if e.Type == "stdout" && e.Data == "one" {
			// The network drops in the middle of the task.
			once.Do(r.admin.srv.CloseClientConnections)
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	code, err := RunTask(ctx, o)
	if err != nil || code != 3 {
		t.Fatalf("code %d err %v (events %s)", code, err, log.summary())
	}
	if got, want := log.summary(), "start:|stdout:one|stdout:two:fix it|exit:"; got != want {
		t.Fatalf("events %q, want %q (each once, in order)", got, want)
	}
	if n := r.admin.count(isTaskRoute); n < 2 {
		t.Fatalf("the stream was not followed again: %d task requests", n)
	}
	// logs -f later replays the whole task.
	replay := &eventLog{}
	code, err = FollowTask(ctx, r.options(), id, replay.add)
	if err != nil || code != 3 || replay.summary() != log.summary() {
		t.Fatalf("follow: %d %v %q", code, err, replay.summary())
	}
	if _, err := FollowTask(ctx, r.options(), "nope", replay.add); err == nil || !strings.Contains(err.Error(), "no task nope") {
		t.Fatalf("unknown task: %v", err)
	}
}

func TestStatusThroughRoute(t *testing.T) {
	r := newRig(t, realRelay(t))
	m, err := Status(context.Background(), r.options())
	if err != nil {
		t.Fatal(err)
	}
	if m["version"] != relay.Version || m["session"] == "" {
		t.Fatalf("status %v", m)
	}
}

func TestRunTaskWaitsWhileFull(t *testing.T) {
	r := newRig(t, realRelay(t))
	var mu sync.Mutex
	tasks := 0
	r.admin.setAnswer(func(rq *http.Request) (int, http.Header) {
		mu.Lock()
		defer mu.Unlock()
		if rq.Method == http.MethodPost && strings.HasSuffix(rq.URL.Path, "/attach/task") {
			if tasks++; tasks == 1 {
				return 503, http.Header{"Retry-After": {"2"}}
			}
		}
		return 0, nil
	})
	code, err := RunTask(context.Background(), TaskOptions{Options: r.options(), Prompt: testTask, Emit: func(relay.TaskEvent) {}})
	if err != nil || code != 3 {
		t.Fatalf("%d %v", code, err)
	}
	if !strings.Contains(r.errb.String(), fullMsg) {
		t.Fatalf("stderr %q", r.errb.String())
	}
	if sl := r.clock.slept(); len(sl) != 1 || sl[0] < 2*time.Second {
		t.Fatalf("sleeps %v (Retry-After 2 not honoured)", sl)
	}
	if _, err := RunTask(context.Background(), TaskOptions{Options: r.options()}); err == nil {
		t.Fatal("a task without a prompt was sent")
	}
}

func TestTaskRefusals(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   string
	}{
		{401, "run: defenseclaw substrate login"},
		{403, "you are not allowed to attach to a6-test/cc-1"},
		{404, "no agent a6-test/cc-1 of yours"},
		{501, "ask your administrator to upgrade DefenseClaw"},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			r := newRig(t, nil)
			r.admin.setAnswer(func(*http.Request) (int, http.Header) { return tc.status, nil })
			_, err := RunTask(context.Background(), TaskOptions{Options: r.options(), Prompt: testTask, Emit: func(relay.TaskEvent) {}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("run: %v", err)
			}
			_, err = Status(context.Background(), r.options())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("status: %v", err)
			}
			_, err = FollowTask(context.Background(), r.options(), "t1", func(relay.TaskEvent) {})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("follow: %v", err)
			}
			if n := r.admin.count(nil); n != 3 {
				t.Fatalf("a refusal was retried: %d requests", n)
			}
			noSecrets(t, "error", err.Error())
		})
	}
}
