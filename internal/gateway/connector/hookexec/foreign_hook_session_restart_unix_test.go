//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func standaloneExchangeOptions(socket string, startedAt time.Time) Options {
	return Options{
		Connector:         "claudecode",
		ManagedEnterprise: true,
		ManagedStandalone: true,
		ManagedUnixSocket: socket,
		ManagedServiceUID: os.Getuid(),
		StartedAt:         startedAt,
	}
}

// #1278: a gateway that binds its own hook socket (macOS) has none for a
// moment while it restarts. The foreign-hook session exchange, the first
// gateway call of a guarded hook, waits for the socket within the restart
// budget instead of failing closed at once, and talks to it once it is
// there (its listener checked like any other).
func TestForeignHookSessionExchangeWaitsForTheHookSocketOfARestartingGateway(t *testing.T) {
	fastRestartRetries(t)
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	listening := make(chan error, 1)
	var server *http.Server
	go func() {
		time.Sleep(300 * time.Millisecond)
		listener, err := net.Listen("unix", socket)
		if err != nil {
			listening <- err
			return
		}
		server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			_, _ = io.WriteString(w, `{"deny":false}`)
		})}
		listening <- nil
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		if server != nil {
			_ = server.Close()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	response, err := ExchangeForeignHookSession(ctx, standaloneExchangeOptions(socket, time.Now()), "claudecode", []byte(`{}`))
	if listenErr := <-listening; listenErr != nil {
		t.Fatal(listenErr)
	}
	if err != nil || string(response) != `{"deny":false}` {
		t.Fatalf("exchange = %q, error %v; want the answer of the gateway that started", response, err)
	}
}

// A socket that is still missing at the end of the restart budget, counted
// from the hook invocation, ends the exchange with the not-running error,
// which the guard turns into a block.
func TestForeignHookSessionExchangeFailsClosedWhenTheHookSocketStaysMissing(t *testing.T) {
	fastRestartRetries(t)
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	invocation := started.Add(-gatewayRestartBudget + 200*time.Millisecond)
	_, err := ExchangeForeignHookSession(ctx, standaloneExchangeOptions(socket, invocation), "claudecode", []byte(`{}`))
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the exchange waited %s past the restart budget of the invocation", elapsed)
	}
	if !ManagedGatewayNotRunning(err) {
		t.Fatalf("error = %v, want the not-running error", err)
	}
}

// B-01 review item 2: a gateway that accepted the foreign-hook session
// exchange of a tool call but does not answer (stopping, starting, busy) ends
// the exchange at the hook's answer budget, counted from the invocation, not
// at the exchange's own deadline (up to twice the scan budget, 10 s). The
// guard then denies. A session event keeps the exchange's whole deadline.
func TestStalledForeignHookSessionExchangeEndsAtTheAnswerBudget(t *testing.T) {
	shortAnswerBudget(t, 400*time.Millisecond)
	previousProbe := standaloneGatewayServiceProbe
	standaloneGatewayServiceProbe = func(context.Context) (gatewayServiceState, error) {
		return gatewayServiceState{Active: "active", Sub: "running"}, nil
	}
	t.Cleanup(func() { standaloneGatewayServiceProbe = previousProbe })
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, `{"deny":false}`)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { close(release); _ = server.Close() })

	opts := standaloneExchangeOptions(socket, time.Now())
	opts.Event = "PreToolUse"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	response, err := ExchangeForeignHookSession(ctx, opts, "claudecode", []byte(`{}`))
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the stalled exchange of a tool call waited %s", elapsed)
	}
	if err == nil || response != nil || !ManagedGatewayNoAnswer(err) {
		t.Fatalf("exchange = %q, error %v; want no answer and the no-answer cause", response, err)
	}

	// A session start is not a tool call: it keeps the exchange deadline.
	opts = standaloneExchangeOptions(socket, time.Now())
	opts.Event = "SessionStart"
	short, cancelShort := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancelShort()
	if _, err := ExchangeForeignHookSession(short, opts, "claudecode", []byte(`{}`)); err == nil || ManagedGatewayNoAnswer(err) {
		t.Fatalf("a session-start exchange ended with %v; want its own deadline, not the answer budget", err)
	}
}

// #1278: on Linux systemd holds the hook socket across a restart, so the
// exchange connects and waits for an answer no gateway gives yet. It ends
// at the restart budget of the invocation, with the restart named, not at
// the exchange's own deadline (up to twice the scan budget, 10 s).
func TestQueuedForeignHookSessionExchangeEndsAtTheRestartBudget(t *testing.T) {
	previousProbe, previousInterval := standaloneGatewayServiceProbe, gatewayStartWatchInterval
	standaloneGatewayServiceProbe = func(context.Context) (gatewayServiceState, error) {
		return gatewayServiceState{Active: "deactivating", Sub: "stop-sigterm"}, nil
	}
	gatewayStartWatchInterval = 5 * time.Millisecond
	t.Cleanup(func() { standaloneGatewayServiceProbe, gatewayStartWatchInterval = previousProbe, previousInterval })
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	// A listener that never accepts: the call waits in its backlog, as in
	// the socket systemd keeps while the service is stopping.
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	invocation := started.Add(-gatewayRestartBudget + 300*time.Millisecond)
	response, err := ExchangeForeignHookSession(ctx, standaloneExchangeOptions(socket, invocation), "claudecode", []byte(`{}`))
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the queued exchange waited %s", elapsed)
	}
	if err == nil || response != nil || !ManagedGatewayRestarting(err) {
		t.Fatalf("exchange = %q, error %v; want no answer and the restart named", response, err)
	}
}

// B-40: a gateway that sent the exchange's headers and part of its body,
// then stalled, is cut off at the answer budget like one that sends no
// headers; the guard then denies.
func TestForeignHookSessionExchangeBodyStallEndsAtTheAnswerBudget(t *testing.T) {
	shortAnswerBudget(t, 400*time.Millisecond)
	previousProbe := standaloneGatewayServiceProbe
	standaloneGatewayServiceProbe = func(context.Context) (gatewayServiceState, error) {
		return gatewayServiceState{Active: "active", Sub: "running"}, nil
	}
	t.Cleanup(func() { standaloneGatewayServiceProbe = previousProbe })
	socket := filepath.Join(shortSocketDir(t), "hook.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Length", "64")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"deny":false}`)
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { close(release); _ = server.Close() })

	opts := standaloneExchangeOptions(socket, time.Now())
	opts.Event = "PreToolUse"
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	response, err := ExchangeForeignHookSession(ctx, opts, "claudecode", []byte(`{}`))
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the exchange whose body stalled waited %s", elapsed)
	}
	if err == nil || response != nil || !ManagedGatewayNoAnswer(err) {
		t.Fatalf("exchange = %q, error %v; want no answer and the no-answer cause", response, err)
	}
}
