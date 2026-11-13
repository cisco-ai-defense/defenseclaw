// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"golang.org/x/sys/windows"
)

const (
	maximumClients  = 16
	shutdownTimeout = 10 * time.Second
)

// Server is the guardian end: LocalSystem, one pipe whose DACL lets only
// SYSTEM and the gateway service SID connect, every client authenticated
// by its token (the gateway service SID) and SCM PID, one bounded
// request per connection.
type Server struct {
	names  Names
	verify Verifier
	log    func(Event)
}

// NewServer builds the broker for gatewayService; the process must run as
// LocalSystem.
func NewServer(gatewayService string, log func(Event)) (*Server, error) {
	names, err := NamesFor(gatewayService)
	if err != nil {
		return nil, err
	}
	if err := requireLocalSystem(); err != nil {
		return nil, err
	}
	return &Server{names: names, verify: peercred.VerifyLoopbackTCPPeer, log: log}, nil
}

// Serve answers until ctx ends. The first pipe instance is created with
// FILE_FLAG_FIRST_PIPE_INSTANCE, so a pipe another process created first
// is an error (the guardian retries; the gateway refuses meanwhile).
func (s *Server) Serve(ctx context.Context, ready chan<- struct{}) error {
	security, err := cmidbroker.NewGatewayPipeSecurity(s.names.Gateway)
	if err != nil {
		return err
	}
	semaphore := make(chan struct{}, maximumClients)
	var active sync.WaitGroup
	first := true
	for {
		select {
		case <-ctx.Done():
			return waitActive(&active)
		case semaphore <- struct{}{}:
		}
		pipe, err := cmidbroker.CreateGatewayServerPipe(s.names.Pipe, security, first)
		if err != nil {
			<-semaphore
			_ = waitActive(&active)
			return fmt.Errorf("create peer broker pipe: %w", err)
		}
		if first {
			first = false
			if ready != nil {
				close(ready)
			}
		}
		if err := cmidbroker.ConnectServerPipe(ctx, pipe); err != nil {
			_ = windows.CloseHandle(pipe)
			<-semaphore
			if ctx.Err() != nil {
				return waitActive(&active)
			}
			continue
		}
		clientPID, err := cmidbroker.AuthenticateGatewayPipeClient(pipe, s.names.Gateway)
		if err != nil {
			_ = windows.DisconnectNamedPipe(pipe)
			_ = windows.CloseHandle(pipe)
			<-semaphore
			s.emit(Event{Stage: "client-auth", Outcome: "refused", ClientPID: clientPID})
			continue
		}
		active.Add(1)
		go func(handle windows.Handle, pid uint32) {
			defer active.Done()
			defer func() { <-semaphore }()
			defer windows.CloseHandle(handle)
			defer windows.DisconnectNamedPipe(handle)
			defer cmidbroker.FlushPipeBounded(handle, OperationTimeout)
			s.handle(ctx, handle, pid)
		}(pipe, clientPID)
	}
}

func (s *Server) handle(ctx context.Context, pipe windows.Handle, clientPID uint32) {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, OperationTimeout)
	defer cancel()
	buffer := make([]byte, MaxMessageBytes+1)
	count, err := cmidbroker.ReadPipeMessage(ctx, pipe, buffer)
	if err != nil || count == 0 || count > MaxMessageBytes {
		s.emit(Event{Stage: "read", Outcome: "failed", ClientPID: clientPID, Duration: time.Since(started)})
		return
	}
	response, outcome := Answer(buffer[:count], clientPID, s.verify)
	if _, err := cmidbroker.WritePipeMessage(ctx, pipe, response); err != nil {
		outcome = "write_failed"
	}
	s.emit(Event{Stage: "answer", Outcome: outcome, ClientPID: clientPID, Duration: time.Since(started)})
}

func (s *Server) emit(event Event) {
	if s.log != nil {
		s.log(event)
	}
}

func waitActive(active *sync.WaitGroup) error {
	done := make(chan struct{})
	go func() {
		active.Wait()
		close(done)
	}()
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return errors.New("peer broker shutdown timed out")
	}
}

func requireLocalSystem() error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		return errors.New("peer broker must run as LocalSystem")
	}
	return nil
}
