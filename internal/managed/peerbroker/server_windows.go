// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"golang.org/x/sys/windows"
)

const (
	maximumClients  = 16
	shutdownTimeout = 10 * time.Second
	// busyAnswerTimeout bounds the busy refusal written from the accept
	// loop (it fits the empty outbound buffer of a fresh instance).
	busyAnswerTimeout = 100 * time.Millisecond
	// connectRetryDelay keeps a failing connect from spinning the loop.
	connectRetryDelay = 20 * time.Millisecond
)

// ErrNameHeld: the pipe name of this start is already served by another
// process (Serve returns it; the guardian restarts with a fresh name).
var ErrNameHeld = errors.New("peer broker pipe name is held by another process")

// Server is the guardian end: LocalSystem, one pipe whose DACL lets only
// SYSTEM and the gateway service SID connect, every client authenticated
// by its token (the gateway service SID) and SCM PID, one bounded request
// per connection. The pipe name is new on every Serve and published in
// <data dir>\hooks (Names.PublishedPath).
type Server struct {
	names     Names
	published string
	verify    Verifier
	log       func(Event)
	slots     int
	// Seams for the Windows tests (an ordinary account cannot make SYSTEM
	// the pipe owner or carry the gateway service SID).
	security     func() (cmidbroker.GatewayPipeSecurity, error)
	authenticate func(windows.Handle) (uint32, error)
	pipeName     func() (string, error)
}

// NewServer builds the broker for gatewayService that publishes its pipe
// name under dataDir; the process must run as LocalSystem.
func NewServer(gatewayService, dataDir string, log func(Event)) (*Server, error) {
	names, err := NamesFor(gatewayService)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("peer broker: the data dir is not set")
	}
	if err := requireLocalSystem(); err != nil {
		return nil, err
	}
	return newServer(names, names.PublishedPath(dataDir), peercred.VerifyLoopbackTCPPeer, log), nil
}

func newServer(names Names, published string, verify Verifier, log func(Event)) *Server {
	return &Server{
		names:     names,
		published: published,
		verify:    verify,
		log:       log,
		slots:     maximumClients,
		security: func() (cmidbroker.GatewayPipeSecurity, error) {
			return cmidbroker.NewGatewayPipeSecurity(names.Gateway)
		},
		authenticate: func(pipe windows.Handle) (uint32, error) {
			return cmidbroker.AuthenticateGatewayPipeClient(pipe, names.Gateway)
		},
		pipeName: names.NewPipeName,
	}
}

// Serve answers until ctx ends. The pipe name is random for this start and
// its first instance is created with FILE_FLAG_FIRST_PIPE_INSTANCE before
// the name is published, so no account can hold it first; a name that is
// held anyway (ErrNameHeld) is logged with the holder PID. While Serve runs
// the name never disappears: the next instance is created before the
// connected one is handed off, refused or closed, and a client over the
// slots gets a busy refusal instead of a blocked accept loop.
func (s *Server) Serve(ctx context.Context) error {
	security, err := s.security()
	if err != nil {
		return err
	}
	name, err := s.pipeName()
	if err != nil {
		return fmt.Errorf("choose the peer broker pipe name: %w", err)
	}
	listening, err := cmidbroker.CreateGatewayServerPipe(name, security, true)
	if err != nil {
		holder := pipeHolder(name)
		s.emit(Event{Stage: "create", Outcome: "name_held", ClientPID: holder})
		return fmt.Errorf("%w (holder pid %d): %v", ErrNameHeld, holder, err)
	}
	if err := publishPipeName(s.published, s.names, name); err != nil {
		_ = windows.CloseHandle(listening)
		return fmt.Errorf("publish the peer broker pipe name: %w", err)
	}
	defer unpublishPipeName(s.published, s.names, name)
	slots := make(chan struct{}, max(s.slots, 1))
	var active sync.WaitGroup
	for {
		connectErr := cmidbroker.ConnectServerPipe(ctx, listening)
		if ctx.Err() != nil {
			_ = windows.CloseHandle(listening)
			return waitActive(&active)
		}
		next, err := cmidbroker.CreateGatewayServerPipe(name, security, false)
		if err != nil {
			_ = windows.DisconnectNamedPipe(listening)
			_ = windows.CloseHandle(listening)
			s.emit(Event{Stage: "create", Outcome: "failed"})
			_ = waitActive(&active)
			return fmt.Errorf("create the next peer broker pipe instance: %w", err)
		}
		connected := listening
		listening = next
		if connectErr != nil {
			// A client that left before the connect completed.
			_ = windows.CloseHandle(connected)
			sleepContext(ctx, connectRetryDelay)
			continue
		}
		clientPID, err := s.authenticate(connected)
		if err != nil {
			_ = windows.DisconnectNamedPipe(connected)
			_ = windows.CloseHandle(connected)
			s.emit(Event{Stage: "client-auth", Outcome: "refused", ClientPID: clientPID})
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			refuseBusy(ctx, connected)
			s.emit(Event{Stage: "admit", Outcome: RefusedBusy, ClientPID: clientPID})
			continue
		}
		active.Add(1)
		go func(handle windows.Handle, pid uint32) {
			defer active.Done()
			defer func() { <-slots }()
			defer windows.CloseHandle(handle)
			defer windows.DisconnectNamedPipe(handle)
			defer cmidbroker.FlushPipeBounded(handle, OperationTimeout)
			s.handle(ctx, handle, pid)
		}(connected, clientPID)
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

// refuseBusy answers a client over the slots with the busy refusal and
// closes the instance without a disconnect, so the client can still read
// the answer; both are bounded and never wait for the client.
func refuseBusy(ctx context.Context, pipe windows.Handle) {
	defer windows.CloseHandle(pipe)
	message, err := encodeBounded(Response{Version: ProtocolVersion, Error: RefusedBusy})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, busyAnswerTimeout)
	defer cancel()
	_, _ = cmidbroker.WritePipeMessage(ctx, pipe, message)
}

// pipeHolder is the PID of the process serving name, 0 when it cannot be
// read. The open asks for identification only, so the holder cannot act as
// LocalSystem.
func pipeHolder(name string) uint32 {
	pointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING,
		windows.SECURITY_SQOS_PRESENT|windows.SECURITY_IDENTIFICATION, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(handle)
	var pid uint32
	if err := windows.GetNamedPipeServerProcessId(handle, &pid); err != nil {
		return 0
	}
	return pid
}

func sleepContext(ctx context.Context, d time.Duration) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
	case <-timer.C:
	}
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
