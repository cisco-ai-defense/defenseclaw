// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package peerbroker

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"golang.org/x/sys/windows"
)

// Server-side checks of the broker on a real pipe (REVIEW-code-winroute
// P3-5). An ordinary test account cannot make SYSTEM the pipe owner or carry
// the gateway service SID, so the tests use the seams of Server: an access
// list that also admits this account, and an authenticate that accepts it,
// except where the real check is the subject.

type testBroker struct {
	server    *Server
	names     Names
	published string
	events    chan Event
	done      chan error
	cancel    context.CancelFunc
}

func currentUserSID(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	return user.User.Sid.String()
}

// openSecurity admits SYSTEM and this account, with no owner (an ordinary
// account cannot set SYSTEM as the owner).
func openSecurity(t *testing.T) func() (cmidbroker.GatewayPipeSecurity, error) {
	t.Helper()
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;" + currentUserSID(t) + ")"
	return func() (cmidbroker.GatewayPipeSecurity, error) { return cmidbroker.PipeSecurityFromSDDL(sddl) }
}

func acceptThisProcess(windows.Handle) (uint32, error) { return windows.GetCurrentProcessId(), nil }

func verifiedAnswer(*net.TCPAddr, *net.TCPAddr, uint32, peercred.TCPConnOwner) (peercred.PeerIdentity, error) {
	return peercred.PeerIdentity{SID: testSID}, nil
}

// startBroker serves a broker of a fresh certification scope; mutate sets
// the seams before Serve starts. wait: block until the name is published.
func startBroker(t *testing.T, wait bool, mutate func(*Server)) *testBroker {
	t.Helper()
	names, err := NamesFor("DefenseClawCertGateway_00000000aa")
	if err != nil {
		t.Fatal(err)
	}
	b := &testBroker{names: names, published: names.PublishedPath(testDataDir(t)), events: make(chan Event, 64), done: make(chan error, 1)}
	b.server = newServer(names, b.published, verifiedAnswer, func(e Event) {
		select {
		case b.events <- e:
		default:
		}
	})
	b.server.security = openSecurity(t)
	b.server.authenticate = acceptThisProcess
	if mutate != nil {
		mutate(b.server)
	}
	ctx, cancel := context.WithCancel(context.Background())
	b.cancel = cancel
	go func() { b.done <- b.server.Serve(ctx) }()
	t.Cleanup(func() { b.stop(t) })
	if wait {
		b.pipe(t)
	}
	return b
}

// pipe is the published pipe name (waits up to 5 s for it).
func (b *testBroker) pipe(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if p, err := readPublishedPipeName(b.published, b.names); err == nil {
			return p.Pipe
		}
		select {
		case err := <-b.done:
			t.Fatalf("Serve returned before publishing: %v", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatal("the broker never published its pipe name")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (b *testBroker) stop(t *testing.T) {
	t.Helper()
	if b.cancel == nil {
		return
	}
	b.cancel()
	b.cancel = nil
	select {
	case <-b.done:
	case <-time.After(15 * time.Second):
		t.Error("Serve did not stop")
	}
}

// waitEvent returns the first event of stage within 5 s.
func (b *testBroker) waitEvent(t *testing.T, stage string) Event {
	t.Helper()
	timeout := time.After(5 * time.Second)
	for {
		select {
		case e := <-b.events:
			if e.Stage == stage {
				return e
			}
		case <-timeout:
			t.Fatalf("no %s event", stage)
		}
	}
}

// exchange opens pipe, writes message and reads one answer.
func exchange(t *testing.T, pipe string, message []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	handle, err := cmidbroker.OpenClientPipe(ctx, pipe)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(handle)
	if _, err := cmidbroker.WritePipeMessage(ctx, handle, message); err != nil {
		return nil, err
	}
	buffer := make([]byte, MaxMessageBytes+1)
	n, err := cmidbroker.ReadPipeMessage(ctx, handle, buffer)
	if err != nil {
		return nil, err
	}
	return buffer[:n], nil
}

// nameHeld reports that a squatter cannot create the first instance of
// name: an instance of the broker still exists.
func nameHeld(t *testing.T, name string) bool {
	t.Helper()
	pointer, _ := windows.UTF16PtrFromString(name)
	handle, err := windows.CreateNamedPipe(pointer, windows.PIPE_ACCESS_DUPLEX|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT, windows.PIPE_UNLIMITED_INSTANCES, MaxMessageBytes, MaxMessageBytes, 0, nil)
	if err == nil {
		_ = windows.CloseHandle(handle)
		return false
	}
	return true
}

// TestServerAnswersAndUnpublishesOnStop: an admitted client gets the
// verified answer; a stop removes the published record.
func TestServerAnswersAndUnpublishesOnStop(t *testing.T) {
	b := startBroker(t, true, nil)
	pipe := b.pipe(t)
	if !strings.HasPrefix(pipe, b.names.PipePrefix+"_") || pipe == b.names.PipePrefix {
		t.Fatalf("pipe %q is not a fresh name of the scope", pipe)
	}
	raw, err := exchange(t, pipe, encodeTestRequest(t))
	if err != nil {
		t.Fatal(err)
	}
	if identity, err := DecodeResponse(raw); err != nil || identity.SID != testSID {
		t.Fatalf("answer = %+v, %v", identity, err)
	}
	b.stop(t)
	if _, err := os.Stat(b.published); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the record outlived the broker: %v", err)
	}
}

// TestServerRefusesAClientWithoutTheGatewayServiceSID: the real client
// authentication refuses a token without the gateway service SID, sends it
// nothing, and the pipe name stays held (no window for a squatter).
func TestServerRefusesAClientWithoutTheGatewayServiceSID(t *testing.T) {
	b := startBroker(t, true, func(s *Server) {
		s.authenticate = func(pipe windows.Handle) (uint32, error) {
			return cmidbroker.AuthenticateGatewayPipeClient(pipe, s.names.Gateway)
		}
	})
	pipe := b.pipe(t)
	raw, err := exchange(t, pipe, encodeTestRequest(t))
	if err == nil && len(raw) > 0 {
		t.Fatalf("an unauthenticated client got %q", raw)
	}
	if e := b.waitEvent(t, "client-auth"); e.Outcome != "refused" || e.ClientPID != windows.GetCurrentProcessId() {
		t.Fatalf("auth event = %+v", e)
	}
	if !nameHeld(t, pipe) {
		t.Fatal("the pipe name was free after a refused client")
	}
}

// TestServerPipeDACLAdmitsOnlySystemAndTheGateway: the descriptor is owner
// SYSTEM, SYSTEM full access and the gateway service SID read and write; an
// account that is neither cannot open the pipe.
func TestServerPipeDACLAdmitsOnlySystemAndTheGateway(t *testing.T) {
	names, _ := NamesFor("DefenseClawCertGateway_00000000aa")
	sddl, err := cmidbroker.GatewayPipeSDDL(names.Gateway)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sddl, "O:SYD:P(A;;GA;;;SY)(A;;GRGW;;;S-1-5-80-") || strings.Count(sddl, "(") != 2 {
		t.Fatalf("pipe descriptor %q", sddl)
	}
	if runningAsLocalSystem(t) {
		t.Skip("the refused client must be an ordinary account")
	}
	b := startBroker(t, true, func(s *Server) {
		s.security = func() (cmidbroker.GatewayPipeSecurity, error) {
			return cmidbroker.PipeSecurityFromSDDL(strings.TrimPrefix(sddl, "O:SY"))
		}
	})
	pipe := b.pipe(t)
	if _, err := exchange(t, pipe, encodeTestRequest(t)); !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		t.Fatalf("an ordinary account opened the broker pipe: %v", err)
	}
}

// TestServerRefusesARequestOverOneKiB: a request over MaxMessageBytes gets
// no answer.
func TestServerRefusesARequestOverOneKiB(t *testing.T) {
	b := startBroker(t, true, nil)
	pipe := b.pipe(t)
	for _, size := range []int{MaxMessageBytes + 1, 4 * MaxMessageBytes} {
		raw, err := exchange(t, pipe, []byte(strings.Repeat(" ", size)))
		if err == nil && len(raw) > 0 {
			t.Fatalf("a %d-byte request got %q", size, raw)
		}
		if e := b.waitEvent(t, "read"); e.Outcome != "failed" {
			t.Fatalf("read event = %+v", e)
		}
	}
}

// TestServerFullSlotsRefuseBusyAndKeepTheName: with every slot in use a
// client gets a fast busy refusal (unavailable, never a blocked accept
// loop), the name stays held, and the broker serves again once a slot is
// free.
func TestServerFullSlotsRefuseBusyAndKeepTheName(t *testing.T) {
	b := startBroker(t, true, func(s *Server) { s.slots = 1 })
	pipe := b.pipe(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	holder, err := cmidbroker.OpenClientPipe(ctx, pipe)
	if err != nil {
		t.Fatal(err)
	}
	// The holder writes nothing: its slot stays in use until the read
	// timeout of the exchange.
	time.Sleep(200 * time.Millisecond)
	started := time.Now()
	raw, err := exchange(t, pipe, encodeTestRequest(t))
	elapsed := time.Since(started)
	if err == nil {
		if _, decodeErr := DecodeResponse(raw); !errors.Is(decodeErr, ErrUnavailable) {
			t.Fatalf("a client over the slots got %q", raw)
		}
	}
	if elapsed > time.Second {
		t.Fatalf("a client over the slots waited %s", elapsed)
	}
	if e := b.waitEvent(t, "admit"); e.Outcome != RefusedBusy {
		t.Fatalf("admit event = %+v", e)
	}
	if !nameHeld(t, pipe) {
		t.Fatal("the pipe name was free while every slot was in use")
	}
	_ = windows.CloseHandle(holder)
	deadline := time.Now().Add(OperationTimeout + 3*time.Second)
	for {
		raw, err := exchange(t, pipe, encodeTestRequest(t))
		if err == nil {
			if identity, decodeErr := DecodeResponse(raw); decodeErr == nil && identity.SID == testSID {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("the broker did not serve again after the slot was freed: %q, %v", raw, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestServerSquattedNameIsReportedWithTheHolder: when the name of this
// start is held anyway, Serve fails with ErrNameHeld, names the holder PID
// and publishes nothing (the guardian restarts under a new name).
func TestServerSquattedNameIsReportedWithTheHolder(t *testing.T) {
	names, _ := NamesFor("DefenseClawCertGateway_00000000aa")
	squatted, err := names.NewPipeName()
	if err != nil {
		t.Fatal(err)
	}
	pointer, _ := windows.UTF16PtrFromString(squatted)
	squatter, err := windows.CreateNamedPipe(pointer, windows.PIPE_ACCESS_DUPLEX,
		windows.PIPE_TYPE_MESSAGE|windows.PIPE_READMODE_MESSAGE|windows.PIPE_WAIT, windows.PIPE_UNLIMITED_INSTANCES, MaxMessageBytes, MaxMessageBytes, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(squatter)
	b := startBroker(t, false, func(s *Server) {
		s.pipeName = func() (string, error) { return squatted, nil }
	})
	select {
	case err := <-b.done:
		if !errors.Is(err, ErrNameHeld) {
			t.Fatalf("Serve = %v; want ErrNameHeld", err)
		}
		b.cancel()
		b.cancel = nil
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not refuse a held name")
	}
	if e := b.waitEvent(t, "create"); e.Outcome != "name_held" || e.ClientPID != windows.GetCurrentProcessId() {
		t.Fatalf("create event = %+v; want name_held by this process", e)
	}
	if _, err := os.Stat(b.published); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a held name was published: %v", err)
	}
}
