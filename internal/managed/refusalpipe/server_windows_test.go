// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package refusalpipe

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-1242: the gateway names the account from the pipe client token, not
// from the report, and the hook writes nothing to a pipe another process
// serves.
func TestRefusalPipeIdentifiesTheClientToken(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !AccountSID(user.User.Sid.String()) {
		t.Skipf("test account %s is not a user account SID", user.User.Sid)
	}
	name := fmt.Sprintf(`\\.\pipe\defenseclaw-refusal-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	restoreName, restorePID := clientPipeName, gatewayServerPID
	t.Cleanup(func() { clientPipeName, gatewayServerPID = restoreName, restorePID })
	clientPipeName = name
	gatewayServerPID = func() (uint32, error) { return uint32(os.Getpid()), nil }

	type received struct {
		sid    string
		report Report
	}
	got := make(chan received, 4)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- serve(ctx, name, func(sid string, report Report) { got <- received{sid, report} })
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})

	report := Report{Connector: "claudecode", Reason: ReasonSIDUnregistered, Event: "PreToolUse", Tool: "Bash"}
	var sendErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		sendCtx, stop := context.WithTimeout(context.Background(), time.Second)
		sendErr = Send(sendCtx, report)
		stop()
		if sendErr == nil {
			break
		}
	}
	if sendErr != nil {
		t.Fatalf("send: %v", sendErr)
	}
	select {
	case r := <-got:
		if r.sid != user.User.Sid.String() || r.report != report {
			t.Fatalf("received %+v, want %s %+v", r, user.User.Sid, report)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no report received")
	}
	// GAP-2639: a CLI command report travels the same pipe and is named by
	// the same token.
	command := Report{Command: "enterprise windows repair", Reason: ReasonElevationRequired}
	if err := Send(context.Background(), command); err != nil {
		t.Fatalf("send command report: %v", err)
	}
	select {
	case r := <-got:
		if r.sid != user.User.Sid.String() || r.report != command {
			t.Fatalf("received %+v, want %s %+v", r, user.User.Sid, command)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no command report received")
	}

	gatewayServerPID = func() (uint32, error) { return uint32(os.Getpid()) + 4, nil }
	if err := Send(context.Background(), report); err == nil {
		t.Fatal("a report was written to a pipe the gateway service does not serve")
	}
	select {
	case r := <-got:
		t.Fatalf("server received %+v from a client that should have refused to write", r)
	case <-time.After(200 * time.Millisecond):
	}
}

// GAP-1253: serve returns only after the reports it accepted were handled,
// so the stop's drain that follows it sees them.
func TestRefusalPipeServeWaitsForItsHandlers(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !AccountSID(user.User.Sid.String()) {
		t.Skipf("test account %s is not a user account SID", user.User.Sid)
	}
	name := fmt.Sprintf(`\\.\pipe\defenseclaw-refusal-join-%d-%d`, os.Getpid(), time.Now().UnixNano())
	restoreName, restorePID := clientPipeName, gatewayServerPID
	t.Cleanup(func() { clientPipeName, gatewayServerPID = restoreName, restorePID })
	clientPipeName = name
	gatewayServerPID = func() (uint32, error) { return uint32(os.Getpid()), nil }

	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	served := make(chan error, 1)
	go func() {
		served <- serve(ctx, name, func(string, Report) {
			once.Do(func() { close(entered) })
			<-release
		})
	}()
	report := Report{Connector: "claudecode", Reason: ReasonSIDUnregistered, Event: "PreToolUse", Tool: "Bash"}
	var sendErr error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		sendCtx, stop := context.WithTimeout(context.Background(), time.Second)
		sendErr = Send(sendCtx, report)
		stop()
		if sendErr == nil {
			break
		}
	}
	if sendErr != nil {
		t.Fatalf("send: %v", sendErr)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no report handled")
	}
	cancel()
	select {
	case <-served:
		t.Fatal("serve returned while a handler was still running")
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not return after its handler")
	}
}

// GAP-2639: a client that closes its end right after its write lost the
// report when the server read or identified it after the close: on the
// managed host most refusals of a standard account's CLI run never reached
// the audit log. Every report a client sent, one after another, arrives.
func TestRefusalPipeKeepsEveryReportOfAClientThatExitsAtOnce(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !AccountSID(user.User.Sid.String()) {
		t.Skipf("test account %s is not a user account SID", user.User.Sid)
	}
	name := fmt.Sprintf(`\\.\pipe\defenseclaw-refusal-burst-%d-%d`, os.Getpid(), time.Now().UnixNano())
	restoreName, restorePID := clientPipeName, gatewayServerPID
	t.Cleanup(func() { clientPipeName, gatewayServerPID = restoreName, restorePID })
	clientPipeName = name
	gatewayServerPID = func() (uint32, error) { return uint32(os.Getpid()), nil }
	var mu sync.Mutex
	received := 0
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- serve(ctx, name, func(sid string, _ Report) {
			if sid == user.User.Sid.String() {
				mu.Lock()
				received++
				mu.Unlock()
			}
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	report := Report{Command: "enterprise windows repair", Reason: ReasonElevationRequired}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if Send(context.Background(), report) == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the pipe never accepted a report")
		}
	}
	const sent = 40
	for i := 1; i < sent; i++ {
		sendCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
		if err := Send(sendCtx, report); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
		stop()
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		mu.Lock()
		n := received
		mu.Unlock()
		if n == sent {
			return
		}
	}
	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("received %d of %d reports", received, sent)
}

// GAP-2639: the gateway service's write-restricted token creates the pipe's
// further instances only through an ACE for its service SID; clients get
// clientRights and never FILE_CREATE_PIPE_INSTANCE.
func TestRefusalPipeSecurityLetsTheRestrictedServiceCreateInstances(t *testing.T) {
	sddl := pipeSDDL("S-1-5-18")
	service := managed.WindowsServiceSIDString(managed.StandaloneWindowsGatewaySvc)
	if !strings.HasPrefix(service, "S-1-5-80-") || !strings.Contains(sddl, "(A;;GA;;;"+service+")") ||
		!strings.Contains(sddl, "(A;;"+clientRights+";;;AU)") {
		t.Fatalf("refusal pipe SDDL = %s", sddl)
	}
	if _, err := windows.SecurityDescriptorFromString(sddl); err != nil {
		t.Fatal(err)
	}
}
