// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package refusalpipe

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/windows"
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
