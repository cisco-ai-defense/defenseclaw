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

// cowork-1-0-8 GAP-0060: the own-status pipe answers for the account whose
// token connected, which the request does not name, and the client asks
// only the gateway service.
func TestOwnStatusPipeAnswersTheClientToken(t *testing.T) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	if !AccountSID(user.User.Sid.String()) {
		t.Skipf("test account %s is not a user account SID", user.User.Sid)
	}
	name := fmt.Sprintf(`\\.\pipe\defenseclaw-own-status-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
	restoreName, restorePID := ownStatusClientPipeName, gatewayServerPID
	t.Cleanup(func() { ownStatusClientPipeName, gatewayServerPID = restoreName, restorePID })
	ownStatusClientPipeName = name
	gatewayServerPID = func() (uint32, error) { return uint32(os.Getpid()), nil }

	asked := make(chan string, 4)
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() {
		served <- serveOwnStatus(ctx, name, func(sid string) []byte {
			asked <- sid
			return []byte(`{"own":true,"account":{"sid":"` + sid + `"}}`)
		}, func(sid string) bool {
			asked <- "excluded:" + sid
			return true
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-served
	})

	var answer []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		askCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		answer, err = OwnStatus(askCtx)
		stop()
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("own status: %v", err)
	}
	want := `{"own":true,"account":{"sid":"` + user.User.Sid.String() + `"}}`
	if string(answer) != want {
		t.Fatalf("answer %s, want %s", answer, want)
	}
	if sid := <-asked; sid != user.User.Sid.String() {
		t.Fatalf("the server named %s, want the client token's %s", sid, user.User.Sid)
	}

	// The exclusion question is answered for the client token too, from the
	// gateway judgement of that token SID.
	askCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	excluded, err := AccountExcluded(askCtx)
	stop()
	if err != nil || !excluded {
		t.Fatalf("AccountExcluded = %t, %v, want true", excluded, err)
	}
	if got := <-asked; got != "excluded:"+user.User.Sid.String() {
		t.Fatalf("the server judged %s, want the SID of the client token", got)
	}

	// The client asks nothing of a pipe another process serves.
	gatewayServerPID = func() (uint32, error) { return uint32(os.Getpid()) + 4, nil }
	if excluded, err := AccountExcluded(context.Background()); err == nil || excluded {
		t.Fatal("an exclusion was read from a pipe the gateway service does not serve")
	}
	if _, err := OwnStatus(context.Background()); err == nil {
		t.Fatal("own status was read from a pipe the gateway service does not serve")
	}
	select {
	case sid := <-asked:
		t.Fatalf("server answered %s for a client that should have refused to ask", sid)
	case <-time.After(200 * time.Millisecond):
	}
}
