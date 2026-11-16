// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestConnectedLoopbackClientSIDNamesTheAcceptedClient(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	self, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	want := self.User.Sid.String()
	var got string
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got, err = ConnectedLoopbackClientSID(server.LocalAddr().(*net.TCPAddr), server.RemoteAddr().(*net.TCPAddr))
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil || got != want {
		t.Fatalf("accepted client SID = %q, error=%v; want %q", got, err, want)
	}
}
