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

package peercred

import (
	"net"
	"os"
	"testing"
)

// The kernel names the account on the client end of a loopback connection
// (GAP-0348): here the test process on both ends.
func TestLoopbackTCPPeerUIDNamesTheClientAccount(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	uid, err := LoopbackTCPPeerUID(server.LocalAddr().(*net.TCPAddr), server.RemoteAddr().(*net.TCPAddr))
	if err != nil || uid != os.Getuid() {
		t.Fatalf("LoopbackTCPPeerUID = %d, %v; want %d", uid, err, os.Getuid())
	}
}
