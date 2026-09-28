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

	"golang.org/x/sys/unix"
)

func TestFromConnSocketpair(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	left := os.NewFile(uintptr(fds[0]), "left")
	right := os.NewFile(uintptr(fds[1]), "right")
	defer left.Close()
	defer right.Close()
	conn, err := net.FileConn(left)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	credentials, err := FromConn(conn)
	if err != nil {
		t.Fatal(err)
	}
	if credentials.UID != os.Getuid() {
		t.Fatalf("peer uid = %d, want %d", credentials.UID, os.Getuid())
	}
	if credentials.PID != 0 && credentials.PID != os.Getpid() {
		t.Fatalf("peer pid = %d, want %d", credentials.PID, os.Getpid())
	}
}

func TestFromConnRejectsTCP(t *testing.T) {
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
	if _, err := FromConn(client); err == nil {
		t.Fatal("TCP connection must not yield peer credentials")
	}
}
