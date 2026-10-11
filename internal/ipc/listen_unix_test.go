// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// GAP-1418: the socket appears at its path only with its final mode, so a
// peer never meets a bind-time mode. A stale socket is replaced, nothing of
// the bind is left beside it, and Close removes only the socket it published.
func TestListenSecuredPublishesTheSocketWithItsFinalMode(t *testing.T) {
	dir, err := os.MkdirTemp("", "ipc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "s.sock")
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable here: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	listener, err := ListenSecured(context.Background(), ListenSpec{
		Path: path, SocketMode: 0o660, DirMode: 0o750, OwnerUID: -1, OwnerGID: -1, BaseName: "s.sock",
	})
	if err != nil {
		t.Fatalf("ListenSecured over a stale socket: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o660 {
		t.Fatalf("published socket = %v, %v; want a 0660 socket", info, err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Fatalf("directory holds %d entries after the bind, want only the socket", len(entries))
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial the published socket: %v", err)
	}
	_ = conn.Close()

	// A newer listener took the path over: closing this one leaves it.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	newer, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer newer.Close()
	_ = listener.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("Close removed the socket another listener published: %v", err)
	}
}
