// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// GAP-1955: a /proc mounted with subset=pid has no /proc/net, only
// /proc/self/net, so the managed lifecycle saw no API port holder there and
// could not name the process that keeps the gateway from listening.
func TestLinuxPortHoldersReadSelfNetWhenProcNetIsAbsent(t *testing.T) {
	root := t.TempDir()
	net := filepath.Join(root, "proc", "self", "net")
	if err := os.MkdirAll(net, 0o755); err != nil {
		t.Fatal(err)
	}
	// 127.0.0.1:18970 (0x4A1A) LISTEN, uid 1001, inode 4242; and a listener
	// on another port that must be ignored.
	table := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1001        0 4242 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1002        0 4343 1 0000000000000000 100 0 0 10 0\n"
	if err := os.WriteFile(filepath.Join(net, "tcp"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	fd := filepath.Join(root, "proc", "4321", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[4242]", filepath.Join(fd, "7")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "proc", "net")); !os.IsNotExist(err) {
		t.Fatalf("fixture must have no /proc/net, got %v", err)
	}
	env := &Env{Root: root}
	got := env.linuxPortHolders(18970)
	want := []portHolder{{PID: 4321, UID: 1001}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("holders = %+v, want %+v", got, want)
	}
}
