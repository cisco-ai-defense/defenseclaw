// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestLogindConnectObeysDeadlineDuringAuth(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "bus")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path="+socket)
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()
	logindBusMu.Lock()
	old := logindBus
	logindBus = nil
	logindBusMu.Unlock()
	defer func() {
		logindBusMu.Lock()
		if logindBus != nil {
			logindBus.Close()
		}
		logindBus = old
		logindBusMu.Unlock()
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := logindConn(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("stalled system bus connection succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		select {
		case conn := <-accepted:
			conn.Close()
		default:
		}
		t.Fatal("system bus connection ignored its deadline")
	}
}
