// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A listener this home did not start (a gateway leaked by another home or
// test run) is named by PID instead of being reported as this gateway.
func TestForeignGatewayListenerNamesHolderPID(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c := config.DefaultConfig()
	c.Gateway.APIBind = "127.0.0.1"
	c.Gateway.APIPort = listener.Addr().(*net.TCPAddr).Port

	problem := foreignGatewayListener(c)
	if want := fmt.Sprintf("held by PID %d", os.Getpid()); !strings.Contains(problem, want) ||
		!strings.Contains(problem, "not by this account's gateway") {
		t.Fatalf("foreign listener = %q, want it to contain %q", problem, want)
	}
	listener.Close()
	if problem := foreignGatewayListener(c); problem != "" {
		t.Fatalf("free port reported as held: %q", problem)
	}
}
