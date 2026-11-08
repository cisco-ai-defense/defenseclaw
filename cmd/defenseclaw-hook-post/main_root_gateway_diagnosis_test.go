// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package main

import (
	"bytes"
	"io"
	"net"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// A listener this account cannot prove (here one that never accepts, so its
// owner is never proven within the verifier bound of 3 s) is refused with exit 8. The shell hook reads the
// root-gateway diagnosis from this helper stdout, whichever layout the data
// folder has: the helper hands the diagnosis the API address of the call and
// the data folder the shell named, and prints exactly what it returns. The
// gateway CLI hook-post prints the same text through the same function.
func TestHookPostPrintsTheRootGatewayDiagnosisOnARefusedListener(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	dataDir := t.TempDir()
	t.Setenv(hookPostDataDirEnv, dataDir)

	var gotAddr, gotDir string
	previous := peerRefusalOutput
	t.Cleanup(func() { peerRefusalOutput = previous })
	peerRefusalOutput = func(err error, apiAddr, dir string) string {
		gotAddr, gotDir = apiAddr, dir
		if !hookexec.PerUserPostPeerUnverified(err) {
			t.Errorf("diagnosis asked for an error that is not a refused listener: %v", err)
		}
		return "DCPOSTROOT1:diagnosis"
	}
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{}\x00Content-Type\x00application/json\x00")
	for _, form := range [][]string{
		{"hook-post", "--api-addr", addr, "--max-time", "5", "--curl-output"},
		{"hook-post", "--api-addr=" + addr, "--max-time", "5", "--curl-output"},
		{"hook-post", "--api-addr", addr, "--max-time", "5", "--curl-output=true"},
		{"hook-post", "--api-addr", addr, "--max-time", "5", "-curl-output=1"},
		// A repeated flag: the request goes to the last address, so the
		// diagnosis is for the last address.
		{"hook-post", "--api-addr", "127.0.0.1:1", "--api-addr", addr, "--max-time", "5", "--curl-output"},
		{"hook-post", "--api-addr=127.0.0.1:1", "--api-addr=" + addr, "--max-time", "5", "--curl-output"},
	} {
		gotAddr, gotDir = "", ""
		var out bytes.Buffer
		if got := runMain(form, bytes.NewReader(frame), &out, io.Discard); got != hookexec.PerUserPostPeerUnverifiedExit {
			t.Fatalf("%v: exit = %d, want the refused-listener status", form, got)
		}
		if out.String() != "DCPOSTROOT1:diagnosis" || gotAddr != addr || gotDir != dataDir {
			t.Fatalf("%v: stdout %q for address %q and folder %q, want the diagnosis for %q and %q", form, out.String(), gotAddr, gotDir, addr, dataDir)
		}
	}
}

// With no root-run gateway to name, the real function prints nothing and the
// shell keeps its generic text.
func TestHookPostPrintsNothingForAListenerThatIsNoRootGateway(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	t.Setenv(hookPostDataDirEnv, t.TempDir())
	frame := []byte("DCPOST1\x00/api/v1/claude-code/hook\x00{}\x00")
	var out bytes.Buffer
	args := []string{"hook-post", "--api-addr", listener.Addr().String(), "--max-time", "5", "--curl-output"}
	if got := runMain(args, bytes.NewReader(frame), &out, io.Discard); got != hookexec.PerUserPostPeerUnverifiedExit || out.Len() != 0 {
		t.Fatalf("exit %d, stdout %q, want the refused-listener status and no text", got, out.String())
	}
}

func TestParseHookPostFlagsTakesWhatTheRequestUses(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want hookPostFlags
		ok   bool
	}{
		{[]string{"hook-post", "--api-addr", "127.0.0.1:1"}, hookPostFlags{"127.0.0.1:1", 10, false}, true},
		{[]string{"hook-post", "--api-addr=127.0.0.1:2", "--curl-output"}, hookPostFlags{"127.0.0.1:2", 10, true}, true},
		{[]string{"hook-post", "--api-addr=127.0.0.1:2", "--curl-output=true"}, hookPostFlags{"127.0.0.1:2", 10, true}, true},
		{[]string{"hook-post", "--api-addr=127.0.0.1:2", "--curl-output=false"}, hookPostFlags{"127.0.0.1:2", 10, false}, true},
		{[]string{"hook-post", "--api-addr", "127.0.0.1:1", "--api-addr", "127.0.0.1:3", "--max-time", "4"}, hookPostFlags{"127.0.0.1:3", 4, false}, true},
		{[]string{"hook-post", "--api-addr"}, hookPostFlags{}, false},
		{[]string{"hook-post", "--max-time", "3"}, hookPostFlags{}, false},
		{[]string{"hook-post", "--api-addr", "127.0.0.1:1", "extra"}, hookPostFlags{}, false},
		{[]string{"other", "--api-addr", "127.0.0.1:1"}, hookPostFlags{}, false},
	} {
		got, err := parseHookPostFlags(tc.args)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("parseHookPostFlags(%v) = %+v, %v, want %+v (ok %v)", tc.args, got, err, tc.want, tc.ok)
		}
	}
}
