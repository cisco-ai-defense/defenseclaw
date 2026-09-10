// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package netprobe

import "testing"

// TestParseLsofKeepsListenersAndTheirState is the macOS local-model case.
//
// lsof -F carries no TCP state unless -Ts is passed and T is in the field
// list; the "(LISTEN)" suffix exists only in the human table. Without it a
// listener has neither a "->" nor a state and was discarded as unparseable,
// so local-model-server-port -- the whole reason plane B looks at listeners
// -- could never fire on macOS.
//
// The fields also arrive f, n, T: the state comes after the address, so the
// socket cannot be finished when its address line is read. This fixture is
// real `lsof -nP -iTCP -Ts -FpfnT` output shape.
func TestParseLsofKeepsListenersAndTheirState(t *testing.T) {
	output := "p1319\n" +
		"f56\n" +
		"n*:11434\n" +
		"TST=LISTEN\n" +
		"TQR=0\n" +
		"TQS=0\n" +
		"f57\n" +
		"n192.168.0.168:49690->23.89.40.98:443\n" +
		"TST=ESTABLISHED\n" +
		"p2020\n" +
		"f3\n" +
		"n127.0.0.1:8080\n" +
		"TST=LISTEN\n"

	connections, unattributed, err := parseLsof(output)
	if err != nil {
		t.Fatalf("parseLsof: %v", err)
	}
	if unattributed != 0 {
		t.Errorf("unattributed = %d, want 0: every socket here has a pid", unattributed)
	}
	if len(connections) != 3 {
		t.Fatalf("parsed %d connections, want 3: %+v", len(connections), connections)
	}

	listener := connections[0]
	if listener.State != StateListen {
		t.Errorf("listener state = %v, want StateListen: the TST line was not applied",
			listener.State)
	}
	if listener.LocalPort != 11434 {
		t.Errorf("listener port = %d, want 11434", listener.LocalPort)
	}
	if listener.PID != 1319 {
		t.Errorf("listener pid = %d, want 1319", listener.PID)
	}
	if LocalModelPorts[listener.LocalPort] == "" {
		t.Error("11434 is not recognised as a local model port, so the signal cannot fire")
	}

	established := connections[1]
	if established.State != StateEstablished {
		t.Errorf("connection state = %v, want StateEstablished", established.State)
	}
	if established.RemotePort != 443 || established.PID != 1319 {
		t.Errorf("connection = %+v, want peer :443 owned by 1319", established)
	}

	// The second process block must flush the previous one's last socket.
	if connections[2].PID != 2020 || connections[2].State != StateListen {
		t.Errorf("third connection = %+v, want a listener owned by 2020", connections[2])
	}
}

// TestParseLsofDropsSocketsWithNeitherPeerNorState keeps the flush from
// inventing rows out of incomplete blocks.
func TestParseLsofDropsSocketsWithNeitherPeerNorState(t *testing.T) {
	connections, _, err := parseLsof("p10\nf1\nn*:9999\n")
	if err != nil {
		t.Fatalf("parseLsof: %v", err)
	}
	if len(connections) != 0 {
		t.Fatalf("kept %d connections with no state and no peer: %+v",
			len(connections), connections)
	}
}
