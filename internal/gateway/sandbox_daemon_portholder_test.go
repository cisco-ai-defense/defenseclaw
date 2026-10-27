// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"net"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// r103 GAP-0038: the daemon polls the gateway port while the account's own
// gateway, just started, binds it. A lookup that ran before the bind and a
// dial that connected after it must not make the account's own gateway
// another account's: a fresh run after kept sandboxes was refused with
// "another account is using them (one account at a time)".
func TestAGatewayThatStartsListeningDuringTheLookupIsTheAccountsOwn(t *testing.T) {
	const own = 503
	listening := false
	find := func(string, int) (daemon.PortHolder, error) {
		if !listening {
			return daemon.PortHolder{UID: -1}, daemon.ErrNoListener
		}
		return daemon.PortHolder{PID: 42, UID: own, Command: "openshell-gateway"}, nil
	}
	dial := func(string) (net.Conn, error) {
		listening = true // the gateway bound the port after the lookup
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	if uid, held := portHolderSeen(17670, find, dial); !held || uid != own {
		t.Fatalf("portHolderSeen = (%d, %v), want (%d, true): the account's own gateway was taken for another account's", uid, held, own)
	}
}

// The refusal stays for what it is meant for: a listener that accepts but
// that no lookup of this account sees (macOS lsof lists only the account's
// own processes) is another account's, and a closed port is held by nobody.
func TestAListenerNoLookupSeesIsStillAnotherAccounts(t *testing.T) {
	unseen := func(string, int) (daemon.PortHolder, error) {
		return daemon.PortHolder{UID: -1}, daemon.ErrNoListener
	}
	connects := func(string) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}
	if uid, held := portHolderSeen(17670, unseen, connects); !held || uid != -1 {
		t.Fatalf("unseen listener: (%d, %v), want (-1, true)", uid, held)
	}
	refused := func(string) (net.Conn, error) { return nil, errors.New("connection refused") }
	if _, held := portHolderSeen(17670, unseen, refused); held {
		t.Fatal("closed port reported held")
	}
	other := func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{PID: 7, UID: 504}, nil }
	if uid, held := portHolderSeen(17670, other, refused); !held || uid != 504 {
		t.Fatalf("visible holder: (%d, %v), want (504, true)", uid, held)
	}
}
