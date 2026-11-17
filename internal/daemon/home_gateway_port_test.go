// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// rel-1-0-10:GAP-1133: only this home's own gateway, found in the socket
// table, holds the port; a table-read error, no listener, the caller itself
// or a holder no record names is "not held", so the agents are parked.
func TestHomeGatewayHoldsPort(t *testing.T) {
	dir := t.TempDir()
	const port = 18970
	holder, holderErr := PortHolder{PID: 4242, UID: -1}, error(nil)
	thisAccount := true
	prev, prevAccount := homeGatewayPortHolder, homeGatewayHolderIsThisAccount
	homeGatewayPortHolder = func(string, int) (PortHolder, error) { return holder, holderErr }
	homeGatewayHolderIsThisAccount = func(PortHolder) bool { return thisAccount }
	t.Cleanup(func() { homeGatewayPortHolder, homeGatewayHolderIsThisAccount = prev, prevAccount })

	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("a holder no record names is not this home's gateway")
	}
	record := filepath.Join(dir, "gateway-api.json")
	if err := os.WriteFile(record, []byte(`{"pid":4242,"host":"127.0.0.1","port":18970}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := safefile.ProtectFile(record); err != nil {
		t.Fatal(err)
	}
	if !HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("the holder this home's runtime record names (a foreground gateway) holds the port")
	}
	if HomeGatewayHoldsPort(dir, "127.0.0.1", 18971) {
		t.Fatal("the record names another port")
	}
	// GAP-1133 (SQUATREV3): the record outlives a crash; another account
	// that got the crashed gateway's PID (Windows: UID -1 in the table) and
	// bound the port, or a failed account check, must not hold it.
	thisAccount = false
	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("a stale-record PID of another account (or an unreadable owner) holds the port")
	}
	thisAccount = true
	holder.PID = os.Getpid()
	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("the caller itself never counts")
	}
	holder, holderErr = PortHolder{UID: -1}, errors.New("socket table read failed")
	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("a table-read error is not held (park)")
	}
	holderErr = ErrNoListener
	if HomeGatewayHoldsPort(dir, "127.0.0.1", port) {
		t.Fatal("no listener is not held")
	}
	if HomeGatewayHoldsPort("relative", "127.0.0.1", port) {
		t.Fatal("a relative data dir is never trusted")
	}
}

// rel-1-0-10:GAP-1133 (SQUATREV3): the account check itself. This process
// runs as this account; another account's UID, a PID that does not exist and
// no PID are not this account (on Windows the token query of a missing
// process fails, which parks).
func TestHolderIsThisAccount(t *testing.T) {
	if !holderIsThisAccount(PortHolder{PID: os.Getpid(), UID: -1}) {
		t.Fatal("this process (UID unknown in the table) is this account")
	}
	if holderIsThisAccount(PortHolder{PID: 0, UID: -1}) {
		t.Fatal("no PID is not this account")
	}
	if holderIsThisAccount(PortHolder{PID: 0x3ffffff0, UID: -1}) {
		t.Fatal("a PID that does not exist (owner query fails) is not this account")
	}
	if runtime.GOOS != "windows" {
		if !holderIsThisAccount(PortHolder{PID: os.Getpid(), UID: os.Getuid()}) {
			t.Fatal("this account's UID")
		}
		if holderIsThisAccount(PortHolder{PID: os.Getpid(), UID: os.Getuid() + 1}) {
			t.Fatal("another account's UID is not this account")
		}
	}
}
