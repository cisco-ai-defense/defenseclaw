// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// rel-1-0-10:GAP-1164: a Windows gateway this account started elevated has a
// token a non-elevated start or stop cannot read. It holds the port only when
// its creation time is the one its gateway-api.json recorded; a reused PID, a
// record without a start identity, an unreadable creation time or no record
// is "not held" (park).
func TestHomeGatewayHoldsPortElevatedHolder(t *testing.T) {
	dir := t.TempDir()
	const port = 18973
	const pid = 4243
	account := holderAccountUnreadable
	live, liveErr := "133000000000000001", error(nil)
	prevHolder, prevAccount, prevIdentity := homeGatewayPortHolder, homeGatewayHolderAccount, homeGatewayStartIdentity
	homeGatewayPortHolder = func(string, int) (PortHolder, error) { return PortHolder{PID: pid, UID: -1}, nil }
	homeGatewayHolderAccount = func(PortHolder) holderAccountMatch { return account }
	homeGatewayStartIdentity = func(got int) (string, error) {
		if got != pid {
			t.Fatalf("start identity read for pid %d, want %d", got, pid)
		}
		return live, liveErr
	}
	t.Cleanup(func() {
		homeGatewayPortHolder, homeGatewayHolderAccount, homeGatewayStartIdentity = prevHolder, prevAccount, prevIdentity
	})
	record := filepath.Join(dir, "gateway-api.json")
	write := func(body string) {
		t.Helper()
		_ = os.Remove(record)
		if err := os.WriteFile(record, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := safefile.ProtectFile(record); err != nil {
			t.Fatal(err)
		}
	}
	held := func() bool { return HomeGatewayHoldsPort(dir, "127.0.0.1", port) }

	if held() {
		t.Fatal("token denied and no record: not held")
	}
	write(`{"pid":4243,"host":"127.0.0.1","port":18973}`)
	if held() {
		t.Fatal("token denied and a record without a start identity: not held")
	}
	write(`{"pid":4243,"host":"127.0.0.1","port":18973,"start_identity":"133000000000000001"}`)
	if !held() {
		t.Fatal("token denied, creation time the record carries: this home's elevated gateway holds the port")
	}
	if HomeGatewayHoldsPort(dir, "127.0.0.1", 18974) {
		t.Fatal("the record names another port")
	}
	// rel-1-0-10:GAP-1212: the same binding names it out of reach.
	if got, ok := HomeGatewayOutOfReach(dir, "127.0.0.1", port); !ok || got != pid {
		t.Fatalf("HomeGatewayOutOfReach = %d, %v; want %d, true", got, ok, pid)
	}
	account = holderThisAccount
	if _, ok := HomeGatewayOutOfReach(dir, "127.0.0.1", port); ok {
		t.Fatal("a holder this caller can read is not out of reach")
	}
	account = holderOtherAccount
	if _, ok := HomeGatewayOutOfReach(dir, "127.0.0.1", port); ok {
		t.Fatal("another account's holder is not this home's gateway out of reach")
	}
	account = holderAccountUnreadable
	live = "133000000000000999"
	if held() {
		t.Fatal("token denied, another creation time (a reused PID): not held")
	}
	if _, ok := HomeGatewayOutOfReach(dir, "127.0.0.1", port); ok {
		t.Fatal("a reused PID is not this home's gateway out of reach")
	}
	live, liveErr = "", errors.New("access denied")
	if held() {
		t.Fatal("token denied and the creation time unreadable: not held")
	}
	live, liveErr = "", nil
	if held() {
		t.Fatal("token denied and no creation time on this system: not held")
	}
	write(`{"pid":4244,"host":"127.0.0.1","port":18973,"start_identity":"133000000000000001"}`)
	live = "133000000000000001"
	if held() {
		t.Fatal("the record names another PID")
	}

	// The same record with an account check that failed for any other
	// reason (another account, no process, an open error) never holds.
	write(`{"pid":4243,"host":"127.0.0.1","port":18973,"start_identity":"133000000000000001"}`)
	account = holderOtherAccount
	if held() {
		t.Fatal("another account's holder with the recorded creation time: not held")
	}
	// This account's holder: the recorded creation time must match too.
	account = holderThisAccount
	if !held() {
		t.Fatal("this account's holder the record names holds the port")
	}
	live = "133000000000000999"
	if held() {
		t.Fatal("this account's process that reused the PID: not held")
	}
}
