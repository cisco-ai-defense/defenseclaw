// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestPerUserDarwinWaitsForAcceptedSameAccountSocket(t *testing.T) {
	// A gateway of this account's real home run by another account would be
	// accepted by its own evidence; these cases test the lsof proof alone.
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	want := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55233\n", os.Geteuid())
	reads := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := awaitPerUserDarwinSocket(ctx, client, server, func(context.Context) ([]byte, error) {
		reads++
		if reads < 3 {
			return nil, nil // connect returned before the gateway accepted
		}
		return []byte(want), nil
	})
	if err != nil || reads != 3 {
		t.Fatalf("accepted same-account socket: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinNeverAcceptsAnUnprovenPeer(t *testing.T) {
	// A gateway of this account's real home run by another account would be
	// accepted by its own evidence; these cases test the lsof proof alone.
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	wrongTuple := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55234\n", os.Geteuid())
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	if err := awaitPerUserDarwinSocket(ctx, client, server, func(context.Context) ([]byte, error) {
		return []byte(wrongTuple), nil
	}); err == nil {
		t.Fatal("another connected tuple was accepted")
	}
	reads := 0
	if err := awaitPerUserDarwinSocket(context.Background(), client, server, func(context.Context) ([]byte, error) {
		reads++
		return nil, errors.New("inspection failed")
	}); err == nil || reads != 1 {
		t.Fatalf("inspection failure was not terminal: reads=%d err=%v", reads, err)
	}
	foreign := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55233\n", os.Geteuid()+1)
	reads = 0
	if err := awaitPerUserDarwinSocket(context.Background(), client, server, func(context.Context) ([]byte, error) {
		reads++
		return []byte(foreign), nil
	}); err == nil || reads != 1 {
		t.Fatalf("foreign owner was not refused immediately: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinRetriesLsofNoMatchesExit(t *testing.T) {
	// A gateway of this account's real home run by another account would be
	// accepted by its own evidence; these cases test the lsof proof alone.
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	missing := exec.Command("/usr/bin/false").Run()
	if missing == nil {
		t.Fatal("failed to make an lsof no-matches exit")
	}
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	want := fmt.Sprintf("p4242\nu%d\nn127.0.0.1:18970->127.0.0.1:55233\n", os.Geteuid())
	reads := 0
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := awaitPerUserDarwinSocket(ctx, client, server, func(context.Context) ([]byte, error) {
		reads++
		if reads == 1 {
			return nil, missing
		}
		return []byte(want), nil
	}); err != nil || reads != 2 {
		t.Fatalf("lsof no-match exit was not retried: reads=%d err=%v", reads, err)
	}
}

func TestPerUserDarwinVerifiesARealAcceptedSocket(t *testing.T) {
	listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	accepted := make(chan *net.TCPConn, 1)
	go func() {
		peer, _ := listener.AcceptTCP()
		accepted <- peer
	}()
	server := <-accepted
	if server == nil {
		t.Fatal("local server did not accept")
	}
	defer server.Close()
	if err := verifyPerUserConnectedTuple(client.LocalAddr().(*net.TCPAddr), client.RemoteAddr().(*net.TCPAddr)); err != nil {
		t.Fatalf("same-account accepted socket was not proven: %v", err)
	}
}

// The macOS app's privileged helper runs this account's gateway as root for
// this home: lsof lists only this account's sockets, so the accepted tuple
// never shows there and every token-bearing request was refused as another
// account's. This home's own evidence (its verified PID record and the
// gateway's runtime record naming the endpoint) proves the listener; the
// kernel's socket table, where it names owners at all, can only veto.
func TestPerUserDarwinAcceptsThisHomesGatewayRunByAnotherAccount(t *testing.T) {
	client := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 55233}
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	header := "Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs\n"
	row := func(foreignPort, pid int) string {
		return fmt.Sprintf("tcp4       0      0  127.0.0.1.18970        127.0.0.1.%d        ESTABLISHED           52            0  408300  146988 defenseclaw-gate:%d  02131 00000000 0000000001396f0e 00000080 04000900      1      0 000000\n", foreignPort, pid)
	}
	oldTable, oldGateway := perUserDarwinSocketTable, perUserOtherAccountGateway
	t.Cleanup(func() { perUserDarwinSocketTable, perUserOtherAccountGateway = oldTable, oldGateway })
	noOwnSocket := func(context.Context) ([]byte, error) { return nil, nil }
	homeGateway := func(asked *net.TCPAddr) (int, bool) {
		if asked.IP.Equal(server.IP) && asked.Port == server.Port {
			return 50721, true
		}
		return 0, false
	}

	accepts := []struct {
		name  string
		table string
		err   error
	}{
		{"socket table names the gateway", header + row(55233, 50721), nil},
		{"socket table is empty (macOS 26 and later)", header, nil},
		{"socket table has no row for the tuple yet", header + row(55234, 50721), nil},
		{"socket table is unavailable", "", errors.New("netstat failed")},
	}
	for _, tc := range accepts {
		perUserOtherAccountGateway = homeGateway
		perUserDarwinSocketTable = func(context.Context) ([]byte, error) { return []byte(tc.table), tc.err }
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err := awaitPerUserDarwinSocket(ctx, client, server, noOwnSocket)
		cancel()
		if err != nil {
			t.Fatalf("%s: this home's gateway run by another account was refused: %v", tc.name, err)
		}
	}

	refusals := []struct {
		name    string
		gateway func(*net.TCPAddr) (int, bool)
		table   string
	}{
		{"socket table names another process", homeGateway, header + row(55233, 50720)},
		{"no gateway of this home listens there", func(*net.TCPAddr) (int, bool) { return 0, false }, header},
		{"this home's gateway listens on another port", func(asked *net.TCPAddr) (int, bool) {
			return 50721, asked.Port == 18980
		}, header},
	}
	for _, tc := range refusals {
		perUserOtherAccountGateway = tc.gateway
		perUserDarwinSocketTable = func(context.Context) ([]byte, error) { return []byte(tc.table), nil }
		ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
		err := awaitPerUserDarwinSocket(ctx, client, server, noOwnSocket)
		cancel()
		if err == nil {
			t.Fatalf("%s: an unproven peer was accepted", tc.name)
		}
	}
}

// thisHomesGatewayRunByAnotherAccountListensAt needs a live gateway of
// another account; with none recorded for a fresh home it proves nothing.
func TestThisHomesGatewayRunByAnotherAccountNeedsARecord(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", t.TempDir())
	server := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 18970}
	if pid, ok := thisHomesGatewayRunByAnotherAccountListensAt(server); ok || pid != 0 {
		t.Fatalf("an empty home proved a listener: pid=%d ok=%v", pid, ok)
	}
	if pid, ok := thisHomesGatewayRunByAnotherAccountListensAt(nil); ok || pid != 0 {
		t.Fatalf("a nil endpoint proved a listener: pid=%d ok=%v", pid, ok)
	}
}

func TestPerUserGatewayHomeFollowsDefenseClawHome(t *testing.T) {
	t.Setenv("DEFENSECLAW_HOME", "/tmp/dc-home")
	if got := perUserGatewayHome(); got != "/tmp/dc-home" {
		t.Fatalf("perUserGatewayHome() = %q", got)
	}
	t.Setenv("DEFENSECLAW_HOME", "")
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip(err)
	}
	if got := perUserGatewayHome(); got != home+"/.defenseclaw" {
		t.Fatalf("perUserGatewayHome() = %q", got)
	}
}
