// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// perUserOtherAccountGateway is thisHomesGatewayRunByAnotherAccountListensAt
// (a seam for tests).
var perUserOtherAccountGateway = thisHomesGatewayRunByAnotherAccountListensAt

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	if client == nil || server == nil {
		return errors.New("connected gateway endpoint is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return awaitPerUserDarwinSocket(ctx, func(ctx context.Context) (bool, error) {
		return perUserDarwinConnectedTupleProven(ctx, client, server)
	})
}

// perUserDarwinConnectedTupleProven reports whether the accepted end of
// client->server is proven to be this account's gateway: held by a process
// of this account, or held by this home's gateway while an administrator runs
// it as another account (thisHomesGatewayRunByAnotherAccountListensAt).
func perUserDarwinConnectedTupleProven(ctx context.Context, client, server *net.TCPAddr) (bool, error) {
	owners, err := darwinSocketOwnerPIDs(ctx, server, client, darwinTCPEstablished)
	if err != nil {
		return false, err
	}
	if len(owners) != 0 {
		return true, nil
	}
	_, ok := perUserOtherAccountGateway(server)
	return ok, nil
}

// perUserGatewayHome is this account's DefenseClaw home, resolved as
// config.DefaultDataPath does (this package cannot import config).
func perUserGatewayHome() string {
	if home := os.Getenv("DEFENSECLAW_HOME"); home != "" {
		return home
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	return filepath.Join(home, ".defenseclaw")
}

// thisHomesGatewayRunByAnotherAccountListensAt reports whether server is the
// listener of this home's gateway while that gateway runs as another account,
// and that gateway's PID. The macOS app's privileged helper starts this
// account's gateway as root for this home. The socket inspection above sees
// this account's processes only, and no socket table this account may read
// names that socket's owner either (netstat and sysctl net.inet.tcp.pcblist
// are empty for this binary's process tree on macOS 26 and later), so every
// request to that gateway was refused as "another account's". The proof is
// this home's own evidence: its verified PID record (gateway.pid) names a
// live gateway this account cannot signal, and the gateway's private runtime
// record (gateway-api.json) names that PID as the listener on exactly
// server. A loopback connection to that endpoint is accepted by the process
// that holds it.
func thisHomesGatewayRunByAnotherAccountListensAt(server *net.TCPAddr) (int, bool) {
	if server == nil {
		return 0, false
	}
	home := perUserGatewayHome()
	running, pid := daemon.New(home).IsRunning()
	if !running || pid <= 0 || daemon.ProcessSignalable(pid) {
		// This account's own gateway is seen by the socket inspection;
		// nothing to excuse.
		return 0, false
	}
	published := daemon.RuntimeAPIAddress(home, pid)
	if published == nil || !published.IP.Equal(server.IP) || published.Port != server.Port {
		return 0, false
	}
	return pid, true
}

// connect can finish before accept gives the gateway its server-side FD.
// The request waits for the held connection's exact reverse tuple.
func awaitPerUserDarwinSocket(ctx context.Context, inspect func(context.Context) (bool, error)) error {
	refused := errors.New("connected gateway server socket was not proven to belong to this account")
	for {
		if ctx.Err() != nil {
			return refused
		}
		found, err := inspect(ctx)
		if err != nil {
			return err
		}
		if found {
			return nil
		}
		select {
		case <-ctx.Done():
			return refused
		case <-time.After(20 * time.Millisecond):
		}
	}
}
