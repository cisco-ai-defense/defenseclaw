// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	if client == nil || server == nil {
		return errors.New("connected gateway endpoint is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), perUserConnectedWait)
	defer cancel()
	err := awaitPerUserDarwinSocket(ctx, func(ctx context.Context) (bool, error) {
		owners, err := darwinSocketOwnerPIDs(ctx, server, client, darwinTCPEstablished)
		return len(owners) != 0, err
	})
	if errors.Is(err, errDarwinSocketNotProven) && darwinOwnListenerHolds(server) {
		return fmt.Errorf("%w: %w", errPerUserListenerUnanswered, err)
	}
	return err
}

// darwinOwnListenerHolds reports whether a process of this account listens
// on the server endpoint (or the wildcard address of its family). Only the
// processes of this account are listed, so a listener of another account is
// never found. A connection nobody accepted for the whole wait, on a port
// this account listens on, is the gateway of this account, stopped or frozen.
func darwinOwnListenerHolds(server *net.TCPAddr) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	wildcard := net.IPv6unspecified
	if server.IP.To4() != nil {
		wildcard = net.IPv4zero
	}
	for _, ip := range []net.IP{server.IP, wildcard} {
		owners, err := darwinSocketOwnerPIDs(ctx, &net.TCPAddr{IP: ip, Port: server.Port}, nil, darwinTCPListen)
		if err == nil && len(owners) != 0 {
			return true
		}
	}
	return false
}

// errDarwinSocketNotProven ends the wait for a connected socket that was
// never seen as the accepted socket of a process of this account.
var errDarwinSocketNotProven = errors.New("connected gateway server socket was not proven to belong to this account")

// connect can finish before accept gives the gateway its server-side FD.
// The request waits for the held connection exact reverse tuple.
func awaitPerUserDarwinSocket(ctx context.Context, inspect func(context.Context) (bool, error)) error {
	for {
		if ctx.Err() != nil {
			return errDarwinSocketNotProven
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
			return errDarwinSocketNotProven
		case <-time.After(20 * time.Millisecond):
		}
	}
}
