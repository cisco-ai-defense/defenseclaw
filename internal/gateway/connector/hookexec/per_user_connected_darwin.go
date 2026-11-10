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
	if errors.Is(err, errDarwinSocketNotProven) {
		return fmt.Errorf("%w: %w", errPerUserNotAccepted, err)
	}
	return err
}

// tupleStillQueued reports whether no process of this account holds the
// accepted socket of the held connection (the table was read, and listed none).
func tupleStillQueued(client, server *net.TCPAddr) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	owners, err := darwinSocketOwnerPIDs(ctx, server, client, darwinTCPEstablished)
	return err == nil && len(owners) == 0
}

// listenersHeldOnlyByPID reports whether process pid holds a listening socket
// that can take a connection to server (its address or the wildcard address
// of its family, or the dual-stack wildcard) and no other process of this
// account does. Only the processes of this account are listed, so a listener
// of another account is never found; none found is false.
func listenersHeldOnlyByPID(pid int, server *net.TCPAddr) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	ips := []net.IP{server.IP, net.IPv6unspecified}
	if server.IP.To4() != nil {
		ips = []net.IP{server.IP, net.IPv4zero, net.IPv6unspecified}
	}
	found := false
	for _, ip := range ips {
		owners, err := darwinSocketOwnerPIDs(ctx, &net.TCPAddr{IP: ip, Port: server.Port}, nil, darwinTCPListen)
		if err != nil {
			return false
		}
		for _, owner := range owners {
			if owner != pid {
				return false
			}
			found = true
		}
	}
	return found
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
