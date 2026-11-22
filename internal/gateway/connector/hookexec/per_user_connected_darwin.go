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
	started := time.Now()
	err := awaitPerUserDarwinSocket(ctx, func(ctx context.Context) (bool, error) {
		if darwinRecordedGatewayHoldsSocket(ctx, server, client, darwinTCPEstablished) {
			return true, nil
		}
		// The scan of every process of the account is the proof for a
		// gateway with no valid record, and the fallback once the recorded
		// gateway has not shown the socket for darwinRecordedGatewayGrace.
		if recordedGatewayValid(ctx) && time.Since(started) < darwinRecordedGatewayGrace {
			return false, nil
		}
		owners, err := darwinSocketOwnerPIDs(ctx, server, client, darwinTCPEstablished)
		return len(owners) != 0, err
	})
	if errors.Is(err, errDarwinSocketNotProven) {
		return fmt.Errorf("%w: %w", errPerUserNotAccepted, err)
	}
	return err
}

// darwinRecordedGatewayGrace is how long a call waits for the recorded
// gateway to show the accepted socket before it scans every process of the
// account as well.
const darwinRecordedGatewayGrace = 100 * time.Millisecond

// recordedGatewayValid reports whether a gateway record of the call names a
// live process of the same start.
func recordedGatewayValid(ctx context.Context) bool {
	for _, home := range perUserGatewayHomes(ctx) {
		if _, ok := recordedGatewayPID(home); ok {
			return true
		}
	}
	return false
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
	attempt := 0
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
		case <-time.After(nextConnectedPollPause(&attempt)):
		}
	}
}
