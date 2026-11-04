// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"context"
	"errors"
	"net"
	"time"
)

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	if client == nil || server == nil {
		return errors.New("connected gateway endpoint is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return awaitPerUserDarwinSocket(ctx, func(ctx context.Context) (bool, error) {
		owners, err := darwinSocketOwnerPIDs(ctx, server, client, darwinTCPEstablished)
		return len(owners) != 0, err
	})
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
