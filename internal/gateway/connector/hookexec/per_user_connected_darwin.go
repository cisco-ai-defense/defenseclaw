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
	"strconv"
	"strings"
	"time"
)

func verifyPerUserConnectedTuple(client, server *net.TCPAddr) error {
	if client == nil || server == nil {
		return errors.New("connected gateway endpoint is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	filter := "-iTCP@" + net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port))
	return awaitPerUserDarwinSocket(ctx, client, server, func(ctx context.Context) ([]byte, error) {
		return exec.CommandContext(ctx, "/usr/sbin/lsof", "-nP", "-a", "-u", strconv.Itoa(os.Geteuid()),
			filter, "-sTCP:ESTABLISHED", "-Fpcun").Output()
	})
}

// connect can finish before accept gives the gateway its server-side FD.
// Inspect the same held connection again; callers cannot write request bytes
// until this function has proven its exact reverse tuple.
func awaitPerUserDarwinSocket(ctx context.Context, client, server *net.TCPAddr,
	inspect func(context.Context) ([]byte, error)) error {
	want := net.JoinHostPort(server.IP.String(), strconv.Itoa(server.Port)) + "->" +
		net.JoinHostPort(client.IP.String(), strconv.Itoa(client.Port))
	refused := errors.New("connected gateway server socket was not proven to belong to this account")
	for {
		if ctx.Err() != nil {
			return refused
		}
		output, err := inspect(ctx)
		if err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 1 {
				return fmt.Errorf("inspect connected gateway socket: %w", err)
			}
		} else {
			owner := -1
			for _, line := range strings.Split(string(output), "\n") {
				if len(line) < 2 {
					continue
				}
				switch line[0] {
				case 'p':
					owner = -1
				case 'u':
					parsed, parseErr := strconv.Atoi(line[1:])
					if parseErr != nil {
						owner = -1
					} else {
						owner = parsed
					}
				case 'n':
					if connectedSocketNameMatches(line[1:], want) {
						if owner == os.Geteuid() {
							return nil
						}
						return refused
					}
				}
			}
		}
		select {
		case <-ctx.Done():
			return refused
		case <-time.After(20 * time.Millisecond):
		}
	}
}
