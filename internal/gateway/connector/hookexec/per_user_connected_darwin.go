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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// Seams for tests.
var (
	// perUserDarwinSocketTable is the kernel's TCP socket table with the
	// owning process of every socket (netstat -anv), every account's, where
	// lsof lists this account's only. On macOS 26 and later the table is
	// empty for the process tree of a binary that is not Apple's, this
	// gateway included, so it can only veto, never prove.
	perUserDarwinSocketTable = func(ctx context.Context) ([]byte, error) {
		return exec.CommandContext(ctx, "/usr/sbin/netstat", "-anv", "-p", "tcp").Output()
	}
	// perUserOtherAccountGateway is thisHomesGatewayRunByAnotherAccountListensAt.
	perUserOtherAccountGateway = thisHomesGatewayRunByAnotherAccountListensAt
)

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
// account's gateway as root for this home, so lsof, which lists this
// account's sockets, never shows its accepted socket, and every request was
// refused as "another account's". No socket table this account may read
// names that socket's owner either (netstat and sysctl net.inet.tcp.pcblist
// are empty for this binary's process tree on macOS 26 and later). The proof
// is this home's own evidence: its verified PID record (gateway.pid) names a
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
		// This account's own gateway is listed by lsof; nothing to excuse.
		return 0, false
	}
	published := daemon.RuntimeAPIAddress(home, pid)
	if published == nil || !published.IP.Equal(server.IP) || published.Port != server.Port {
		return 0, false
	}
	return pid, true
}

// otherAccountSocketIsHomeGateway accepts the exact tuple client->server
// when this home's gateway, run as another account, is its listener
// (thisHomesGatewayRunByAnotherAccountListensAt) and the kernel's socket
// table, where it names the socket's owner at all, names that gateway. A
// table that names another process vetoes; an empty or missing table proves
// nothing either way.
func otherAccountSocketIsHomeGateway(ctx context.Context, client, server *net.TCPAddr) bool {
	gateway, ok := perUserOtherAccountGateway(server)
	if !ok {
		return false
	}
	table, err := perUserDarwinSocketTable(ctx)
	if err != nil {
		return true
	}
	pid, err := netstatConnectedPID(table, client, server)
	return err != nil || pid <= 0 || pid == gateway
}

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
// until this function has proven its exact reverse tuple. A socket lsof does
// not list for this account is proven through the kernel's socket table when
// this home's gateway, run as another account, holds it
// (otherAccountSocketIsHomeGateway).
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
		if otherAccountSocketIsHomeGateway(ctx, client, server) {
			return nil
		}
		select {
		case <-ctx.Done():
			return refused
		case <-time.After(20 * time.Millisecond):
		}
	}
}
