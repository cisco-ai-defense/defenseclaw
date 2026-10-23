// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"
)

// No request byte, bearer, scan target or answer may cross to another local
// account. A gateway TCP port is only a number: while the gateway restarts,
// or after it stopped, any account can bind it. So every DefenseClaw client
// proves who owns the socket it is connected to before net/http writes a
// header or a body, on the very connection that carries them:
//
//   - a per-user gateway must be this account's (NewPerUserGatewayHTTPClient);
//   - a managed gateway must be its service (NewManagedGatewayHTTPClient):
//     the running SCM service process on Windows; on Linux and macOS root,
//     which holds the socket for systemd and launchd while the gateway
//     restarts, or the gateway service account.
//
// Native agent exporters cannot run this check, so the managed gateway port
// itself stays held while the gateway restarts (systemd and launchd socket
// activation): an exporter's connection waits for the gateway instead of
// reaching another account.

// ManagedGatewayPeer names the service that must own a managed gateway's
// connected API socket.
type ManagedGatewayPeer struct {
	// ServiceName is the gateway's Windows SCM service.
	ServiceName string
	// ServiceUID is the gateway's Unix service account. Root is accepted as
	// well; a negative value accepts root only.
	ServiceUID int
}

// NewManagedGatewayHTTPClient is the managed counterpart of
// NewPerUserGatewayHTTPClient: before any HTTP byte is written it proves that
// the connected socket belongs to the managed gateway service peer names, and
// it refuses redirects. Each request gets a fresh, freshly verified
// connection. A zero timeout leaves a request bounded by its context.
func NewManagedGatewayHTTPClient(timeout time.Duration, apiAddr string, peer ManagedGatewayPeer) (*http.Client, error) {
	if timeout < 0 {
		timeout = defaultHookRequestTimeout
	}
	client, err := newManagedGatewayHTTPClient(timeout, apiAddr, peer)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client, nil
}

// VerifyManagedConnectedTuple proves that the server end of an open loopback
// connection belongs to the managed gateway service peer names. The Python
// CLI invokes it before urllib3 writes headers or a body on that connection.
func VerifyManagedConnectedTuple(local, remote string, peer ManagedGatewayPeer) error {
	client, server, err := parseConnectedTuple(local, remote)
	if err != nil {
		return err
	}
	return verifyManagedConnectedTuple(client, server, peer)
}

// parseConnectedTuple parses the client and server ends of a loopback TCP
// connection.
func parseConnectedTuple(local, remote string) (*net.TCPAddr, *net.TCPAddr, error) {
	parse := func(raw string) (*net.TCPAddr, error) {
		host, portText, err := net.SplitHostPort(raw)
		if err != nil {
			return nil, err
		}
		ip := net.ParseIP(host)
		port, err := strconv.Atoi(portText)
		if ip == nil || err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("connected gateway endpoint is invalid")
		}
		return &net.TCPAddr{IP: ip, Port: port}, nil
	}
	client, err := parse(local)
	if err != nil {
		return nil, nil, err
	}
	server, err := parse(remote)
	if err != nil {
		return nil, nil, err
	}
	if !client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return nil, nil, fmt.Errorf("connected gateway endpoint is not loopback")
	}
	return client, server, nil
}

// verifiedGatewayHTTPClient proves the owner of the connected socket before
// net/http can write a credential, an event or a request. Each request gets a
// fresh connection, so retries and redirects must pass verification again.
// kind names the gateway in errors ("per-user gateway", "managed gateway").
func verifiedGatewayHTTPClient(
	timeout time.Duration,
	apiAddr string,
	kind string,
	dial func(context.Context, string, string) (net.Conn, error),
	verify func(net.Conn) error,
) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:             nil,
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != apiAddr || (network != "tcp" && network != "tcp4") {
					return nil, fmt.Errorf("%s target %q is not configured endpoint %q", kind, address, apiAddr)
				}
				conn, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				if err := verify(conn); err != nil {
					_ = conn.Close()
					return nil, fmt.Errorf("%s connected listener is unverified: %w", kind, err)
				}
				return conn, nil
			},
		},
	}
}
