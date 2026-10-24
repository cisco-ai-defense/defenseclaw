// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// VerifyPerUserConnectedTuple proves ownership of the accepted server socket
// for a client connection that is already open. The Python CLI invokes this
// before urllib3 writes headers or a body on that connection.
func VerifyPerUserConnectedTuple(local, remote string) error {
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
		return err
	}
	server, err := parse(remote)
	if err != nil {
		return err
	}
	if !client.IP.IsLoopback() || !server.IP.IsLoopback() {
		return fmt.Errorf("connected gateway endpoint is not loopback")
	}
	return verifyPerUserConnectedTuple(client, server)
}

// connectedSocketNameMatches accepts lsof's optional protocol and state text
// while requiring both TCP endpoint ports to match exactly. A prefix match
// could mistake a different same-account connection for the accepted socket.
func connectedSocketNameMatches(name, want string) bool {
	name = strings.TrimPrefix(name, "TCP ")
	tuple, _, _ := strings.Cut(strings.TrimSpace(name), " ")
	return tuple == want
}

// PerUserHookReply is the bounded response sent back to an in-agent plugin.
type PerUserHookReply struct {
	Status     int    `json:"status"`
	Body       string `json:"body"`
	RetryAfter string `json:"retry_after,omitempty"`
}

// NewPerUserGatewayHTTPClient verifies the accepted socket's account before
// any HTTP request writes headers or a body. Go CLI management requests use
// this same transport for every per-user gateway call, including retries.
// A zero timeout leaves long operations bounded by their request context.
func NewPerUserGatewayHTTPClient(timeout time.Duration, apiAddr string) (*http.Client, error) {
	client, err := newPerUserHookHTTPClient(timeout, apiAddr)
	if err != nil {
		return nil, err
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client, nil
}

// PostPerUserHook sends a plugin request only after verifying the owner of
// the very socket that carries its bearer and payload. A separate preflight
// would leave a race when the gateway stops and another account binds its
// port before the plugin opens a second connection.
// errPerUserAnswerIncomplete wraps a body read failure after the gateway
// sent a status line.
var errPerUserAnswerIncomplete = errors.New("per-user gateway answer incomplete")

// PerUserPostOutageExit is the exit status of `hook-post` for a gateway
// outage (PerUserPostOutage), curl's "could not connect" status, which the
// shell hooks and in-agent plugins already read as this account's gateway
// not running.
const PerUserPostOutageExit = 7

// PerUserPostOutage reports whether err, from PostPerUserHook, is a gateway
// outage: this account's gateway refused or dropped the connection before it
// sent any status. A status line followed by a cut-off body, a listener
// whose owner could not be verified, a timeout after the connection and
// every other error are not.
func PerUserPostOutage(err error) bool {
	if err == nil || errors.Is(err, errPerUserAnswerIncomplete) || errors.Is(err, errInvalidHookRequest) ||
		errors.Is(err, errGatewayTookCallNoAnswer) {
		return false
	}
	return gatewayRestartShaped(err)
}

func PostPerUserHook(ctx context.Context, apiAddr, path string, headers map[string]string, body []byte) (PerUserHookReply, error) {
	switch path {
	case "/api/v1/amp/hook", "/api/v1/opencode/hook",
		"/api/v1/codex/hook", "/api/v1/claude-code/hook",
		"/api/v1/copilot/hook", "/api/v1/cursor/hook",
		"/api/v1/devin/hook", "/api/v1/hermes/hook",
		"/api/v1/kiro/hook", "/api/v1/antigravity/hook",
		"/api/v1/inspect/request", "/api/v1/inspect/response",
		"/api/v1/inspect/tool", "/api/v1/inspect/tool-response":
	default:
		return PerUserHookReply{}, fmt.Errorf("unsupported per-user plugin hook path")
	}
	if len(body) > 900*1024 {
		return PerUserHookReply{}, fmt.Errorf("per-user plugin hook body is too large")
	}
	client, err := NewPerUserGatewayHTTPClient(30*time.Second, apiAddr)
	if err != nil {
		return PerUserHookReply{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+apiAddr+path, bytes.NewReader(body))
	if err != nil {
		return PerUserHookReply{}, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	response, err := client.Do(req)
	if err != nil {
		return PerUserHookReply{}, err
	}
	defer response.Body.Close()
	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		return PerUserHookReply{}, fmt.Errorf("per-user gateway hook response redirected")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20+1))
	if err != nil {
		// The gateway sent its status: a cut-off body is its unusable
		// answer, never an outage (PerUserPostOutage).
		return PerUserHookReply{}, fmt.Errorf("%w: %w", errPerUserAnswerIncomplete, err)
	}
	if len(data) > 1<<20 {
		return PerUserHookReply{}, fmt.Errorf("per-user gateway hook response is too large")
	}
	return PerUserHookReply{Status: response.StatusCode, Body: string(data), RetryAfter: response.Header.Get("Retry-After")}, nil
}

// verifiedPerUserHTTPClient proves the owner of the connected socket before
// net/http can write a hook credential or event. Each request gets a fresh
// connection so retries and redirects must pass verification again.
func verifiedPerUserHTTPClient(
	timeout time.Duration,
	apiAddr string,
	dial func(context.Context, string, string) (net.Conn, error),
	verify func(net.Conn) error,
) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if address != apiAddr || (network != "tcp" && network != "tcp4") {
					return nil, fmt.Errorf("per-user gateway target %q is not configured endpoint %q", address, apiAddr)
				}
				conn, err := dial(ctx, network, address)
				if err != nil {
					return nil, err
				}
				if err := verify(conn); err != nil {
					_ = conn.Close()
					return nil, fmt.Errorf("per-user gateway connected listener is unverified: %w", err)
				}
				return conn, nil
			},
		},
	}
}
