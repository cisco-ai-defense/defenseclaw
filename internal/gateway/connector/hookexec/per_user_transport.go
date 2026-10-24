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
	"strings"
	"time"
)

// VerifyPerUserConnectedTuple proves ownership of the accepted server socket
// for a client connection that is already open. The Python CLI invokes this
// before urllib3 writes headers or a body on that connection.
func VerifyPerUserConnectedTuple(local, remote string) error {
	client, server, err := parseConnectedTuple(local, remote)
	if err != nil {
		return err
	}
	return verifyPerUserConnectedTuple(client, server)
}

// VerifyLocalPeer is the one check that a loopback TCP connection
// DefenseClaw opened to a local service it does not run itself (the bundled
// observability stack's collector) reaches that service and not another
// account: the accepted server socket must belong to this account or to the
// system account (root, LocalSystem), which can read this account's data
// anyway. A socket of any other account, or one whose owner cannot be read,
// is sent no byte (GAP-1087). It refuses to send; it never blocks a call.
func VerifyLocalPeer(conn net.Conn) error {
	local, localOK := conn.LocalAddr().(*net.TCPAddr)
	remote, remoteOK := conn.RemoteAddr().(*net.TCPAddr)
	if !localOK || !remoteOK {
		return fmt.Errorf("local peer is not a TCP connection")
	}
	return verifyLocalPeerTuple(local, remote)
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
// sent any status, or another account's listener, or one whose owner could
// not be verified, holds its port (errPerUserGatewayPeerUnverified: nothing
// was sent to it, and this account's gateway is not reachable there). A
// status line followed by a cut-off body, a timeout after the connection and
// every other error are not.
func PerUserPostOutage(err error) bool {
	if err == nil || errors.Is(err, errPerUserAnswerIncomplete) || errors.Is(err, errInvalidHookRequest) ||
		errors.Is(err, errGatewayTookCallNoAnswer) {
		return false
	}
	return errors.Is(err, errPerUserGatewayPeerUnverified) || gatewayRestartShaped(err)
}

// errPerUserGatewayPeerUnverified wraps a per-user connection whose listener
// is not proven to be this account's: the hook wrote nothing to it. It is a
// refusal to send, never a block of the call by itself: the call takes the
// outage decision (withPerUserOutage, config.HookOutageFailMode), as when
// this account's gateway is not running.
var errPerUserGatewayPeerUnverified = errors.New("per-user gateway listener is not proven to be this account's")

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
// net/http can write a hook credential or event (verifiedGatewayHTTPClient).
func verifiedPerUserHTTPClient(
	timeout time.Duration,
	apiAddr string,
	dial func(context.Context, string, string) (net.Conn, error),
	verify func(net.Conn) error,
) *http.Client {
	return verifiedGatewayHTTPClient(timeout, apiAddr, "per-user gateway", dial, func(conn net.Conn) error {
		if err := verify(conn); err != nil {
			return fmt.Errorf("%w: %v", errPerUserGatewayPeerUnverified, err)
		}
		return nil
	})
}
