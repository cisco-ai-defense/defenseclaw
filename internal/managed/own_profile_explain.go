// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// OwnProfileExplainPath is the hook-socket route on which a standard user of
// a managed computer reads the guardrail profile the gateway applies to
// their own account (GAP-0431, GAP-0422). The gateway explains the socket's
// kernel-verified peer and nobody else: users see only their own policy.
const OwnProfileExplainPath = "/api/v1/managed/profile-explain"

// ownProfileExplainTimeout bounds one explain: the gateway may look the
// account up in the directory.
const ownProfileExplainTimeout = 20 * time.Second

// ownProfileExplainMaxBytes bounds the answer read.
const ownProfileExplainMaxBytes = 1 << 20

// ExplainOwnProfile asks the gateway on the hook socket which guardrail
// profile the calling account gets, for connector and agent (either may be
// empty); user, when set, is the caller's own spelling, which the gateway
// checks. It returns the HTTP status and the JSON answer.
func ExplainOwnProfile(ctx context.Context, socket, user, connector, agent string) (int, []byte, error) {
	query := url.Values{}
	for key, value := range map[string]string{"user": user, "connector": connector, "agent": agent} {
		if value != "" {
			query.Set(key, value)
		}
	}
	target := "http://defenseclaw-hook" + OwnProfileExplainPath
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	ctx, cancel := context.WithTimeout(ctx, ownProfileExplainTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("X-DefenseClaw-Client", CommandRefusalClient)
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, ownProfileExplainMaxBytes+1))
	if err != nil {
		return response.StatusCode, nil, err
	}
	if len(body) > ownProfileExplainMaxBytes {
		return response.StatusCode, nil, fmt.Errorf("the gateway's answer is larger than %d bytes", ownProfileExplainMaxBytes)
	}
	return response.StatusCode, body, nil
}
