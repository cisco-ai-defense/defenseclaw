// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"time"
)

// CommandRefusalPath is the hook-socket route a managed CLI reports a refused
// command on. The gateway attributes the row to the socket's kernel-verified
// peer, so the request carries no identity of its own.
const CommandRefusalPath = "/api/v1/managed/refusal"

// CommandRefusalClient is the X-DefenseClaw-Client value of a refusal report.
// The hook socket's CSRF gate refuses a POST without that header.
const CommandRefusalClient = "defenseclaw-cli"

// commandRefusalTimeout bounds a report, so a stopped or hung gateway never
// delays the refusal the user sees for longer than this.
const commandRefusalTimeout = 3 * time.Second

// ReportCommandRefusal posts one refused-command report to the gateway's hook
// socket and returns the HTTP status. Only the fixed command name and the
// allowlisted reason are sent: CLI arguments can contain secrets.
func ReportCommandRefusal(ctx context.Context, socket, command, reason string) (int, error) {
	body, err := json.Marshal(struct {
		Action  string `json:"action"`
		Target  string `json:"target"`
		Details string `json:"details"`
		Reason  string `json:"reason,omitempty"`
	}{Action: "action", Target: command, Details: "command=" + command, Reason: reason})
	if err != nil {
		return 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, commandRefusalTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://defenseclaw-hook"+CommandRefusalPath, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-DefenseClaw-Client", CommandRefusalClient)
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return 0, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	_ = response.Body.Close()
	return response.StatusCode, nil
}
