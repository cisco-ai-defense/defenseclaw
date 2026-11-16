// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
)

// apiPortHeldError is a gateway that serves hooks on its socket while its
// TCP API listener is not up because another process holds the port. The
// message already names the holder when the lifecycle can see it.
type apiPortHeldError struct{ message string }

func (e *apiPortHeldError) Error() string { return e.message }

// gatewayHealth is the gateway readiness check. It reads the /health
// document over the hook socket, checks that the gateway serves that socket
// (gatewayServing), and returns the document when the gateway reports its
// own TCP API listener as running. The answer on 127.0.0.1:18970 is never
// trusted: another local account can bind the port while the gateway's
// listener is down, and answer there. A gateway from an earlier release
// refuses /health on its socket; its TCP API fallback verifies the connected
// socket against the protected gateway service before reading /health.
func (l *lifecycle) gatewayHealth(ctx context.Context, gateway Unit, serviceUID int) ([]byte, error) {
	env := l.env
	code, body, err := env.HealthGet(ctx)
	if err != nil {
		return nil, env.hookSocketProblem(err)
	}
	if err := env.gatewayServing(ctx, gateway, serviceUID); err != nil {
		return nil, err
	}
	switch {
	case code == http.StatusNotFound || code == http.StatusForbidden:
		return l.apiHealth(ctx, serviceUID)
	case code != http.StatusOK:
		return nil, fmt.Errorf("gateway health on the hook socket returned HTTP %d", code)
	}
	var document struct {
		API struct {
			State     string         `json:"state"`
			LastError string         `json:"last_error"`
			Details   map[string]any `json:"details"`
		} `json:"api"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		return nil, fmt.Errorf("gateway health on the hook socket: %w", err)
	}
	if document.API.State == "running" {
		return body, nil
	}
	retrying, _ := document.API.Details["tcp_bind_retrying"].(bool)
	if held := l.portHeldProblem(ctx, serviceUID, retrying); held != "" {
		return nil, &apiPortHeldError{message: held}
	}
	detail := strings.TrimSpace(document.API.State)
	if detail == "" {
		detail = "state not reported"
	}
	if reason := strings.TrimSpace(document.API.LastError); reason != "" {
		detail += ": " + reason
	}
	message := fmt.Sprintf("the gateway serves hooks on its socket, but its API listener %s is not up (%s)", env.Layout.APIAddr, detail)
	if retrying {
		// The holder is gone or not visible to this account; the gateway
		// takes the port when it is free.
		return nil, &apiPortHeldError{message: message + "; the gateway keeps retrying the port"}
	}
	return nil, errors.New(message)
}

// unresponsiveGatewayProcess is a gateway process the service manager ran
// that did not answer on its hook socket before a repair or ensure restarted
// it (a stopped or hung process).
type unresponsiveGatewayProcess struct {
	unit   string
	pid    int
	reason string
}

// unresponsiveGateway asks the running gateway for its health on the hook
// socket before a repair or ensure of an installed deployment restarts the
// services, and returns it when it does not answer; nil otherwise. Any HTTP
// answer counts as an answer.
func (l *lifecycle) unresponsiveGateway(ctx context.Context, units []Unit, active []string) *unresponsiveGatewayProcess {
	env := l.env
	gateway, ok := gatewayUnitOf(units)
	if !ok || !l.reportChanges || l.opts.NoStart || !contains(active, gateway.Name) {
		return nil
	}
	_, _, err := env.HealthGet(ctx)
	if err == nil {
		return nil
	}
	status, _ := env.Services.Status(ctx, gateway)
	return &unresponsiveGatewayProcess{unit: gateway.Name, pid: status.PID, reason: env.hookSocketProblem(err).Error()}
}

// replacedNote is the change line for the unresponsive gateway once its unit
// runs again: it names the process the restart ended and the new one, and
// is "" when the service manager still runs the same process.
func (u *unresponsiveGatewayProcess) replacedNote(ctx context.Context, services ServiceManager, unit Unit) string {
	now := 0
	if status, err := services.Status(ctx, unit); err == nil {
		now = status.PID
	}
	if u.pid > 0 && now == u.pid {
		return ""
	}
	old, started := "process", "started a new one"
	if u.pid > 0 {
		old = fmt.Sprintf("process %d", u.pid)
	}
	if now > 0 {
		started = fmt.Sprintf("started a new one (pid %d)", now)
	}
	return fmt.Sprintf("terminated the unresponsive %s %s (%s) and %s", u.unit, old, u.reason, started)
}

// hookSocketProblem says in words why the hook socket did not answer. The
// request error names the API address (the request's Host) and Go's dial
// details, which read as if the TCP API had been asked.
func (e *Env) hookSocketProblem(err error) error {
	var reason string
	var netErr net.Error
	var urlErr *url.Error
	switch {
	case errors.Is(err, fs.ErrNotExist):
		reason = "the socket file does not exist"
	case errors.Is(err, syscall.ECONNREFUSED):
		reason = "nothing is listening on it"
	case errors.Is(err, fs.ErrPermission):
		reason = "this account may not connect to it"
	case errors.As(err, &netErr) && netErr.Timeout():
		reason = "it did not answer in time"
	case errors.As(err, &urlErr):
		reason = "it did not answer (" + urlErr.Err.Error() + ")"
	default:
		reason = "it did not answer (" + err.Error() + ")"
	}
	return fmt.Errorf("the gateway does not serve the hook socket %s: %s", e.Layout.HookSocketPath, reason)
}

// apiHealth is readiness for a gateway that answers /health only on the
// TCP API. On macOS the gateway binds that port itself, so a process other
// than the gateway listening there means the answer is not the gateway's.
func (l *lifecycle) apiHealth(ctx context.Context, serviceUID int) ([]byte, error) {
	env := l.env
	code, body, err := env.APIHealthGet(ctx)
	if err != nil {
		return nil, fmt.Errorf("gateway health: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("gateway health returned HTTP %d", code)
	}
	if env.GOOS == "darwin" {
		if held := l.portHeldProblem(ctx, serviceUID, true); held != "" {
			return nil, &apiPortHeldError{message: held}
		}
	}
	return body, nil
}
