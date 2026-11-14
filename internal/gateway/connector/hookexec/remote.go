// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// RemoteCall is one hook call whose transport is not this package's: the
// Agent Substrate actor kit (internal/substrate/kit) posts the event to the
// cluster gateway itself and uses these functions only to answer the agent
// in its connector's native format, so the actor and the host agree byte for
// byte on what an allow, a block, an ask or a failure looks like.
//
// A remote call has no local install state, no per-user gateway, no managed
// runtime and no Secure Client: every host-only branch of the runner is off.
type RemoteCall struct {
	// Connector is a SupportedConnectors name ("claudecode", "codex", ...).
	Connector string
	// Event is the agent hook event ("PreToolUse"); Claude Code binds it in
	// the payload's hook_event_name, the others on the hook command line.
	Event string
	// HookContractID is the connector hook contract the settings were
	// rendered for (Codex reads it to tell which events it may control).
	HookContractID string
	// FailMode is the outage mode, "open" or "closed". Anything but an
	// outage (an answer that is not a verdict, an oversized event, a refusal)
	// is closed whatever it says, as on a host.
	FailMode string
	// LogHome, when set, is the directory whose logs/ subdirectory takes the
	// hook-failure rows ("" writes none).
	LogHome string
	// Payload is the agent's event, kept for failure-row correlation only.
	Payload []byte
	Stdout  io.Writer
	Stderr  io.Writer
	Now     func() time.Time
}

func (c RemoteCall) options() (Options, spec, error) {
	sp, ok := specFor(c.Connector)
	if !ok {
		return Options{}, spec{}, fmt.Errorf("connector %q has no native hook contract", c.Connector)
	}
	now := c.Now
	if now == nil {
		now = time.Now
	}
	opts := Options{
		Connector:      c.Connector,
		Event:          strings.TrimSpace(c.Event),
		HookContractID: c.HookContractID,
		FailMode:       normalizeFailMode(c.FailMode),
		Home:           c.LogHome,
		Stdout:         c.Stdout,
		Stderr:         c.Stderr,
		Now:            now,
		StartedAt:      now(),
		failurePayload: c.Payload,
	}
	if opts.Stdout == nil {
		opts.Stdout = io.Discard
	}
	if opts.Stderr == nil {
		opts.Stderr = io.Discard
	}
	return opts, sp, nil
}

// RemoteAnswer writes the agent-native answer for the gateway's reply
// (status and body) and returns the hook's exit code. A 2xx body is shaped
// exactly as the host runner shapes it. A 502, 503 or 504 is an outage and
// follows FailMode; any other status is a refusal and closes.
func RemoteAnswer(c RemoteCall, status int, body []byte) (int, error) {
	opts, sp, err := c.options()
	if err != nil {
		return blockExit, err
	}
	switch {
	case status >= 200 && status < 300:
		return sp.decide(opts, body), nil
	case status == 502 || status == 503 || status == 504:
		return failUnreachable(opts, sp, opts.FailMode, fmt.Sprintf("the DefenseClaw gateway in the cluster is not available (status %d)", status)), nil
	case status == 401 || status == 403:
		// Not "HTTP 401/403": the host's token-drift advice does not apply.
		return failResponse(opts, sp, "closed", fmt.Sprintf("the DefenseClaw gateway in the cluster refused this actor (status %d): "+
			"its identity was not accepted; the cluster administrator runs `defenseclaw substrate doctor`", status)), nil
	default:
		return failResponse(opts, sp, "closed", fmt.Sprintf("the DefenseClaw gateway in the cluster answered status %d", status)), nil
	}
}

// RemoteUnreachable writes the agent-native answer for a call whose gateway
// never answered (after the transport's own retry) and returns the exit
// code. It follows FailMode.
func RemoteUnreachable(c RemoteCall, reason string) (int, error) {
	opts, sp, err := c.options()
	if err != nil {
		return blockExit, err
	}
	return failUnreachable(opts, sp, opts.FailMode, reason), nil
}

// RemoteRefused writes the agent-native closed answer for a call the kit
// itself refuses (an oversized event, an unreadable payload, a kit that is
// not installed correctly) and returns the exit code. It is closed in every
// fail mode.
func RemoteRefused(c RemoteCall, reason string) (int, error) {
	opts, sp, err := c.options()
	if err != nil {
		return blockExit, err
	}
	return failResponse(opts, sp, "closed", reason), nil
}
