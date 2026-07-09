// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package ipc

import (
	"fmt"
	"net"
)

// peerIdentity carries everything we can learn about a UDS peer at
// accept time. PID + UID + GID come from the getsockopt(2) syscalls;
// TeamID + SigningID come from `codesign -dv +<pid>` on darwin (the
// system tool accepts a PID directly and does the exe-path + digest
// walk itself, so we do not have to resolve /proc-style paths).
// TeamID / SigningID stay empty when the platform lookup is
// unavailable or the peer is unsigned.
type peerIdentity struct {
	PID       int32
	UID       uint32
	GID       uint32
	TeamID    string
	SigningID string
}

// codesignValidatingListener wraps a UDS net.Listener and enforces
// a codesign identity allowlist at accept time. A peer passes when
// its Team ID is on AllowedTeamIDs OR its signing identifier is on
// AllowedSigningIDs. Rejected connections are closed silently and
// the gRPC server never sees them.
//
// When both allowlists are empty the listener is bypassed entirely
// by the caller (newCodesignValidatingListener returns inner
// verbatim) so the accept path has no per-connection cost.
type codesignValidatingListener struct {
	inner             net.Listener
	allowedTeamIDs    map[string]struct{}
	allowedSigningIDs map[string]struct{}
	logRejectFn       func(peerIdentity, string)
}

// newCodesignValidatingListener wraps a listener with codesign
// peer-auth. If both allowlists are empty the codesign check is
// disabled and the inner listener is returned unwrapped — this is
// the intended production posture for hosts where filesystem
// perms alone are the trust boundary.
func newCodesignValidatingListener(inner net.Listener, teamIDs, signingIDs []string, logReject func(peerIdentity, string)) net.Listener {
	if len(teamIDs) == 0 && len(signingIDs) == 0 {
		return inner
	}
	teams := make(map[string]struct{}, len(teamIDs))
	for _, t := range teamIDs {
		if t != "" {
			teams[t] = struct{}{}
		}
	}
	signs := make(map[string]struct{}, len(signingIDs))
	for _, s := range signingIDs {
		if s != "" {
			signs[s] = struct{}{}
		}
	}
	if len(teams) == 0 && len(signs) == 0 {
		// Config had entries but every entry was the empty string.
		// Treat that as "no allowlist configured" rather than
		// silently rejecting every peer — the operator meant to
		// disable the check.
		return inner
	}
	return &codesignValidatingListener{
		inner:             inner,
		allowedTeamIDs:    teams,
		allowedSigningIDs: signs,
		logRejectFn:       logReject,
	}
}

func (l *codesignValidatingListener) Accept() (net.Conn, error) {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			return nil, err
		}
		id, extractErr := extractPeerIdentity(c)
		if extractErr != nil {
			l.reject(id, extractErr.Error(), c)
			continue
		}
		if !l.allow(id) {
			l.reject(id, "codesign identity not in allow list", c)
			continue
		}
		return c, nil
	}
}

func (l *codesignValidatingListener) allow(id peerIdentity) bool {
	if id.TeamID != "" {
		if _, ok := l.allowedTeamIDs[id.TeamID]; ok {
			return true
		}
	}
	if id.SigningID != "" {
		if _, ok := l.allowedSigningIDs[id.SigningID]; ok {
			return true
		}
	}
	return false
}

func (l *codesignValidatingListener) reject(id peerIdentity, reason string, c net.Conn) {
	if l.logRejectFn != nil {
		l.logRejectFn(id, reason)
	}
	_ = c.Close()
}

func (l *codesignValidatingListener) Close() error   { return l.inner.Close() }
func (l *codesignValidatingListener) Addr() net.Addr { return l.inner.Addr() }

// extractPeerIdentity reads peer credentials + resolves the peer's
// executable path + reads codesign metadata (darwin only). Called
// once per accepted UDS connection.
func extractPeerIdentity(c net.Conn) (peerIdentity, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return peerIdentity{}, fmt.Errorf("ipc: peer identity: expected *net.UnixConn, got %T", c)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peerIdentity{}, fmt.Errorf("ipc: peer identity: syscall conn: %w", err)
	}
	var (
		id     peerIdentity
		optErr error
	)
	ctrlErr := raw.Control(func(fd uintptr) {
		optErr = readPeerIdentity(int(fd), &id)
	})
	if ctrlErr != nil {
		return id, fmt.Errorf("ipc: peer identity: control: %w", ctrlErr)
	}
	if optErr != nil {
		return id, optErr
	}
	// Best-effort codesign lookup by PID. Failures surface as
	// empty TeamID / SigningID; the allow() call above rejects
	// such peers when an allowlist is configured.
	if id.PID > 0 && readCodesignFn != nil {
		team, sign, _ := readCodesignFn(id.PID)
		id.TeamID = team
		id.SigningID = sign
	}
	return id, nil
}

// readPeerIdentity is the platform-specific getsockopt(2) call for
// peer credentials (PID / UID / GID). Implemented in peerauth_darwin.go
// and peerauth_linux.go via init(), so callers can rely on it being
// non-nil under the linux || darwin build tag.
var readPeerIdentity func(fd int, id *peerIdentity) error

// readCodesignFn returns the codesign TeamIdentifier and Identifier
// for a peer PID (darwin: `/usr/bin/codesign -dv +<pid>`). Non-darwin
// builds leave this nil so the check is bypassed. Overridable in
// tests to avoid an exec.
var readCodesignFn func(pid int32) (teamID, signingID string, err error)
