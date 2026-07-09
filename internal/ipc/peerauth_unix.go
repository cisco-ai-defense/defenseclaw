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

// KindUnixPeer is the peerIdentity.Kind value assigned to a peer
// whose identity was successfully extracted from a live
// *net.UnixConn. Any non-empty value other than this is treated as
// "not a real UDS peer" by the validator and rejected.
const KindUnixPeer = "UnixPeer"

// peerIdentity carries everything we can learn about a UDS peer at
// accept time.
//
//   - Kind: KindUnixPeer when identity came from a *net.UnixConn;
//     empty otherwise. requireUnixPeer gates on this.
//   - PID / UID / GID: from LOCAL_PEERPID + LOCAL_PEERCRED (darwin)
//     or SO_PEERCRED (linux).
//   - ExePath: absolute path of the peer executable (darwin only,
//     resolved from the `Executable=` line of `codesign -dv +<pid>`).
//     Empty on linux and on darwin when the exec fails.
//   - TeamID / SigningID: codesign attributes (darwin only).
//   - BundleID: CFBundleIdentifier read from the peer app's
//     Info.plist via plutil (darwin only). Empty for non-bundle
//     executables.
//
// All string fields stay empty when the platform lookup is
// unavailable or the peer is unsigned/unbundled; the allow() gate
// then rejects such peers when the corresponding allowlist is
// non-empty.
type peerIdentity struct {
	Kind      string
	PID       int32
	UID       uint32
	GID       uint32
	ExePath   string
	TeamID    string
	SigningID string
	BundleID  string
}

// codesignValidatingListener wraps a UDS net.Listener and enforces
// the Secure-Client codesign identity policy at accept time.
//
// Semantics are AND-with-precondition; a peer must satisfy EVERY
// applicable check to be admitted. See allow() for ordering.
//
// The constructor bypasses the wrapper (returns inner verbatim)
// only when NO check is configured — all three allowlists empty
// and both require-flags off — so we do not pay per-connection
// cost when peer-auth is disabled outright.
type codesignValidatingListener struct {
	inner             net.Listener
	requireUnixPeer   bool
	requireSigningMd  bool // team + signing + bundle all present
	allowedTeamIDs    map[string]struct{}
	allowedSigningIDs map[string]struct{}
	allowedBundleIDs  map[string]struct{}
	logRejectFn       func(peerIdentity, string)
}

// newCodesignValidatingListener wraps a listener with the strict
// Secure-Client peer-auth. When no check is configured at all
// (three empty allowlists AND both require-flags false) the inner
// listener is returned unwrapped — that's the "peer-auth disabled"
// posture for non-managed hosts. Otherwise the returned wrapper
// enforces every configured layer.
func newCodesignValidatingListener(
	inner net.Listener,
	teamIDs, signingIDs, bundleIDs []string,
	requireUnixPeer, requireSigningMetadata bool,
	logReject func(peerIdentity, string),
) net.Listener {
	teams := stringSet(teamIDs)
	signs := stringSet(signingIDs)
	bundles := stringSet(bundleIDs)
	if !requireUnixPeer && !requireSigningMetadata &&
		len(teams) == 0 && len(signs) == 0 && len(bundles) == 0 {
		return inner
	}
	return &codesignValidatingListener{
		inner:             inner,
		requireUnixPeer:   requireUnixPeer,
		requireSigningMd:  requireSigningMetadata,
		allowedTeamIDs:    teams,
		allowedSigningIDs: signs,
		allowedBundleIDs:  bundles,
		logRejectFn:       logReject,
	}
}

// stringSet is a small helper that skips empty strings so a
// [""] operator config doesn't accidentally match every empty
// peer field.
func stringSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		if s != "" {
			out[s] = struct{}{}
		}
	}
	return out
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
		if reason := l.allow(id); reason != "" {
			l.reject(id, reason, c)
			continue
		}
		return c, nil
	}
}

// allow returns the empty string when the peer passes every
// configured check, or a short human-readable rejection reason
// when it fails. Ordering matches the reference in
// /Users/sanjay23/Downloads/GrpcOverUDS 2/IPC/peerauth/types.go
// validate() so operators comparing daemon log lines against the
// reference see the same first-failure semantics.
func (l *codesignValidatingListener) allow(id peerIdentity) string {
	if l.requireUnixPeer && id.Kind != KindUnixPeer {
		return "peer kind must be " + KindUnixPeer
	}
	if l.requireSigningMd {
		switch {
		case id.TeamID == "":
			return "peer signing metadata incomplete: team_id missing"
		case id.SigningID == "":
			return "peer signing metadata incomplete: signing_id missing"
		case id.BundleID == "":
			return "peer signing metadata incomplete: bundle_id missing"
		}
	}
	if len(l.allowedTeamIDs) > 0 {
		if _, ok := l.allowedTeamIDs[id.TeamID]; !ok {
			return fmt.Sprintf("team id %q not allowed", id.TeamID)
		}
	}
	if len(l.allowedSigningIDs) > 0 {
		if _, ok := l.allowedSigningIDs[id.SigningID]; !ok {
			return fmt.Sprintf("signing id %q not allowed", id.SigningID)
		}
	}
	if len(l.allowedBundleIDs) > 0 {
		if _, ok := l.allowedBundleIDs[id.BundleID]; !ok {
			return fmt.Sprintf("bundle id %q not allowed", id.BundleID)
		}
	}
	return ""
}

func (l *codesignValidatingListener) reject(id peerIdentity, reason string, c net.Conn) {
	if l.logRejectFn != nil {
		l.logRejectFn(id, reason)
	}
	_ = c.Close()
}

func (l *codesignValidatingListener) Close() error   { return l.inner.Close() }
func (l *codesignValidatingListener) Addr() net.Addr { return l.inner.Addr() }

// extractPeerIdentity reads peer credentials, marks the identity
// as UnixPeer, and (on darwin) enriches with codesign + bundle
// metadata. Called once per accepted UDS connection.
func extractPeerIdentity(c net.Conn) (peerIdentity, error) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		// Non-UDS conn: leave Kind empty so the requireUnixPeer
		// check catches this even when the caller ignores the
		// error return.
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
	// Successful cred read → this really was a UDS peer.
	id.Kind = KindUnixPeer

	// Best-effort codesign / bundle enrichment by PID. Failures
	// surface as empty ExePath / TeamID / SigningID / BundleID;
	// the allow() call rejects such peers when the corresponding
	// allowlist is configured.
	if id.PID > 0 && readCodesignFn != nil {
		team, signing, bundle, exePath, _ := readCodesignFn(id.PID)
		id.TeamID = team
		id.SigningID = signing
		id.BundleID = bundle
		id.ExePath = exePath
	}
	return id, nil
}

// readPeerIdentity is the platform-specific getsockopt(2) call for
// peer credentials (PID / UID / GID). Implemented in
// peerauth_darwin.go and peerauth_linux.go via init(), so callers
// can rely on it being non-nil under the linux || darwin build tag.
var readPeerIdentity func(fd int, id *peerIdentity) error

// readCodesignFn returns codesign (Team ID, signing identifier)
// and bundle metadata (bundle id, executable path) for a peer PID.
// On darwin this shells out to `/usr/bin/codesign -dv +<pid>` and
// then to `plutil -extract CFBundleIdentifier raw` on the peer's
// containing .app. Non-darwin builds leave this nil so bundle /
// codesign checks are effectively no-ops on Linux.
//
// Test hook: darwin tests overwrite this var to return canned
// values without touching /usr/bin/codesign.
var readCodesignFn func(pid int32) (teamID, signingID, bundleID, exePath string, err error)
