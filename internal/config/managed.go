// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedIPCConfig controls the local UDS gRPC server that external
// consumers (Cisco Secure Client GUI) use to observe DefenseClaw
// health, aggregate stats, and user-visible notifications.
//
// The server only starts when Config.ManagedIPCEnabled() returns
// true. In v1 that requires deployment_mode == managed_enterprise
// (installer path) — the IPC surface is intentionally unavailable
// in unmanaged / BYOD / CI / sandboxed / server / saas modes so a
// misconfigured host cannot expose it by accident.
//
// Access is defended by two independent layers:
//
//  1. Filesystem perms: the socket is created as root:staff 0660 in
//     managed_enterprise, so only root and processes running as the
//     console user (member of group staff on macOS) can connect at
//     all. Non-staff callers are rejected by the kernel before any
//     bytes are read.
//
//  2. Codesign peer-auth at accept-time: managed_enterprise ships a
//     strict Secure-Client allowlist by default (see
//     DefaultSecureClientPolicy). Every incoming connection has its
//     peer identity extracted (LOCAL_PEERPID / LOCAL_PEERCRED) and
//     enriched with codesign metadata (Team ID, signing identifier,
//     bundle id). A peer passes only when ALL three identity fields
//     match the allowlists AND the peer connected via a real UDS
//     (Kind == "UnixPeer"). Any missing field, wrong value, or
//     non-UDS transport is rejected. Operator config can override
//     one or more of the three allowlists per-list; unset lists
//     fall back to the compiled defaults.
//
// Socket path and mode are resolved at server start when left empty;
// the resolver in internal/ipc/paths.go picks per-platform defaults
// so the installer does not have to hard-code them into the rendered
// config.yaml.
type ManagedIPCConfig struct {
	// SocketPath overrides the resolver-picked path. Empty is the
	// normal case in production — the resolver lands the socket at
	// the standard per-platform location under the install prefix.
	SocketPath string `mapstructure:"socket_path" yaml:"socket_path,omitempty"`

	// SocketMode overrides the resolver-picked octal mode. Empty
	// means the resolver uses 0660 (managed_enterprise, gated by
	// group=staff ownership) or 0600 (unmanaged/dev). Wider than
	// the per-mode ceiling is refused at server start; the
	// managed_enterprise ceiling is 0660 so an operator override
	// cannot re-open the world-writable path.
	SocketMode string `mapstructure:"socket_mode" yaml:"socket_mode,omitempty"`

	// AllowedTeamIDs is the codesign Team-ID allowlist. Empty in
	// managed_enterprise means "use DefaultSecureClientPolicy's
	// team id"; non-empty replaces the default entirely.
	AllowedTeamIDs []string `mapstructure:"allowed_team_ids" yaml:"allowed_team_ids,omitempty"`

	// AllowedSigningIDs is the codesign signing-identifier allowlist
	// (the `Identifier=` line from `codesign -dv`). Empty in
	// managed_enterprise means "use DefaultSecureClientPolicy's
	// signing id"; non-empty replaces the default entirely.
	AllowedSigningIDs []string `mapstructure:"allowed_signing_ids" yaml:"allowed_signing_ids,omitempty"`

	// AllowedBundleIDs is the CFBundleIdentifier allowlist (read
	// from the peer app's Info.plist via plutil). Empty in
	// managed_enterprise means "use DefaultSecureClientPolicy's
	// bundle id"; non-empty replaces the default entirely. Only
	// applied on darwin — Linux peers have no bundle id concept
	// and the check is skipped there.
	AllowedBundleIDs []string `mapstructure:"allowed_bundle_ids" yaml:"allowed_bundle_ids,omitempty"`
}

// ManagedIPCEnabled reports whether the local UDS gRPC server should
// start. True only when deployment_mode is managed_enterprise. The
// IPC surface has no unmanaged escape hatch: it is either an
// enterprise-installed feature or absent.
func (c *Config) ManagedIPCEnabled() bool {
	if c == nil {
		return false
	}
	return managed.IsManagedEnterprise(c.DeploymentMode)
}

// SecureClientTeamID is the Cisco Team Identifier under which the
// Cisco Secure Client GUI is signed. Compiled-in default for the
// strict peer-auth policy applied in managed_enterprise.
const SecureClientTeamID = "DE8Y96K9QP"

// SecureClientSigningID is the codesign `Identifier=` value the
// Secure Client GUI ships with. Doubles as the CFBundleIdentifier
// value (see SecureClientBundleID), which is expected for a
// bundle-signed app.
const SecureClientSigningID = "com.cisco.secureclient.gui"

// SecureClientBundleID is the CFBundleIdentifier of the Cisco
// Secure Client GUI. Extracted from the peer executable's
// enclosing .app / Contents/Info.plist at accept time.
const SecureClientBundleID = "com.cisco.secureclient.gui"

// DefaultSecureClientPolicy is the compiled-in peer-auth allowlist
// applied to every managed_enterprise install that has not
// overridden AllowedTeamIDs / AllowedSigningIDs / AllowedBundleIDs
// in config.yaml. Only the Cisco Secure Client GUI matches all
// three fields; every other codesign identity is rejected at
// accept-time.
func DefaultSecureClientPolicy() ManagedIPCConfig {
	return ManagedIPCConfig{
		AllowedTeamIDs:    []string{SecureClientTeamID},
		AllowedSigningIDs: []string{SecureClientSigningID},
		AllowedBundleIDs:  []string{SecureClientBundleID},
	}
}

// Peer-auth Kind literals. Duplicated here (rather than imported
// from internal/ipc/peerauth_unix.go) to avoid an import cycle: the
// ipc package imports internal/config, so a config → ipc edge would
// break the build. The values MUST stay in sync — the value lookup
// helpers (peerauth_unix.go / peerauth_windows.go) are the runtime
// sources; this file's role is to surface the effective KIND to
// callers that need to compose diagnostic output BEFORE the ipc
// server is constructed (e.g. spec 004's startup log line).
const (
	peerAuthKindUnixPeer                = "UnixPeer"
	peerAuthKindUnixPeerUnauthenticated = "UnixPeerUnauthenticated"
)

// EffectivePeerAuthKind reports which peer-auth kind the IPC accept
// path will report for peers on the current runtime, given a config.
// Returns "" when ManagedIPCEnabled() is false — no IPC server, no
// peer-auth surface.
//
//   - macOS + Linux managed_enterprise: `"UnixPeer"` (codesign +
//     LOCAL_PEERCRED path in peerauth_unix.go / peerauth_darwin.go).
//   - Windows managed_enterprise: `"UnixPeerUnauthenticated"` — the
//     initial-cut deferred-auth posture (spec 004 REQ-06 / REQ-11).
//     The socket-file DACL is the access boundary; full peer-auth is
//     a follow-up spec per parity-plan §4.4.
//
// The GA release-gate at internal/ipc/authposture_gagate.go refuses
// a release-candidate build in which this helper can still return
// "UnixPeerUnauthenticated" (spec 004 REQ-18 + REQ-19).
func (c *Config) EffectivePeerAuthKind() string {
	if !c.ManagedIPCEnabled() {
		return ""
	}
	if runtime.GOOS == "windows" {
		return peerAuthKindUnixPeerUnauthenticated
	}
	return peerAuthKindUnixPeer
}
