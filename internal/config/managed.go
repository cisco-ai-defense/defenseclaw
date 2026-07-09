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

import "github.com/defenseclaw/defenseclaw/internal/managed"

// ManagedIPCConfig controls the local UDS gRPC server that external
// consumers use to observe DefenseClaw health, aggregate stats, and
// user-visible notifications.
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
//  2. Codesign peer-auth at accept-time: when either allowlist below
//     is non-empty, every incoming connection has its peer executable
//     resolved (LOCAL_PEERPID → proc_pidpath) and inspected with
//     `codesign -dv --verbose=4`; the peer passes only if its Team ID
//     or its signing identifier is on the allowlist. When both
//     allowlists are empty the peer-auth layer is off and access is
//     enforced by fs perms alone.
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

	// AllowedTeamIDs is the codesign Team-ID allowlist. A peer whose
	// codesign TeamIdentifier is on this list passes the peer-auth
	// check. Both AllowedTeamIDs and AllowedSigningIDs empty disables
	// the codesign check entirely (fs perms are then the only gate).
	AllowedTeamIDs []string `mapstructure:"allowed_team_ids" yaml:"allowed_team_ids,omitempty"`

	// AllowedSigningIDs is the codesign signing-identifier allowlist
	// (the `Identifier=` line from `codesign -dv`). Complements
	// AllowedTeamIDs; a peer passes when its signing-id is on this
	// list, so operators can pin a specific bundle even from an
	// otherwise-unrestricted Team ID.
	AllowedSigningIDs []string `mapstructure:"allowed_signing_ids" yaml:"allowed_signing_ids,omitempty"`
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
