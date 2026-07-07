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

// ManagedIPCConfig controls the local UDS gRPC server that AVC (Cisco
// Secure Client) consumes to observe DefenseClaw health, aggregate
// stats, and user-visible notifications.
//
// The server is started only when Config.ManagedIPCEnabled() returns
// true, which is derived from either:
//   - deployment_mode == managed_enterprise (installer path), or
//   - managed.enabled == true (developer escape hatch).
//
// Socket path and mode are resolved at server start when left empty;
// the resolver in internal/ipc/paths.go picks per-platform defaults
// so the installer does not have to hard-code them into the rendered
// config.yaml.
type ManagedIPCConfig struct {
	// Enabled is a manual override that turns on the UDS gRPC server
	// even when deployment_mode is not managed_enterprise. Intended
	// for local development so contributors do not need the
	// enterprise trust chain to test the socket.
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`

	// SocketPath overrides the resolver-picked path. Empty is the
	// normal case in production — the installer just sets
	// deployment_mode and allowed_uids and lets the resolver land the
	// socket at the standard per-platform location.
	SocketPath string `mapstructure:"socket_path" yaml:"socket_path,omitempty"`

	// SocketMode overrides the resolver-picked octal mode. Empty
	// means the resolver uses 0666 (managed_enterprise, gated by
	// AllowedUIDs) or 0600 (unmanaged/dev). Wider than the per-mode
	// ceiling is refused at server start.
	SocketMode string `mapstructure:"socket_mode" yaml:"socket_mode,omitempty"`

	// AllowedUIDs is the peer-cred allowlist enforced at accept-time.
	// Mandatory in managed_enterprise (empty + world-writable socket
	// refuses to start). Populated by the installer with the UID(s)
	// under which the AVC UI runs.
	AllowedUIDs []int `mapstructure:"allowed_uids" yaml:"allowed_uids,omitempty"`
}

// ManagedIPCEnabled reports whether the local UDS gRPC server should
// start. True when deployment_mode is managed_enterprise, or when the
// operator has manually flipped Managed.Enabled for development.
func (c *Config) ManagedIPCEnabled() bool {
	if c == nil {
		return false
	}
	if c.Managed.Enabled {
		return true
	}
	return managed.IsManagedEnterprise(c.DeploymentMode)
}
