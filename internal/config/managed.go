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
// Socket path and mode are resolved at server start when left empty;
// the resolver in internal/ipc/paths.go picks per-platform defaults
// so the installer does not have to hard-code them into the rendered
// config.yaml.
type ManagedIPCConfig struct {
	// SocketPath overrides the resolver-picked path. Empty is the
	// normal case in production — the installer sets deployment_mode
	// and allowed_uids and lets the resolver land the socket at the
	// standard per-platform location.
	SocketPath string `mapstructure:"socket_path" yaml:"socket_path,omitempty"`

	// SocketMode overrides the resolver-picked octal mode. Empty
	// means the resolver uses 0666 (managed_enterprise, gated by
	// AllowedUIDs) or 0600 (unmanaged/dev). Wider than the per-mode
	// ceiling is refused at server start.
	SocketMode string `mapstructure:"socket_mode" yaml:"socket_mode,omitempty"`

	// AllowedUIDs is the peer-cred allowlist enforced at accept-time.
	// Mandatory in managed_enterprise (empty + world-writable socket
	// refuses to start). Populated by the installer with the UID(s)
	// under which the consumer UI runs.
	AllowedUIDs []int `mapstructure:"allowed_uids" yaml:"allowed_uids,omitempty"`
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
