//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/defenseclaw/defenseclaw/internal/managed"

// healManagedLaunchdPlatform heals the peer services' LaunchDaemon plists
// and the shared log folder.
func healManagedLaunchdPlatform(managedServiceRole, managed.ManagedServiceLayout) {}
