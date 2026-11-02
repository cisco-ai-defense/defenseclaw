//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Config load failures keep their existing exit behaviour off macOS.
func managedServiceRetriesConfigLoadPlatform() bool { return false }

// repairManagedServicePathsBeforeConfigLoadPlatform is macOS-only; the
// Windows services repair through their own descriptor batches.
func repairManagedServicePathsBeforeConfigLoadPlatform(managedServiceRole) {}

// repairGatewayRuntimePlatform is macOS-only, where the gateway runs as root
// and owns its runtime objects.
func repairGatewayRuntimePlatform(*config.Config) {}

// startManagedPeerHealPlatform is macOS-only: the gateway and the guardian
// cross-heal each other's LaunchDaemon plists and the shared log folder.
func startManagedPeerHealPlatform(context.Context, managedServiceRole) {}

// Restart-loop holding is macOS-only; elsewhere a failed service exits and
// its service manager applies its own restart policy.
func noteManagedServiceStartPlatform(managedServiceRole) {}

func holdManagedServiceAfterFailurePlatform(context.Context, managedServiceRole, error) bool {
	return false
}
