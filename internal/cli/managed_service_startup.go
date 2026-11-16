// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"time"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedServiceRole names the long-running managed services. Only these
// repair managed paths before config load and keep retrying a config load
// that failed; every other command keeps the fail-fast behaviour.
type managedServiceRole string

const (
	managedServiceNone     managedServiceRole = ""
	managedServiceGateway  managedServiceRole = "gateway"
	managedServiceGuardian managedServiceRole = "hook-guardian"
)

func managedServiceRoleFor(cmd *cobra.Command) managedServiceRole {
	switch {
	case cmd == nil:
		return managedServiceNone
	case cmd.Parent() == nil:
		return managedServiceGateway
	case cmd == enterpriseHooksWatchCmd:
		return managedServiceGuardian
	}
	return managedServiceNone
}

// Bounded backoff between config load attempts of a service that started
// degraded.
var (
	managedConfigRetryInitialDelay = 5 * time.Second
	managedConfigRetryMaxDelay     = 5 * time.Minute
	managedServiceConfigLoader     = loadGatewayConfigV8
)

// loadGatewayConfigV8ForService loads config for cmd. For a managed service
// it first repairs the paths the LaunchDaemon environment pins (repair before
// validate), and where the platform supports it a failed load does not exit:
// the service logs that it started degraded and keeps repairing and retrying
// with a bounded backoff until config loads. A missing config is left to the
// caller's own wait. Other commands load once.
func loadGatewayConfigV8ForService(
	ctx context.Context,
	cfgPath string,
	role managedServiceRole,
) (*config.Config, *observabilityV8Startup, error) {
	if role != managedServiceNone {
		noteManagedServiceStartPlatform(role)
		repairManagedServicePathsBeforeConfigLoadPlatform(role)
	}
	loaded, startup, err := managedServiceConfigLoader(cfgPath)
	if err == nil || role == managedServiceNone || !managedServiceRetriesConfigLoadPlatform() ||
		!managedEnterpriseFromPin() || isMissingConfigErr(err) {
		return loaded, startup, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	lastReason := err.Error()
	managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
		"component": string(role),
		"path":      cfgPath,
		"subsystem": "config",
		"reason":    "config load failed at startup; repairing and retrying instead of exiting: " + lastReason,
	})
	delay := managedConfigRetryInitialDelay
	for {
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, nil, err
		case <-timer.C:
		}
		repairManagedServicePathsBeforeConfigLoadPlatform(role)
		loaded, startup, err = managedServiceConfigLoader(cfgPath)
		if err == nil {
			managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
				"component": string(role),
				"path":      cfgPath,
				"subsystem": "config",
				"reason":    "config loaded after a degraded start",
			})
			return loaded, startup, nil
		}
		if isMissingConfigErr(err) {
			return nil, nil, err
		}
		if reason := err.Error(); reason != lastReason {
			lastReason = reason
			managed.EmitResilienceEvent(managed.MarkerDegraded, map[string]string{
				"component": string(role),
				"path":      cfgPath,
				"subsystem": "config",
				"reason":    "config load still failing: " + reason,
			})
		}
		if delay *= 2; delay > managedConfigRetryMaxDelay {
			delay = managedConfigRetryMaxDelay
		}
	}
}
