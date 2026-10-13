// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// lifecycleGatewayPolicy is the policy block of the read-only lifecycle
// status, which reads /health from the gateway it verified serves the hook
// socket; nil when that status has none.
func lifecycleGatewayPolicy(ctx context.Context) *enterprisestatus.PolicyState {
	env, err := newUnixLifecycleEnv(runtime.GOOS)
	if err != nil {
		return nil
	}
	return enterpriseunix.Run(ctx, env, enterpriseunix.Options{Action: enterpriseunix.ActionStatus}).Policy
}

func platformBundleSessionStatus(ctx context.Context) enterprisestatus.SessionRestartStatus {
	env, err := newUnixLifecycleEnv(runtime.GOOS)
	if err != nil {
		return enterprisestatus.SessionRestartStatus{State: "unknown", Entries: []enterprisestatus.SessionEntry{}}
	}
	return env.UnprotectedSessions(ctx)
}
