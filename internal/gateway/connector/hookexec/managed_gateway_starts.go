// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"sync"
	"time"
)

// errGatewayStartFailing ends a hook request early when the managed gateway
// service keeps failing to start. Its socket stays open (systemd holds it
// and restarts the service without a limit), so without this a hook waits
// its whole budget, about 30 seconds per prompt, before failing closed.
var errGatewayStartFailing = errors.New("the managed gateway service keeps failing to start")

// gatewayServiceState is the service manager's view of the managed gateway.
type gatewayServiceState struct {
	Active   string // ActiveState: active, activating, failed, ...
	Sub      string // SubState: running, start, auto-restart, ...
	Restarts int    // NRestarts
}

// gatewayStartWatchInterval is how often a waiting hook asks the service
// manager about the gateway.
var gatewayStartWatchInterval = time.Second

// watchManagedGatewayStarts returns ctx, ended with errGatewayStartFailing
// once the standalone gateway service is seen failing a start that began
// while this hook waited. stop ends the watch (call it once the response
// arrives); release frees ctx. Off Linux, or outside the standalone
// profile, ctx is returned unchanged.
func watchManagedGatewayStarts(ctx context.Context, opts Options) (watched context.Context, stop, release func()) {
	probe := standaloneGatewayServiceProbe
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || probe == nil {
		return ctx, func() {}, func() {}
	}
	watched, cancel := context.WithCancelCause(ctx)
	done := make(chan struct{})
	var once sync.Once
	stop = func() { once.Do(func() { close(done) }) }
	go watchGatewayStarts(watched, done, cancel, probe, gatewayStartWatchInterval)
	return watched, stop, func() { stop(); cancel(nil) }
}

// watchGatewayStarts polls probe until the gateway runs, the watch stops,
// or a restart counted after the first poll ends in another failure. A
// single crash followed by a good start keeps the request waiting.
func watchGatewayStarts(
	ctx context.Context,
	done <-chan struct{},
	cancel context.CancelCauseFunc,
	probe func(context.Context) (gatewayServiceState, error),
	interval time.Duration,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	baseline := -1
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
		}
		state, err := probe(ctx)
		switch {
		case err != nil, state.Active == "active":
			// No answer from the service manager, or a running gateway
			// whose reply is just slow: keep waiting as before.
			return
		case state.Active == "failed":
			cancel(errGatewayStartFailing)
			return
		case baseline < 0:
			baseline = state.Restarts
		case state.Restarts > baseline && state.Sub == "auto-restart":
			cancel(errGatewayStartFailing)
			return
		}
	}
}
