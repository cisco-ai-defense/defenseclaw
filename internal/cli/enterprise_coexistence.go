// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winenterprise"
)

// refusePerUserGatewayBesideEnterprise stops a per-user gateway from starting
// on a Windows computer that has an administrator-managed enterprise
// deployment. Both would serve hooks on the same local port, and the managed
// hooks of every user fail closed while another listener holds it. It is a
// no-op off Windows and for the enterprise gateway service itself.
var refusePerUserGatewayBesideEnterprise = func() error {
	return winenterprise.RefusePerUser("start its gateway")
}

// refuseRunningPerUserGatewayBesideEnterprise is the same check for a
// per-user gateway that was already running when the enterprise service was
// registered, for example when Secure Client deploys the enterprise product
// during a user's session. The start gate cannot see that case.
var refuseRunningPerUserGatewayBesideEnterprise = func() error {
	return winenterprise.RefusePerUser("keep its gateway running")
}

var (
	// The enterprise SCM deployment exists only on Windows.
	enterpriseCoexistenceWatchSupported = runtime.GOOS == "windows"
	// enterpriseCoexistencePollInterval keeps the per-user gateway's exit well
	// inside the 30-second bind retry of the enterprise gateway service, so the
	// service takes the port on its first start. Each check is one read-only
	// SCM query.
	enterpriseCoexistencePollInterval = 5 * time.Second
)

// enterpriseCoexistenceWatch stops a running per-user gateway once an
// enterprise deployment is installed on the computer. Detection failures do
// not stop the gateway, as with the start gate.
type enterpriseCoexistenceWatch struct {
	done    chan struct{}
	mu      sync.Mutex
	refusal error
}

// runWithEnterpriseCoexistenceWatch runs the gateway until run returns. A
// per-user gateway is stopped once an enterprise deployment is installed and
// then returns the refusal, so its log and exit status say why it stopped.
func runWithEnterpriseCoexistenceWatch(
	ctx context.Context,
	stop context.CancelFunc,
	deploymentMode string,
	run func(context.Context) error,
) error {
	watch := startEnterpriseCoexistenceWatch(ctx, deploymentMode, stop)
	return watch.exitError(run(ctx))
}

// startEnterpriseCoexistenceWatch checks for an enterprise deployment every
// poll interval until ctx ends. On detection it records the refusal and calls
// stop, which cancels the gateway's run context. It starts nothing off
// Windows or for a managed-enterprise gateway, which is the enterprise
// product itself.
func startEnterpriseCoexistenceWatch(
	ctx context.Context,
	deploymentMode string,
	stop context.CancelFunc,
) *enterpriseCoexistenceWatch {
	watch := &enterpriseCoexistenceWatch{done: make(chan struct{})}
	if !enterpriseCoexistenceWatchSupported || managed.IsManagedEnterprise(deploymentMode) {
		close(watch.done)
		return watch
	}
	go watch.run(ctx, enterpriseCoexistencePollInterval, refuseRunningPerUserGatewayBesideEnterprise, stop)
	return watch
}

func (w *enterpriseCoexistenceWatch) run(
	ctx context.Context,
	interval time.Duration,
	refuse func() error,
	stop context.CancelFunc,
) {
	defer close(w.done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		refusal := refuse()
		if refusal == nil || ctx.Err() != nil {
			continue
		}
		w.mu.Lock()
		w.refusal = refusal
		w.mu.Unlock()
		fmt.Fprintf(os.Stderr, "[sidecar] stopping the per-user gateway: %v\n", refusal)
		stop()
		return
	}
}

// exitError adds the refusal that stopped the gateway, if any, to runErr.
func (w *enterpriseCoexistenceWatch) exitError(runErr error) error {
	w.mu.Lock()
	refusal := w.refusal
	w.mu.Unlock()
	if refusal == nil {
		return runErr
	}
	return errors.Join(refusal, runErr)
}
