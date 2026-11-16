// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed/mcpasuser"
)

// enrolledMCPRefreshBudget bounds the refresh before an MCP tool call. The
// call's hook waits about 3.5 seconds, from the start of the hook process,
// for the whole decision: its own start, the dial, this refresh and the
// checks after it. A refresh that does not finish within its budget refuses
// the call as not scanned yet (the agent reads the "still scanning" wait and
// tries again), never decides it on the list read before. With a 10 second
// bound a stopped hook enumerator held the call past the hook's wait, so the
// agent got the hook's no-answer failure instead (GAP-0216). A refresh
// normally takes well under 200 ms.
var enrolledMCPRefreshBudget = 1500 * time.Millisecond

// enrolledMCPRefreshMargin is kept before the deadline of a request that
// has one, for the checks and the answer after the refresh.
const enrolledMCPRefreshMargin = 500 * time.Millisecond

// enrolledMCPRefreshDeadline is when a refresh that starts at now stops
// waiting: its budget, or earlier when the request ends sooner.
func enrolledMCPRefreshDeadline(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(enrolledMCPRefreshBudget)
	if request, ok := ctx.Deadline(); ok {
		if bounded := request.Add(-enrolledMCPRefreshMargin); bounded.Before(deadline) {
			deadline = bounded
		}
	}
	return deadline
}

// enrolledMCPEnumeratorRefresh asks the hook enumerator serving the gateway
// service to publish the enrolled users' MCP servers again (seam).
var enrolledMCPEnumeratorRefresh = mcpasuser.Refresh

// enrolledMCPRefresher brings a managed Windows gateway's view of its
// enrolled users' MCP servers up to date before an MCP tool call is decided.
// The gateway cannot read a user's profile: it knows a user's servers only
// from the record the hook enumerator publishes, on an interval of 30
// seconds, and reads that record on an interval of its own. A server a user
// changed under the same name was decided on its old definition and its old
// verdict until both caught up (GAP-0216). refresh has the enumerator publish
// every enrolled user's servers from their files now, and reload reads the
// records into the list the watcher's pending check reads, so a changed
// definition is pending (refused until its own scan) at the first call.
type enrolledMCPRefresher struct {
	coalesce mcpasuser.Coalescer
	refresh  func(ctx context.Context) error
	reload   func()
}

func (s *Sidecar) newEnrolledMCPRefresher(reg *connector.Registry, wcfg config.GatewayWatcherConfig, live *enrolledMCPServers) *enrolledMCPRefresher {
	return &enrolledMCPRefresher{
		refresh: func(ctx context.Context) error {
			service := strings.TrimSpace(os.Getenv(mcpasuser.GatewayServiceEnv))
			if service == "" {
				return fmt.Errorf("%s is not set", mcpasuser.GatewayServiceEnv)
			}
			return enrolledMCPEnumeratorRefresh(ctx, service)
		},
		reload: func() {
			next := resolveEnrolledWatchSet(s.currentConfig(), reg, wcfg, serviceHomeDir())
			publishMCPStatesUnreadable(next.mcpUnreadable)
			live.set(next.mcp)
		},
	}
}

// refreshEnrolledMCPBeforeCall refreshes, on a managed Windows gateway, the
// enrolled users' MCP servers of a connector the enumerator publishes before
// a tool call of that connector is decided. Calls that arrive together share
// one refresh, and each is answered by a refresh that started after it,
// within its own budget (enrolledMCPRefreshBudget), also while another
// call's refresh runs. It returns why the refresh failed or did not finish
// in time, and the caller refuses the call (fail closed): the gateway would
// otherwise decide it on a definition it cannot tell is current. A refresh
// that published only some records (*mcpasuser.RefreshIncomplete) still
// has the published ones read, and refuses only a call whose own record it
// did not confirm: the caller's connector and account, or any account of
// the connector when the caller's home is not known. Other gateways and
// connectors have nothing to refresh.
func (s *Sidecar) refreshEnrolledMCPBeforeCall(ctx context.Context, connectorName string) error {
	r := s.enrolledMCPRefresh.Load()
	if r == nil || !mcpasuser.PublishedConnector(connectorName) {
		return nil
	}
	ctx, cancel := context.WithDeadline(ctx, enrolledMCPRefreshDeadline(ctx, time.Now()))
	defer cancel()
	err := r.coalesce.Run(ctx, func() error {
		err := r.refresh(ctx)
		var incomplete *mcpasuser.RefreshIncomplete
		if err != nil && !errors.As(err, &incomplete) {
			return err
		}
		r.reload()
		return err
	})
	var incomplete *mcpasuser.RefreshIncomplete
	if errors.As(err, &incomplete) {
		home, _ := callerHomeForAssets(ctx)
		if !incomplete.Refuses(connectorName, home) {
			return nil
		}
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "[watch] could not read the enrolled users' current %s MCP servers before a tool call: %v; the call is refused\n",
			connectorName, err)
	}
	return err
}
