// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// The standalone hook of an account the protected target set does not
// register (a new account, or one the policy excludes: the hook reads that
// from the gateway) tells it to wait for enrollment. While the gateway
// service is proven stopped nothing enrolls it, so the call is refused,
// closed, with the outage text an enrolled account gets. A running service
// keeps the enrollment text, and Secure Client keeps its fail-mode behaviour.
func TestUnenrolledAccountWithAStoppedGatewayServiceSaysItIsNotRunning(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		for _, reason := range []string{managedSIDUnregisteredReason, managedEnrollmentPendingReason} {
			for _, stopped := range []bool{true, false} {
				name := connector + " " + reason
				if stopped {
					name += " stopped"
				}
				t.Run(name, func(t *testing.T) {
					previous := managedGatewayServiceStopped
					managedGatewayServiceStopped = func(service string) bool { return stopped && service == "DefenseClawGateway" }
					t.Cleanup(func() { managedGatewayServiceStopped = previous })
					rt := ok(`{"action":"allow"}`)
					result := run(t, connector, rt, func(opts *Options) {
						opts.ManagedEnterprise = true
						opts.ExplainUnenrolledAccount = true
						opts.ManagedGatewayServiceName = "DefenseClawGateway"
						opts.ManagedRuntimeFailure = reason
					})
					text := result.stdout + result.stderr
					if result.code == 0 && !strings.Contains(text, "block") && !strings.Contains(text, "deny") {
						t.Fatalf("code=%d stdout=%q stderr=%q, want a block", result.code, result.stdout, result.stderr)
					}
					if rt.requests != 0 {
						t.Fatalf("requests = %d, want no gateway call", rt.requests)
					}
					waits := strings.Contains(text, "not enrolled yet")
					notRunning := strings.Contains(text, "service is not running") && strings.Contains(text, managedGatewayNotRunningReason)
					if stopped && (waits || !notRunning) {
						t.Errorf("stdout=%q stderr=%q, want the not-running text and no enrollment wait", result.stdout, result.stderr)
					}
					if !stopped && (!waits || notRunning) {
						t.Errorf("stdout=%q stderr=%q, want the enrollment text of a running service", result.stdout, result.stderr)
					}
				})
			}
		}
	}
}
