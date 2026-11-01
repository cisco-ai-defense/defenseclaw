// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"strings"
	"testing"
)

// A repair of a deployment whose gateway runs but does not answer on its hook
// socket (a stopped or hung process) ended that process and started a new
// one, yet listed only "nothing to repair" (p0-round GAP-0959). It names the
// process it ended and the new one, as it names a job it started.
func TestRepairNamesTheUnresponsiveGatewayItReplaced(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			gateway, _ := gatewayUnitOf(h.env.Services.Units())
			h.services.mu.Lock()
			h.services.pids = map[string]int{gateway.Name: 52747}
			h.services.mu.Unlock()
			h.healthy = false // running, but its hook socket does not answer
			replaced := func(u Unit) {
				if u.Name != gateway.Name {
					return
				}
				h.services.mu.Lock()
				h.services.pids[gateway.Name] = 54999
				h.services.mu.Unlock()
				h.healthy = true
			}
			h.services.afterStart, h.services.afterRestart = replaced, replaced
			repair := h.run(Options{Action: ActionRepair})
			requireOK(t, repair)
			changes := strings.Join(repair.Changes, "\n")
			if !strings.Contains(changes, "terminated the unresponsive "+gateway.Name+" process 52747 (the gateway does not serve the hook socket ") ||
				!strings.Contains(changes, ") and started a new one (pid 54999)") || strings.Contains(changes, RepairNothingChanged) ||
				!strings.HasSuffix(changes, RepairRestartedServices) {
				t.Fatalf("repair of an unresponsive gateway lists %q", repair.Changes)
			}
			// A repair of the healthy deployment names no process.
			again := h.run(Options{Action: ActionRepair})
			requireOK(t, again)
			if strings.Join(again.Changes, "\n") != RepairNothingChanged+"\n"+RepairRestartedServices {
				t.Fatalf("a repair of a healthy gateway lists %q", again.Changes)
			}
		})
	}
}
