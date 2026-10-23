// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// The configuration loop can be refreshing the closed start-up floor when
// the daemon confirms a registration and calls RefreshPolicies. The older
// resolution must finish first: otherwise it can replace the new sandbox
// view after cfgSeen already points at the new configuration, leaving the
// stopped sandbox on the closed-floor deny until another policy change.
func TestRefreshPoliciesSerializesOverlappingFloorChanges(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	var calls atomic.Int32
	var armed atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	// Install the callback before live starts configLoop. Replacing opts.Config
	// after that goroutine starts races its periodic read of the callback.
	e.m.opts.Config = func() *config.Config {
		cfg := e.config()
		if armed.Load() && calls.Add(1) == 2 {
			close(entered)
			<-release
		}
		return cfg
	}
	e.live(sandboxapi.CreateRequest{Name: "stopped-box"})
	e.register("stopped-box")
	e.stopBox("stopped-box")
	real := e.config().OpenShell.Admin
	no := false
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin = config.OpenShellAdminConfig{MinProfile: "strict", Allowed: &no}
	})
	e.m.RefreshPolicies()
	closed, err := e.m.Get(t.Context(), "stopped-box")
	must(t, err)
	if closed.Phase != "stopped" || !slices.ContainsFunc(closed.Violations, func(v sandboxapi.Violation) bool { return v.Constraint == "openshell.admin.allowed" }) {
		t.Fatalf("fixture did not start with the closed-floor deny: %+v", closed)
	}

	// The first refresh has recorded cfgSeen as closed. Hold its per-box
	// resolve until the new floor can overtake it.
	armed.Store(true)
	oldDone := make(chan struct{})
	go func() { e.m.RefreshPolicies(); close(oldDone) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the old resolution did not reach the stopped sandbox")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin = real })
	newDone := make(chan struct{})
	go func() { e.m.RefreshPolicies(); close(newDone) }()
	// Without serialization the new resolution can finish while the old
	// one is held; with serialization it waits and finishes last.
	select {
	case <-newDone:
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	for _, done := range []<-chan struct{}{oldDone, newDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a policy refresh did not finish")
		}
	}
	e.m.mu.Lock()
	seen := e.m.cfgSeen
	e.m.mu.Unlock()
	if seen != e.config() {
		t.Fatal("the manager did not record the confirmed configuration")
	}
	after, err := e.m.Get(t.Context(), "stopped-box")
	must(t, err)
	if orgViolation(after) != "" || after.Profile == "strict" || after.NetworkMode == "deny" {
		t.Fatalf("an older closed-floor refresh replaced the confirmed view: %+v", after)
	}
}
