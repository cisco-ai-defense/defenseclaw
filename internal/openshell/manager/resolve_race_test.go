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
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// A caller outside the policy refresh (an unblock, an approval, a hook)
// resolves a sandbox's policy too. If it read the closed start-up floor
// just before the daemon confirmed the registration, its store must not
// land after the refresh's: the stopped sandbox's status would show the
// closed floor again until the next configuration change (GAP-0616).
func TestSandboxResolveOutsideRefreshCannotRepublishAnOlderFloor(t *testing.T) {
	e, _ := managedEnv(t, func(c *config.Config) { c.OpenShell.Profile = config.OpenShellProfileBalanced })
	var armed atomic.Bool
	entered, release := make(chan struct{}), make(chan struct{})
	e.m.opts.Config = func() *config.Config {
		cfg := e.config()
		if armed.CompareAndSwap(true, false) {
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
	if closed, err := e.m.Get(t.Context(), "stopped-box"); err != nil || orgViolation(closed) == "" {
		t.Fatalf("fixture did not start with the closed-floor deny: %+v %v", closed, err)
	}
	e.m.mu.Lock()
	b := e.m.boxes["stopped-box"]
	e.m.mu.Unlock()

	// The outside caller reads the closed floor and is held there.
	armed.Store(true)
	oldDone := make(chan struct{})
	go func() { _, _ = e.m.resolveBox(b); close(oldDone) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the outside resolution did not read the configuration")
	}
	// The registration is confirmed and the policies are refreshed.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin = real })
	newDone := make(chan struct{})
	go func() { e.m.RefreshPolicies(); close(newDone) }()
	select {
	case <-newDone:
	case <-time.After(200 * time.Millisecond):
	}
	close(release)
	for _, done := range []<-chan struct{}{oldDone, newDone} {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a policy resolution did not finish")
		}
	}
	after, err := e.m.Get(t.Context(), "stopped-box")
	must(t, err)
	if orgViolation(after) != "" || after.Profile == "strict" || after.NetworkMode == "deny" {
		t.Fatalf("an older resolution outside the refresh replaced the confirmed view: %+v", after)
	}
}

// Two managers in one process (a test, a daemon restart within the same
// process) keep their own refresh order: one manager's refresh never waits
// for another's.
func TestPolicyRefreshLockIsPerManager(t *testing.T) {
	a, _ := managedEnv(t, nil)
	b, _ := managedEnv(t, nil)
	a.m.refreshMu.Lock()
	defer a.m.refreshMu.Unlock()
	done := make(chan struct{})
	go func() { b.m.RefreshPolicies(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a policy refresh waited for another manager's refresh")
	}
}
