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

package connector

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// GAP-1128: setup ran with install admission off (the default pack), then a
// reload turns it on (use-pack strict): RefreshInstallPolicy writes the block
// without the rest of setup, a later setup keeps it as is, turning it off
// again removes it, and teardown takes it out.
func TestOpenClawRefreshInstallPolicyFollowsConfig(t *testing.T) {
	configPath, command, opts := installPolicyFixture(t, openClawCombinedSpelling)
	c := NewOpenClawConnector()
	off := opts
	off.OpenClawInstallPolicy = false
	if err := c.registerPlugin(off); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, present := installPolicyIn(t, configPath); present {
		t.Fatal("setup with install admission off wrote security.installPolicy")
	}

	if state, err := c.RefreshInstallPolicy(opts); err != nil || state != openClawInstallPolicyRegistered {
		t.Fatalf("refresh on: %q %v", state, err)
	}
	policy, present := installPolicyIn(t, configPath)
	if !present || !reflect.DeepEqual(policy, openClawInstallPolicyBlock(opts, command)) {
		t.Fatalf("refresh did not write the install policy:\n%s", mustReadFileString(t, configPath))
	}
	before := mustReadFileString(t, configPath)
	if err := c.registerPlugin(opts); err != nil {
		t.Fatalf("setup after refresh: %v", err)
	}
	if got := mustReadFileString(t, configPath); got != before {
		t.Fatalf("setup after a refresh rewrote openclaw.json:\n%s", got)
	}

	if state, err := c.RefreshInstallPolicy(off); err != nil || state != openClawInstallPolicyOff {
		t.Fatalf("refresh off: %q %v", state, err)
	}
	if _, present := installPolicyIn(t, configPath); present {
		t.Fatalf("refresh with install admission off left the block:\n%s", mustReadFileString(t, configPath))
	}
	if _, err := c.RefreshInstallPolicy(opts); err != nil {
		t.Fatalf("refresh on again: %v", err)
	}
	if err := c.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	// As after a second setup that changed the file, teardown removes only
	// the DefenseClaw settings (no exact restore of a later change).
	if _, has := readOpenClawJSON5(t, configPath)["security"]; has {
		t.Fatalf("teardown after a refresh left the install policy:\n%s", mustReadFileString(t, configPath))
	}
	if _, ok := loadOpenClawInstallPolicyRecord(opts.DataDir); ok {
		t.Fatal("teardown after a refresh left the install policy record")
	}
}

// Before setup registered the plugin there is nothing to refresh.
func TestOpenClawRefreshInstallPolicyNeedsSetupFirst(t *testing.T) {
	configPath, _, opts := installPolicyFixture(t, openClawCombinedSpelling)
	if state, err := NewOpenClawConnector().RefreshInstallPolicy(opts); err != nil || !strings.HasPrefix(state, "not changed: setup has not registered") {
		t.Fatalf("refresh: %q %v", state, err)
	}
	if got := mustReadFileString(t, configPath); got != openClawCombinedSpelling {
		t.Fatalf("refresh before setup changed openclaw.json:\n%s", got)
	}
}

// GAP-1128 round 2: the refresh reports the state it left, so the gateway
// log says "not registered" and why when the command check refuses (on
// Windows below a default drive root), not "updated".
func TestOpenClawRefreshInstallPolicyReportsWhyNotRegistered(t *testing.T) {
	configPath, _, opts := installPolicyFixture(t, openClawCombinedSpelling)
	c := NewOpenClawConnector()
	if err := c.registerPlugin(opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	openClawInstallPolicyTrusted = func(string, string) error { return errors.New(`C:\ lets BUILTIN\Users change its entries`) }
	state, err := c.RefreshInstallPolicy(opts)
	if err != nil || !strings.HasPrefix(state, "not registered: ") || !strings.Contains(state, "BUILTIN") {
		t.Fatalf("state = %q, err = %v", state, err)
	}
	if _, present := installPolicyIn(t, configPath); present {
		t.Fatal("a command OpenClaw would refuse stayed registered")
	}
}
