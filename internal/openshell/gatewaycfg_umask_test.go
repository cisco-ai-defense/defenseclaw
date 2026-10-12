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

package openshell_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

func TestUMaskTooStrict(t *testing.T) {
	for umask, want := range map[string]bool{
		"0022": false, "022": false, "0002": false, "0000": false, "0": false, "": false, "not a umask": false,
		"0077": true, "0027": true, "0037": true, "0007": true, "0050": true, "0750": true,
	} {
		if got := openshell.UMaskTooStrict(umask); got != want {
			t.Errorf("UMaskTooStrict(%q) = %t, want %t", umask, got, want)
		}
	}
}

// dropIn is where the drop-in of the gateway service goes, next to the
// OpenShell config directory.
func (f *gatewayFixture) dropIn() string {
	return filepath.Join(filepath.Dir(f.dir), "systemd", "user", "openshell-gateway.service.d", "zz-defenseclaw-umask.conf")
}

func TestGatewayServiceReportsItsUMask(t *testing.T) {
	f := newGatewayFixture(t)
	f.unit += "UMask=0077\n"
	st, err := f.cfg.ServiceState(context.Background())
	if err != nil || st.UMask != "0077" {
		t.Fatalf("state = %+v, %v", st, err)
	}
	if got := f.runner.Calls()[0].Args; !strings.Contains(strings.Join(got, " "), ",UMask") {
		t.Fatalf("systemctl show asked %v", got)
	}
}

// TestGatewayPlanGivesTheServiceAUMask: the drop-in applies to the package's
// unit and to a copy of it in the user's config that shadows it, and the
// manager reads it before the gateway restarts.
func TestGatewayPlanGivesTheServiceAUMask(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.runner.On("systemctl --user daemon-reload", "", nil)
	plan, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: "0022"})
	if err != nil || len(plan.Files) != 1 || plan.Files[0].Path != f.dropIn() || plan.Files[0].TOML {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
	if s := plan.String(); !strings.Contains(s, "create "+f.dropIn()) || !strings.Contains(s, "set UMask=0022 for the openshell-gateway service") {
		t.Fatalf("plan renders as:\n%s", s)
	}
	if res, err := f.cfg.Apply(ctx, plan); err != nil || !res.Restarted {
		t.Fatalf("apply = %+v, %v", res, err)
	}
	data, err := os.ReadFile(f.dropIn())
	if err != nil || !strings.HasSuffix(string(data), "[Service]\nUMask=0022\n") {
		t.Fatalf("drop-in = %q, %v", data, err)
	}
	var order []string
	for _, c := range f.runner.Calls() {
		if a := strings.Join(c.Args, " "); a == "--user daemon-reload" || a == "--user restart openshell-gateway" {
			order = append(order, a)
		}
	}
	if strings.Join(order, ",") != "--user daemon-reload,--user restart openshell-gateway" {
		t.Fatalf("service commands = %v", order)
	}
	if again, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: "0022"}); err != nil || !again.Empty() {
		t.Fatalf("a second plan = %+v, %v", again, err)
	}
}

// A restart that fails puts the unit back as it was and has the manager
// read it again.
func TestGatewayUMaskRollsBackWithTheRestart(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.runner.On("systemctl --user daemon-reload", "", nil)
	f.runner.On("systemctl --user restart openshell-gateway", "", errors.New("exit status 1"))
	plan, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: "0022"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cfg.Apply(ctx, plan); err == nil {
		t.Fatal("apply succeeded with a restart that failed")
	}
	if _, err := os.Stat(f.dropIn()); !os.IsNotExist(err) {
		t.Fatalf("the drop-in stayed after the rollback: %v", err)
	}
	reloads := 0
	for _, c := range f.runner.Calls() {
		if strings.Join(c.Args, " ") == "--user daemon-reload" {
			reloads++
		}
	}
	if reloads != 2 {
		t.Fatalf("daemon-reload ran %d times, want once for the drop-in and once for its removal", reloads)
	}
}

// A drop-in that sorts after ours, or a unit that sets UMask= otherwise, can
// leave the service on its old umask: the change is rolled back with the
// drop-ins named, not reported as done.
func TestGatewayUMaskMustTakeEffect(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.runner.On("systemctl --user daemon-reload", "", nil)
	f.unit += "UMask=0077\nDropInPaths=/home/dev/.config/systemd/user/openshell-gateway.service.d/override.conf\n"
	plan, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: "0022"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.cfg.Apply(ctx, plan)
	if err == nil || !strings.Contains(err.Error(), "runs with umask 0077, not 0022: another setting overrides the drop-in (drop-ins applied: /home/dev/.config/systemd/user/openshell-gateway.service.d/override.conf)") {
		t.Fatalf("apply = %v", err)
	}
	if _, err := os.Stat(f.dropIn()); !os.IsNotExist(err) {
		t.Fatalf("the drop-in stayed after the rollback: %v", err)
	}
}

// A service that runs with a looser umask than the plan's (0002 for 0022)
// still lets the guest traverse what the driver makes: the change stays.
func TestGatewayLooserUMaskIsKept(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	f.runner.On("systemctl --user daemon-reload", "", nil)
	f.unit += "UMask=0002\n"
	plan, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: "0022"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.cfg.Apply(ctx, plan); err != nil {
		t.Fatalf("apply = %v", err)
	}
	if _, err := os.Stat(f.dropIn()); err != nil {
		t.Fatalf("the drop-in was rolled back: %v", err)
	}
}

func TestGatewayPlanRefusesAnImpossibleUMask(t *testing.T) {
	ctx := context.Background()
	f := newGatewayFixture(t)
	for _, bad := range []string{"0o22", "8", "00022", "umask"} {
		if _, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: bad}); err == nil || !strings.Contains(err.Error(), "is not a umask") {
			t.Errorf("umask %q: err = %v", bad, err)
		}
	}
	// Homebrew's launchd service has no drop-ins.
	f.cfg.GOOS = "darwin"
	if _, err := f.cfg.Plan(ctx, openshell.GatewayChanges{ServiceUMask: "0022"}); err == nil || !strings.Contains(err.Error(), "systemd setting") {
		t.Errorf("on a Mac: err = %v", err)
	}
}

// No gateway service, nothing to give a umask to.
func TestGatewayPlansNoUMaskWithoutAService(t *testing.T) {
	f := newGatewayFixture(t)
	f.unit = "LoadState=not-found\nActiveState=inactive\nSubState=dead\nUnitFileState=\n"
	plan, err := f.cfg.Plan(context.Background(), openshell.GatewayChanges{ServiceUMask: "0022"})
	if err != nil || !plan.Empty() {
		t.Fatalf("plan = %+v, %v", plan, err)
	}
}
