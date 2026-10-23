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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
)

// errRawBox is CheckStopped's refusal of a sandbox a raw `openshell`
// client started (StopWayOn's words for a ready one).
var errRawBox = fmt.Errorf("%w; OpenShell has not reported these stopped: raw-box (ready): `defenseclaw sandbox stop raw-box` (DefenseClaw sandbox), "+
	"or `openshell sandbox stop raw-box` (raw OpenShell sandbox); then try again", openshell.ErrUnflushed)

// GAP-0380, GAP-0454, GAP-0458, GAP-0347 (decision A): a raw `openshell`
// client takes no DefenseClaw lock, so a rollback holds the account's
// lifecycle lock exclusively (every DefenseClaw attach, stop, delete,
// create and start waits), checks OpenShell's own state first and again
// last, right before the restart, and aborts at either check: no restart,
// the active gateway files kept, the pending-restart mark as it was, and
// the exact stop-and-retry command. A raw start after the final check is
// the interval no local check fences (documented as unsupported): nothing
// but the restart command runs after that check.
func TestGatewayRollbackRawOpenShellStart(t *testing.T) {
	cases := []struct {
		name string
		// refuseAt is the CheckStopped call (1: first, 2: final) that finds
		// the raw sandbox; 0 finds none.
		refuseAt int
		// pending is the restart mark before the rollback ("" for none).
		pending string
	}{
		{name: "running before the rollback's first check", refuseAt: 1},
		{name: "started after the first check, found by the final one", refuseAt: 2},
		{name: "started during the restore, with a restart pending before", refuseAt: 2, pending: "2026-09-26T18:30:00Z\n"},
		{name: "started after the final check: only the restart follows it", refuseAt: 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newGatewayFixture(t)
			f.write(t, "gateway.toml", operatorTOML)
			res, err := f.apply(f.plan(t, bindMounts))
			if err != nil {
				t.Fatal(err)
			}
			applied := f.read(t, "gateway.toml")
			mark := filepath.Join(f.dir, ".defenseclaw-restart-pending")
			if tc.pending != "" {
				f.write(t, ".defenseclaw-restart-pending", tc.pending)
			}
			restarts := f.restarts()
			openshell.SetLifecycleLockWait(t, 100*time.Millisecond)
			checks, callsAtFinal := 0, 0
			f.cfg.CheckStopped = func(ctx context.Context) error {
				checks++
				// Every DefenseClaw sandbox path is held off meanwhile.
				if _, err := openshell.LockGatewayShared(ctx, f.dir); !errors.Is(err, openshell.ErrGatewayBusy) {
					t.Errorf("check %d: a sandbox attach, stop or delete got the lifecycle lock during the rollback: %v", checks, err)
				}
				if _, err := openshell.LockSandboxStart(f.dir); !errors.Is(err, openshell.ErrGatewayBusy) {
					t.Errorf("check %d: a sandbox start got the lifecycle lock during the rollback: %v", checks, err)
				}
				if checks == 2 {
					if got := f.read(t, "gateway.toml"); got != operatorTOML {
						t.Errorf("the final check ran before the restore: %q", got)
					}
					callsAtFinal = len(f.runner.Calls())
				}
				if checks == tc.refuseAt {
					return errRawBox
				}
				return nil
			}
			err = f.cfg.Rollback(context.Background(), res)
			if tc.refuseAt == 0 {
				if err != nil || f.restarts() != restarts+1 {
					t.Fatalf("Rollback = %v, restarts %d", err, f.restarts()-restarts)
				}
				after := f.runner.Calls()[callsAtFinal:]
				if len(after) == 0 || openshelltest.Argv(after[0]) != "systemctl --user restart openshell-gateway" {
					t.Fatalf("after the final check came %v, not the restart", after)
				}
				return
			}
			if !errors.Is(err, openshell.ErrUnflushed) || f.restarts() != restarts {
				t.Fatalf("Rollback = %v; restarts %d, want the abort and none", err, f.restarts()-restarts)
			}
			for _, want := range []string{"`openshell sandbox stop raw-box`", "then try again"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("Rollback = %v, lacks %q", err, want)
				}
			}
			if got := f.read(t, "gateway.toml"); got != applied {
				t.Fatalf("the abort overwrote the active gateway.toml: %q", got)
			}
			data, rerr := os.ReadFile(mark)
			switch {
			case tc.pending == "" && !errors.Is(rerr, os.ErrNotExist):
				t.Fatalf("the abort left a restart mark: %q, %v", data, rerr)
			case tc.pending != "" && string(data) != tc.pending:
				t.Fatalf("the abort changed the pending restart: %q, %v, want %q", data, rerr, tc.pending)
			}
			if tc.refuseAt == 2 && !strings.Contains(err.Error(), "the rollback was aborted") {
				t.Fatalf("Rollback = %v, does not say it aborted", err)
			}
			// Once raw-box is stopped, the retry rolls back.
			f.cfg.CheckStopped = func(context.Context) error { return nil }
			if err := f.cfg.Rollback(context.Background(), res); err != nil || f.read(t, "gateway.toml") != operatorTOML || f.restarts() != restarts+1 {
				t.Fatalf("retry = %v; restarts %d", err, f.restarts()-restarts)
			}
		})
	}
}

// A rollback whose lifecycle lock a DefenseClaw attach, stop or delete
// keeps past the bounded wait aborts before it changes anything.
func TestGatewayRollbackLockWaitExpiryAborts(t *testing.T) {
	f := newGatewayFixture(t)
	f.write(t, "gateway.toml", operatorTOML)
	res, err := f.apply(f.plan(t, bindMounts))
	if err != nil {
		t.Fatal(err)
	}
	applied, restarts := f.read(t, "gateway.toml"), f.restarts()
	held, err := openshell.LockGatewayShared(context.Background(), f.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer held()
	openshell.SetLifecycleLockWait(t, 150*time.Millisecond)
	err = f.cfg.Rollback(context.Background(), res)
	if !errors.Is(err, openshell.ErrGatewayBusy) || f.restarts() != restarts || f.read(t, "gateway.toml") != applied {
		t.Fatalf("Rollback = %v; restarts %d, config restored %v", err, f.restarts()-restarts, f.read(t, "gateway.toml") != applied)
	}
}
