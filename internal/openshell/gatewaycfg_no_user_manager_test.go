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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// GAP-0369, GAP-0374: a per-user uninstall run from a session that reaches
// no systemd user manager (the account signed out, no linger) stopped half
// done. Its sandbox teardown restored the gateway files and then failed on
// the restart with "Failed to connect to bus". Without a user manager no
// user service runs, so the files go back without a restart, as for a
// stopped service, and the teardown goes on.
func TestGatewayRollbackWithoutUserManagerRestoresTheFilesWithoutARestart(t *testing.T) {
	for name, said := range map[string]string{
		"no bus socket": "Failed to connect to bus: No such file or directory",
		"no runtime dir": "Failed to connect to user scope bus via local transport: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR " +
			"not defined (consider using --machine=<user>@.host --user to connect to bus of other user)",
	} {
		t.Run(name, func(t *testing.T) {
			f := newGatewayFixture(t)
			f.write(t, "gateway.toml", operatorTOML)
			res, err := f.apply(f.plan(t, bindMounts))
			if err != nil {
				t.Fatal(err)
			}
			f.runner.On("systemctl --user", said, errors.New("exit status 1"))
			restarts, flushes := f.restarts(), f.flushes
			err = f.cfg.Rollback(context.Background(), res)
			if !errors.Is(err, openshell.ErrGatewayServiceStopped) {
				t.Fatalf("Rollback = %v, want ErrGatewayServiceStopped", err)
			}
			if got := f.read(t, "gateway.toml"); got != operatorTOML {
				t.Fatalf("gateway.toml not restored:\n%s", got)
			}
			if f.restarts() != restarts || f.flushes != flushes {
				t.Fatalf("restarts %d, flushes %d: want none without a user manager", f.restarts()-restarts, f.flushes-flushes)
			}
			if st, err := f.cfg.Read(); err != nil || !st.RestartPendingSince.IsZero() {
				t.Fatalf("Rollback left a pending-restart mark: %+v, %v", st, err)
			}
		})
	}
	// An unknown service state is not a missing user manager: the restart
	// is still tried, and its failure still fails the rollback.
	t.Run("other systemctl failure", func(t *testing.T) {
		f := newGatewayFixture(t)
		f.write(t, "gateway.toml", operatorTOML)
		res, err := f.apply(f.plan(t, bindMounts))
		if err != nil {
			t.Fatal(err)
		}
		f.runner.On("systemctl --user show", "Access denied", errors.New("exit status 1"))
		restarts := f.restarts()
		if err := f.cfg.Rollback(context.Background(), res); err != nil {
			t.Fatalf("Rollback = %v", err)
		}
		if f.restarts() != restarts+1 || f.read(t, "gateway.toml") != operatorTOML {
			t.Fatalf("restarts %d, want 1, and the files restored", f.restarts()-restarts)
		}
	})
}
