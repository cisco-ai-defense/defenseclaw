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

	"github.com/defenseclaw/defenseclaw/internal/daemon"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// TestDoctorStartsAndRegistersAFirstGateway (GAP-0054, GAP-0055, GAP-0062,
// GAP-0063): an account whose OpenShell package someone else installed has
// the gateway service stopped and no registration. The service fix started
// the gateway, then waited 1m30s for a registration nothing made; the
// registration's hint (`openshell gateway add`) failed until the gateway
// had started; and the telemetry fix waited again on a gateway that was
// not up. The service fix now starts the gateway, waits for its client
// certificates and registers it; the registration says to start the
// service first; a failed start skips the fixes that need the gateway; and
// with another account's gateway on the port nothing is started.
func TestDoctorStartsAndRegistersAFirstGateway(t *testing.T) {
	const add = "openshell gateway add https://127.0.0.1:17670 --local --name openshell"
	newHost := func(t *testing.T) *doctorFixture {
		f := newDoctorFixture(t)
		if err := os.RemoveAll(filepath.Join(f.dir, "gateways")); err != nil {
			t.Fatal(err)
		}
		f.runner.On("systemctl --user show openshell-gateway", f.unit("inactive", "disabled"), nil)
		off := false
		f.doctor.WantTelemetry = &off
		return f
	}

	t.Run("start, then register", func(t *testing.T) {
		f := newHost(t)
		f.runner.OnFunc("systemctl --user enable --now openshell-gateway", func(context.Context, openshell.Command) ([]byte, error) {
			// The gateway writes its client certificates when it starts.
			mtls := filepath.Join(f.dir, "gateways", "openshell", "mtls")
			if err := os.MkdirAll(mtls, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ca.crt", "tls.crt", "tls.key"} {
				writeFile(t, filepath.Join(mtls, name), name, 0o600)
			}
			return nil, nil
		})
		f.runner.OnFunc(add, func(context.Context, openshell.Command) ([]byte, error) {
			f.addRegistration("openshell", nil)
			return nil, nil
		})
		r := f.run()
		if reg := expectCheck(t, r, "gateway-registration", openshell.StatusFail, "no gateway registration"); reg.Fix == nil || reg.Fix.Apply != nil ||
			!strings.Contains(reg.Fix.Summary, "start the gateway first") || !strings.HasSuffix(reg.Fix.Command, "&& "+add) {
			t.Fatalf("registration fix = %+v", reg.Fix)
		}
		if svc := expectCheck(t, r, "gateway-service", openshell.StatusFail, "inactive"); !strings.Contains(svc.Fix.Summary, "then register it ("+add+")") {
			t.Fatalf("service fix = %+v", svc.Fix)
		}
		applyFixes(t, r, "gateway-service")
		if !f.runner.Called(add) || f.verified != 1 {
			t.Fatalf("registered %v, waited %d times", f.runner.Called(add), f.verified)
		}
		if _, err := openshell.Discover(f.doctor.Discover); err != nil {
			t.Fatalf("no registration after the fix: %v", err)
		}
	})

	t.Run("a failed start skips the fixes that need the gateway", func(t *testing.T) {
		f := newHost(t)
		f.runner.On("systemctl --user enable --now openshell-gateway", "Job failed", errors.New("exit status 1"))
		r := f.run()
		var asked []string
		outcomes, err := r.ApplyFixes(context.Background(), func(c openshell.Check) (bool, error) {
			asked = append(asked, c.ID)
			return true, nil
		})
		if err != nil || strings.Join(asked, ",") != "gateway-service" {
			t.Fatalf("asked about %v, %v", asked, err)
		}
		var skipped []string
		for _, o := range outcomes {
			if o.Skipped != "" {
				skipped = append(skipped, o.ID)
			}
		}
		if len(outcomes) < 2 || !strings.Contains(outcomes[0].Error, "Job failed") || !strings.Contains(strings.Join(skipped, ","), "telemetry") {
			t.Fatalf("outcomes = %+v", outcomes)
		}
	})

	t.Run("another account holds the port", func(t *testing.T) {
		f := newHost(t)
		f.busy["127.0.0.1:17670"] = true
		f.doctor.PortHolder = func(string, int) (daemon.PortHolder, error) { return daemon.PortHolder{UID: 4242}, nil }
		r := f.run()
		svc := expectCheck(t, r, "gateway-service", openshell.StatusFail, "127.0.0.1:17670, the gateway's port, is held by a process of another account (uid 4242")
		if svc.Fix == nil || svc.Fix.Apply != nil || !strings.Contains(svc.Fix.Summary, "one OpenShell gateway runs on a machine") {
			t.Fatalf("service fix = %+v", svc.Fix)
		}
		// Nor does the registration send the user to a doctor --fix that
		// cannot start the gateway.
		if reg := r.Get("gateway-registration"); reg == nil || reg.Fix == nil || strings.Contains(reg.Fix.Summary, "doctor --fix") {
			t.Fatalf("registration = %+v", reg)
		}
	})
}
