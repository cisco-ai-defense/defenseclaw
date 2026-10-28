// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

func TestSandboxResolveDriverMismatchIsTemporary(t *testing.T) {
	for _, tc := range []struct{ before, after string }{{"vm", "docker"}, {"docker", "vm"}, {"docker", "auto"}} {
		t.Run(tc.before+"_to_"+tc.after, func(t *testing.T) {
			f := newSandboxFixture(t, config.EnterpriseEnrollmentConfig{}, nil)
			f.setGroups(sbxAlice, "dc-sbx-contractors")
			f.cfg.Enterprise.OpenShell.Driver = tc.after
			req := claudeResolve()
			req.Driver, req.DriverReason = tc.before, "configured"
			rec := f.do(sbxAlice, http.MethodPost, sandboxrelay.PathPolicyResolve, req, nil)
			var out sandboxrelay.ResolveResponse
			if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS == "darwin" && tc.before == "vm" {
				// macOS runs only the MicroVM driver whatever is configured
				// (sandboxDriverClaim), so a MicroVM daemon changed nothing.
				if rec.Code != http.StatusOK || out.Refusal != nil {
					t.Fatalf("macOS MicroVM daemon under %q: %d %s, want it resolved", tc.after, rec.Code, rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusServiceUnavailable || out.Refusal == nil || out.Refusal.Reason != sandboxrelay.DetailSetupChanging ||
				!strings.Contains(out.Refusal.Message, "defenseclaw sandbox stop NAME") || out.Registration.ID != "" {
				t.Fatalf("driver change refusal: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}
