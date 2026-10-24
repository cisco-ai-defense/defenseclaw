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

//go:build unix

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// On Linux the shim starts the account's gateway on the docker fallback's
// rendered configuration only when the lifecycle rendered one, the account's
// own KVM probe fails now and its fallback is docker; otherwise on the
// MicroVM configuration.
func TestPlanSandboxOpenShellExecDockerFallback(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("the shim refuses root")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home")
	dir := filepath.Join(root, "etc", "openshell")
	for _, d := range []string{filepath.Join(home, ".local", "bin"), dir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".local", "bin", "openshell-gateway"), []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	primary, fallback := filepath.Join(dir, openshell.GatewayTOMLFile), filepath.Join(dir, openshell.GatewayFallbackTOMLFile)
	if err := os.WriteFile(primary, []byte("[openshell.gateway]\ncompute_driver = 'vm'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreHost, restoreHome, restoreFile, restoreProbe, restoreSettings := sandboxDaemonHost, openShellExecHome,
		openShellExecTrustedFile, openShellExecVMProbe, openShellExecSettings
	t.Cleanup(func() {
		sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecVMProbe, openShellExecSettings =
			restoreHost, restoreHome, restoreFile, restoreProbe, restoreSettings
	})
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{ConfigDir: filepath.Dir(dir)}, &managed.RuntimeDescriptor{}, nil
	}
	openShellExecHome = func() (string, error) { return home, nil }
	openShellExecTrustedFile = func(string, string) error { return nil }
	kvm, accountFallback, probes := false, "docker", 0
	openShellExecVMProbe = func(_, _, gatewayExecutable string) openshell.VMProbeResult {
		probes++
		if want := filepath.Join(home, ".local", "bin", openshell.GatewayBinary); gatewayExecutable != want {
			t.Fatalf("fallback probed sibling of %q, want planned gateway %q", gatewayExecutable, want)
		}
		if kvm {
			return openshell.VMProbeResult{OK: true}
		}
		return openshell.VMProbeResult{Reason: openshell.DriverReasonKVMMissing}
	}
	openShellExecSettings = func(context.Context) sandboxrelay.EnterpriseOpenShell {
		return sandboxrelay.EnterpriseOpenShell{DriverFallback: accountFallback}
	}
	configOf := func(goos string) string {
		t.Helper()
		plan, err := planSandboxOpenShellExec(context.Background(), goos, nil)
		if err != nil {
			t.Fatal(err)
		}
		return envValue(plan.env, "OPENSHELL_GATEWAY_CONFIG")
	}

	if got := configOf("linux"); got != primary || probes != 0 {
		t.Fatalf("no fallback rendered: %s (probed %d)", got, probes)
	}
	if err := os.WriteFile(fallback, []byte("[openshell.gateway]\ncompute_driver = 'docker'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := configOf("linux"); got != fallback {
		t.Fatalf("KVM not available, fallback docker: %s", got)
	}
	accountFallback = "none"
	if got := configOf("linux"); got != primary {
		t.Fatalf("a profile's driver_fallback: none: %s", got)
	}
	accountFallback, kvm = "docker", true
	if got := configOf("linux"); got != primary {
		t.Fatalf("KVM available: %s", got)
	}
}
