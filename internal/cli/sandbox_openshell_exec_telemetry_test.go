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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/sandboxrelay"
)

// es:GAP-0144: the account's OpenShell gateway ran with the host's rendered
// gateway.env, which follows the organization's floor, so a profile whose
// floor sets allow_upstream_telemetry: false (computed per account by the
// managed gateway) still let OpenShell send its own telemetry. The shim now
// turns it off when the account's settings do not allow it, or when the
// managed gateway does not answer, and never turns it on.
func TestPlanSandboxOpenShellExecAppliesTheAccountsTelemetrySwitch(t *testing.T) {
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
	restoreHost, restoreHome, restoreFile, restoreSettings, restoreEnv, restoreTelemetry := sandboxDaemonHost, openShellExecHome,
		openShellExecTrustedFile, openShellExecSettings, openShellExecRenderedEnv, openShellExecUpstreamTelemetry
	t.Cleanup(func() {
		sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecSettings, openShellExecRenderedEnv, openShellExecUpstreamTelemetry =
			restoreHost, restoreHome, restoreFile, restoreSettings, restoreEnv, restoreTelemetry
	})
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{ConfigDir: filepath.Dir(dir)}, &managed.RuntimeDescriptor{}, nil
	}
	openShellExecHome = func() (string, error) { return home, nil }
	openShellExecTrustedFile = func(string, string) error { return nil }
	openShellExecSettings = func(context.Context) sandboxrelay.EnterpriseOpenShell {
		return sandboxrelay.EnterpriseOpenShell{Install: "setup"}
	}
	rendered := "true"
	openShellExecRenderedEnv = func(string) ([]string, error) {
		return []string{openshell.EnvTelemetryEnabled + "=" + rendered}, nil
	}
	allowed := false
	openShellExecUpstreamTelemetry = func(context.Context) bool { return allowed }
	telemetry := func() (string, int) {
		t.Helper()
		plan, err := planSandboxOpenShellExec(context.Background(), "linux", nil)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, kv := range plan.env {
			if strings.HasPrefix(kv, openshell.EnvTelemetryEnabled+"=") {
				n++
			}
		}
		return envValue(plan.env, openshell.EnvTelemetryEnabled), n
	}
	// The organization allows it, the account's profile does not.
	if v, n := telemetry(); v != "false" || n != 1 {
		t.Fatalf("profile false over an organization true: %q (%d entries)", v, n)
	}
	// Both allow it: the host's value stands.
	allowed = true
	if v, n := telemetry(); v != "true" || n != 1 {
		t.Fatalf("both allow it: %q (%d entries)", v, n)
	}
	// The account's settings never turn on what the organization keeps off.
	rendered = "false"
	if v, n := telemetry(); v != "false" || n != 1 {
		t.Fatalf("organization false: %q (%d entries)", v, n)
	}
	// A managed gateway that does not answer allows nothing.
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{}, nil, errors.New("no descriptor")
	}
	if sandboxOpenShellUpstreamTelemetry(context.Background()) {
		t.Fatal("telemetry allowed without the managed gateway's answer")
	}
}
