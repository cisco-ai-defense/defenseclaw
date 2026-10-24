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
	"bytes"
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

// GAP-0587, the 1.0.1 upgrade bridge: on a host upgraded from 1.0.1 the
// lifecycle renders the docker configuration without a sandbox_label, and
// the shim starts an account's docker gateway on it while the account keeps a
// sandbox in OpenShell's default namespace (where 1.0.1's managed gateway
// made them) and none in the managed one, so its kept sandboxes stay listed,
// startable and pullable. Every other account, and one whose last default
// sandbox was deleted, starts in the managed namespace; a MicroVM gateway
// never takes the bridge.
func TestPlanSandboxOpenShellExecDefaultNamespaceBridge(t *testing.T) {
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
	primary := filepath.Join(dir, openshell.GatewayTOMLFile)
	fallback := filepath.Join(dir, openshell.GatewayFallbackTOMLFile)
	bridge := filepath.Join(dir, openshell.GatewayDefaultNamespaceTOMLFile)
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	tokens := func(namespace string) string {
		return filepath.Join(home, ".local", "state", "openshell", "docker-sandbox-tokens", namespace)
	}
	keep := func(namespace, sandbox string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(tokens(namespace), sandbox), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	restoreHost, restoreHome, restoreFile, restoreProbe, restoreSettings, restoreIDs, restoreWarn := sandboxDaemonHost, openShellExecHome,
		openShellExecTrustedFile, openShellExecVMProbe, openShellExecSettings, openShellExecDefaultNamespaceSandboxIDs, openShellExecWarn
	t.Cleanup(func() {
		sandboxDaemonHost, openShellExecHome, openShellExecTrustedFile, openShellExecVMProbe, openShellExecSettings, openShellExecDefaultNamespaceSandboxIDs, openShellExecWarn =
			restoreHost, restoreHome, restoreFile, restoreProbe, restoreSettings, restoreIDs, restoreWarn
	})
	var warned bytes.Buffer
	openShellExecWarn = &warned
	// The sandboxes Docker has in the default namespace.
	var dockerErr error
	inDocker := map[string]bool{"fcs-m-eng-101": true, "fcs-m-ctr-101a": true}
	openShellExecDefaultNamespaceSandboxIDs = func() (map[string]bool, error) { return inDocker, dockerErr }
	sandboxDaemonHost = func(string) (managed.StandaloneLayout, *managed.RuntimeDescriptor, error) {
		return managed.StandaloneLayout{ConfigDir: filepath.Dir(dir)}, &managed.RuntimeDescriptor{}, nil
	}
	openShellExecHome = func() (string, error) { return home, nil }
	openShellExecTrustedFile = func(string, string) error { return nil }
	kvm := false
	openShellExecVMProbe = func(string, string) openshell.VMProbeResult {
		if kvm {
			return openshell.VMProbeResult{OK: true}
		}
		return openshell.VMProbeResult{Reason: openshell.DriverReasonKVMMissing}
	}
	openShellExecSettings = func(context.Context) sandboxrelay.EnterpriseOpenShell {
		return sandboxrelay.EnterpriseOpenShell{DriverFallback: "docker"}
	}
	configOf := func(goos string) string {
		t.Helper()
		plan, err := planSandboxOpenShellExec(context.Background(), goos, nil)
		if err != nil {
			t.Fatal(err)
		}
		return envValue(plan.env, "OPENSHELL_GATEWAY_CONFIG")
	}

	// The docker driver.
	write(primary, "[openshell.gateway]\ncompute_driver = 'docker'\n")
	keep(openshell.DefaultDockerNamespace, "fcs-m-eng-101")
	if got := configOf("linux"); got != primary {
		t.Fatalf("no bridge rendered (a host that was not on 1.0.1): %s", got)
	}
	write(bridge, "[openshell.gateway]\ncompute_driver = 'docker'\n")
	if got := configOf("linux"); got != bridge {
		t.Fatalf("an account that keeps 1.0.1 sandboxes: %s, want the bridge", got)
	}
	if warned.Len() != 0 {
		t.Fatalf("a notice without sandboxes in both namespaces: %q", warned.String())
	}
	// Sandboxes in both namespaces (rel-1-0-3:GAP-0164: a 1.0.3 sandbox kept
	// in the managed namespace, a downgrade to 1.0.1 that made one in the
	// default namespace, and the upgrade again): the managed render, and the
	// gateway's journal says why the 1.0.1 sandboxes report not found and
	// what brings them back.
	keep(openshell.ManagedDockerNamespace, "new-one")
	if got := configOf("linux"); got != primary {
		t.Fatalf("an account with a sandbox in the managed namespace: %s, want the managed render", got)
	}
	for _, want := range []string{"the 1.0.1 upgrade bridge is off for this account", `"default"`, `"defenseclaw-managed"`,
		"report not found", "defenseclaw sandbox pull NAME", "defenseclaw sandbox delete NAME", tokens(openshell.ManagedDockerNamespace),
		"the gateway's next start then uses the bridge"} {
		if !strings.Contains(warned.String(), want) {
			t.Fatalf("both namespaces: the notice %q lacks %q", warned.String(), want)
		}
	}
	if err := os.RemoveAll(tokens(openshell.ManagedDockerNamespace)); err != nil {
		t.Fatal(err)
	}
	warned.Reset()
	if got := configOf("linux"); got != bridge || warned.Len() != 0 {
		t.Fatalf("the managed sandboxes are gone: %s, notice %q, want the bridge and no notice", got, warned.String())
	}
	// The account deletes its last 1.0.1 sandbox: OpenShell removes its
	// token folder, and the next gateway start is in the managed namespace.
	if err := os.Remove(filepath.Join(tokens(openshell.DefaultDockerNamespace), "fcs-m-eng-101")); err != nil {
		t.Fatal(err)
	}
	if got := configOf("linux"); got != primary {
		t.Fatalf("an account with no sandbox left in the default namespace: %s", got)
	}
	// A folder whose sandbox Docker no longer has (its containers were
	// removed outside OpenShell, or by a purge) does not keep the account on
	// the bridge (GAP-0677), unless Docker cannot say.
	keep(openshell.DefaultDockerNamespace, "2ca1ed06-stale")
	if got := configOf("linux"); got != primary {
		t.Fatalf("a stray default-namespace folder kept the bridge: %s", got)
	}
	// A stray default-namespace folder next to a managed sandbox is no
	// kept 1.0.1 sandbox: the managed render, and no notice.
	keep(openshell.ManagedDockerNamespace, "new-two")
	if got := configOf("linux"); got != primary || warned.Len() != 0 {
		t.Fatalf("a stray default folder and a managed sandbox: %s, notice %q", got, warned.String())
	}
	if err := os.RemoveAll(tokens(openshell.ManagedDockerNamespace)); err != nil {
		t.Fatal(err)
	}
	dockerErr = errors.New("permission denied on the docker socket")
	if got := configOf("linux"); got != bridge {
		t.Fatalf("Docker did not answer: %s, want the bridge (kept sandboxes are not stranded)", got)
	}
	dockerErr = nil
	if err := os.Remove(filepath.Join(tokens(openshell.DefaultDockerNamespace), "2ca1ed06-stale")); err != nil {
		t.Fatal(err)
	}

	// The MicroVM driver with the docker fallback: only a docker gateway
	// takes the bridge.
	keep(openshell.DefaultDockerNamespace, "fcs-m-ctr-101a")
	write(primary, "[openshell.gateway]\ncompute_driver = 'vm'\n")
	write(fallback, "[openshell.gateway]\ncompute_driver = 'docker'\n")
	if got := configOf("linux"); got != bridge {
		t.Fatalf("KVM not available, fallback docker, kept 1.0.1 sandboxes: %s, want the bridge", got)
	}
	kvm = true
	if got := configOf("linux"); got != primary {
		t.Fatalf("a MicroVM gateway took the bridge: %s", got)
	}
}
