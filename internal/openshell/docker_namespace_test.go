// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package openshell_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/openshell"
)

// defaultNamespaceSandbox leaves a sandbox folder of the docker driver's in
// the default namespace of the account's gateway state.
func defaultNamespaceSandbox(t *testing.T, home string) {
	t.Helper()
	dir := filepath.Join(home, ".local", "state", "openshell", "docker-sandbox-tokens", openshell.DefaultDockerNamespace, "sbx-1111")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
}

// GAP-0579: the per-user docker gateways of two accounts on one Linux host
// shared OpenShell's default sandbox namespace, so one account's gateway
// start removed the supervisors of the other's running sandboxes. The doctor
// names a gateway still on the shared namespace; its fix gives the gateway
// the account's own namespace when no sandbox of the account is in the
// shared one, and says how to get there otherwise.
func TestDoctorNamesAGatewayOnTheSharedDockerNamespace(t *testing.T) {
	// The healthy fixture's gateway.toml without its namespace: what setup
	// wrote before 1.0.2.
	shared := strings.Replace(enabledTOML, "sandbox_label = \"defenseclaw-u1000\"\n", "", 1)
	if shared == enabledTOML {
		t.Fatal("the fixture names no namespace")
	}
	t.Run("no sandbox: the fix gives the gateway its own namespace", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.writeTOML(shared, f.started.Add(-time.Minute))
		r := f.run()
		c := expectCheck(t, r, openshell.CheckIDDockerNamespace, openshell.StatusWarn, "OpenShell's default Docker sandbox namespace")
		if c.Fix == nil || !c.Fix.Automatic || !c.Fix.RestartsGateway {
			t.Fatalf("fix = %+v, want an automatic one that restarts the gateway", c.Fix)
		}
		applyFixes(t, r, openshell.CheckIDDockerNamespace)
		st, err := f.doctor.Gateway.Read()
		if err != nil || st.DockerNamespace != openshell.AccountDockerNamespace(1000) || !st.BindMounts.Enabled() {
			data, _ := os.ReadFile(filepath.Join(f.dir, "gateway.toml"))
			t.Fatalf("gateway.toml after the fix (%v):\n%s", err, data)
		}
		if !f.runner.Called("systemctl --user restart openshell-gateway") {
			t.Fatal("the gateway was not restarted on its namespace")
		}
		if c := f.run().Get(openshell.CheckIDDockerNamespace); c != nil {
			t.Fatalf("after the fix: %+v", c)
		}
	})
	t.Run("sandboxes in the shared namespace stay, with the way on", func(t *testing.T) {
		f := newDoctorFixture(t)
		f.writeTOML(shared, f.started.Add(-time.Minute))
		defaultNamespaceSandbox(t, f.home)
		c := expectCheck(t, f.run(), openshell.CheckIDDockerNamespace, openshell.StatusWarn, "removes the supervisors of your running sandboxes")
		if c.Fix == nil || c.Fix.Automatic || c.Fix.Apply != nil || !strings.Contains(c.Fix.Summary, "defenseclaw sandbox pull NAME") {
			t.Fatalf("fix = %+v, want the account's own steps first", c.Fix)
		}
	})
	t.Run("a gateway with a namespace of its own is not named", func(t *testing.T) {
		f := newDoctorFixture(t)
		r := f.run()
		if c := r.Get(openshell.CheckIDDockerNamespace); c != nil {
			t.Fatalf("own namespace named: %+v", c)
		}
		st, err := f.doctor.Gateway.Read()
		if err != nil || st.DockerNamespace != "defenseclaw-u1000" || st.SharesDefaultDockerNamespace() {
			t.Fatalf("Read = %+v, %v", st, err)
		}
	})
	t.Run("a namespace setup would not write is refused", func(t *testing.T) {
		f := newDoctorFixture(t)
		if _, err := f.doctor.Gateway.Plan(context.Background(), openshell.GatewayChanges{DockerNamespace: "../default"}); err == nil {
			t.Fatal("a namespace with a path element was planned")
		}
	})
}

func TestDockerNamespaceInUseReadsTheDriversSandboxFolders(t *testing.T) {
	home := t.TempDir()
	state := openshell.UserStateHome(func(string) string { return "" }, home)
	if state != filepath.Join(home, ".local", "state") {
		t.Fatalf("state home = %s", state)
	}
	if got := openshell.UserStateHome(func(string) string { return "/xdg/state" }, home); got != "/xdg/state" {
		t.Fatalf("XDG_STATE_HOME state home = %s", got)
	}
	if openshell.DockerNamespaceInUse(state, openshell.DefaultDockerNamespace) {
		t.Fatal("no gateway state is in use")
	}
	if err := os.MkdirAll(filepath.Join(state, "openshell", "docker-sandbox-tokens", openshell.DefaultDockerNamespace), 0o700); err != nil {
		t.Fatal(err)
	}
	if openshell.DockerNamespaceInUse(state, openshell.DefaultDockerNamespace) {
		t.Fatal("an empty namespace folder is in use")
	}
	defaultNamespaceSandbox(t, home)
	if !openshell.DockerNamespaceInUse(state, openshell.DefaultDockerNamespace) {
		t.Fatal("a sandbox folder is not in use")
	}
	if ns := openshell.AccountDockerNamespace(1001); ns != "defenseclaw-u1001" || ns == openshell.ManagedDockerNamespace {
		t.Fatalf("account namespace = %q", ns)
	}
}
