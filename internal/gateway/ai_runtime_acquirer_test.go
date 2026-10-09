// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sensor/acquire"
)

// TestChooseAcquirerKeysOnDeploymentMode pins the one rule left after the
// retired ai_discovery.runtime.acquisition and helper_socket keys: an
// unmanaged gateway reads directly, and a de-privileged managed gateway asks
// the helper at the installer-owned path, whatever its environment says.
func TestChooseAcquirerKeysOnDeploymentMode(t *testing.T) {
	t.Setenv(acquire.SocketEnvVar, filepath.Join(t.TempDir(), "elsewhere.sock"))

	if chooseAcquirer(&config.Config{DataDir: t.TempDir()}).Brokered() {
		t.Fatal("an unmanaged gateway asked a helper, but no helper is installed for it")
	}

	dataDir := t.TempDir()
	managedAcquirer := chooseAcquirer(&config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir})
	if acquire.NewLocal().WideCoverage() {
		// Running as root: the managed gateway can read everything itself.
		if managedAcquirer.Brokered() {
			t.Fatal("a managed gateway with wide coverage added a broker")
		}
		return
	}
	if !managedAcquirer.Brokered() {
		t.Fatal("a de-privileged managed gateway read directly and sees only its own account")
	}
	if got, want := managedAcquirer.Describe(), "brokered via "+acquire.DefaultSocketPath(dataDir, true); got != want {
		t.Fatalf("Describe() = %q, want %q (the environment must not move the managed socket)", got, want)
	}
}
