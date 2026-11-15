// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// rel-1-0-10:GAP-0937: the managed Windows gateway (LocalSystem with a
// write-restricted service SID token) could never publish its route epoch:
// the owner-only protection resets the owner, which that token may not do,
// so every write failed with Access is denied and Setup /ensure ended 1603
// with route_config_drift. On a managed Windows gateway the epoch is
// published and read under the managed service runtime contract, which
// allows the pinned gateway service SID as a writer; a file the contract
// refuses is still refused.
func TestManagedWindowsRouteEpochUsesServiceRuntimeContract(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	const account = `NT SERVICE\DefenseClawGateway`
	t.Setenv(managed.WindowsServiceAccountEnv, account)
	prevRuntime, prevWrite, prevValidate := routeEpochServiceRuntime, routeEpochWriteServiceRuntimeFile, routeEpochValidateServiceRuntimeFile
	t.Cleanup(func() {
		routeEpochServiceRuntime, routeEpochWriteServiceRuntimeFile, routeEpochValidateServiceRuntimeFile = prevRuntime, prevWrite, prevValidate
	})
	routeEpochServiceRuntime = func() bool { return true }
	var wrote, validated []string
	routeEpochWriteServiceRuntimeFile = func(mode, path, label string, data []byte) error {
		if mode != managed.DeploymentModeManagedEnterprise {
			t.Errorf("service runtime write mode = %q", mode)
		}
		wrote = append(wrote, path)
		// The shape the installer runtime DACL gives a gateway-written file:
		// a second writer (the gateway service SID), which the owner-only
		// private file rule refuses.
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return err
		}
		return os.Chmod(path, 0o660)
	}
	var refuse error
	routeEpochValidateServiceRuntimeFile = func(path, label, serviceAccount string) error {
		if serviceAccount != account {
			t.Errorf("service runtime check account = %q, want the pinned gateway account", serviceAccount)
		}
		validated = append(validated, path)
		return refuse
	}

	epoch, err := NewRouteEpoch()
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteRouteEpoch(dataDir, epoch); err != nil {
		t.Fatalf("managed publication: %v", err)
	}
	path, _ := RouteEpochPath(dataDir)
	if len(wrote) != 1 || wrote[0] != path {
		t.Fatalf("managed publication must go through the service runtime writer, got %v", wrote)
	}
	got, err := LoadRouteEpoch(dataDir)
	if err != nil || got == nil || got.Epoch != epoch.Epoch {
		t.Fatalf("managed read of a gateway-written epoch = (%+v, %v)", got, err)
	}
	if len(validated) != 1 || validated[0] != path {
		t.Fatalf("managed read must use the service runtime check, got %v", validated)
	}

	refuse = errors.New("owner is not trusted")
	if got, err := LoadRouteEpoch(dataDir); err == nil || got != nil {
		t.Fatalf("an epoch the service runtime check refuses was accepted: (%+v, %v)", got, err)
	}
}

// Off a managed Windows gateway the epoch keeps the owner-only rule.
func TestRouteEpochServiceRuntimeOnlyOnManagedWindows(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if got, want := routeEpochServiceRuntime(), runtime.GOOS == "windows"; got != want {
		t.Fatalf("managed pin: routeEpochServiceRuntime = %v, want %v", got, want)
	}
	t.Setenv(managed.DeploymentModeEnv, "")
	if routeEpochServiceRuntime() {
		t.Fatal("without the managed pin the route epoch must keep the owner-only rule")
	}
}
