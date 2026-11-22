// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// fakeRouteEpochServiceRuntime replaces the managed service runtime writer
// and trust check with plain file writes and a check that returns refuse,
// and records the paths each was called with.
func fakeRouteEpochServiceRuntime(t *testing.T) (wrote, validated *[]string, refuse *error) {
	t.Helper()
	const account = `NT SERVICE\DefenseClawGateway`
	t.Setenv(managed.WindowsServiceAccountEnv, account)
	prevWrite, prevValidate := routeEpochWriteFile, routeEpochValidateFile
	t.Cleanup(func() { routeEpochWriteFile, routeEpochValidateFile = prevWrite, prevValidate })
	wrote, validated, refuse = &[]string{}, &[]string{}, new(error)
	routeEpochWriteFile = func(mode, path, label string, data []byte) error {
		if mode != managed.DeploymentModeManagedEnterprise {
			t.Errorf("service runtime write mode = %q", mode)
		}
		*wrote = append(*wrote, path)
		return os.WriteFile(path, data, 0o600)
	}
	routeEpochValidateFile = func(path, label, serviceAccount string) error {
		if serviceAccount != account {
			t.Errorf("service runtime check account = %q, want the pinned gateway account", serviceAccount)
		}
		*validated = append(*validated, path)
		return *refuse
	}
	return wrote, validated, refuse
}

// rel-1-0-10:GAP-0937: the managed Windows gateway (LocalSystem with a
// write-restricted service SID token) could never publish its route epoch:
// the owner-only protection resets the owner, which that token may not do,
// so every write failed with Access is denied and Setup /ensure ended 1603
// with route_config_drift. The epoch is published and read under the
// managed service runtime contract, which allows the pinned gateway service
// SID as a writer; a file that contract refuses is still refused.
func TestRouteEpochUsesServiceRuntimeContract(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dataDir, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	wrote, validated, refuse := fakeRouteEpochServiceRuntime(t)
	if got, err := LoadRouteEpoch(dataDir); err != nil || got != nil {
		t.Fatalf("absent epoch = (%v, %v), want (nil, nil)", got, err)
	}
	epoch, err := NewRouteEpoch()
	if err != nil {
		t.Fatal(err)
	}
	epoch.Generations["S-1-5-21-1-2-3-1001"] = 2
	if err := WriteRouteEpoch(dataDir, epoch); err != nil {
		t.Fatalf("publication: %v", err)
	}
	path, _ := RouteEpochPath(dataDir)
	if len(*wrote) != 1 || (*wrote)[0] != path {
		t.Fatalf("publication must go through the service runtime writer, got %v", *wrote)
	}
	got, err := LoadRouteEpoch(dataDir)
	if err != nil || got == nil || got.Epoch != epoch.Epoch || got.Generations["S-1-5-21-1-2-3-1001"] != 2 {
		t.Fatalf("read of the published epoch = (%+v, %v)", got, err)
	}
	if len(*validated) != 1 || (*validated)[0] != path {
		t.Fatalf("the read must use the service runtime check, got %v", *validated)
	}

	*refuse = errors.New("owner is not trusted")
	if got, err := LoadRouteEpoch(dataDir); err == nil || got != nil {
		t.Fatalf("an epoch the service runtime check refuses was accepted: (%+v, %v)", got, err)
	}
	*refuse = nil

	if err := WriteRouteEpoch(dataDir, RouteEpoch{Version: 1, Epoch: "short"}); err == nil || len(*wrote) != 1 {
		t.Fatalf("an invalid epoch must not be written (err %v, writes %v)", err, *wrote)
	}
	for _, bad := range []string{`{"version":1,"epoch":"zz"}`, `{"version":2,"epoch":"` + epoch.Epoch + `"}`, `{"version":1,"epoch":"` + epoch.Epoch + `","generations":{"alice":1}}`, `not json`} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadRouteEpoch(dataDir); err == nil {
			t.Fatalf("malformed epoch %q accepted", bad)
		}
	}
	link := path + ".target"
	if err := os.Rename(path, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(link, path); err == nil {
		if _, err := LoadRouteEpoch(dataDir); err == nil {
			t.Fatal("a symlinked route epoch must be refused")
		}
	}
}
