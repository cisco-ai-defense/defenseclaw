// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

func useConfirmedProductFloor(t *testing.T, floor string, err error) {
	t.Helper()
	previous := confirmedBundleProductFloor
	confirmedBundleProductFloor = func(*enterprisebundle.Store) (string, error) { return floor, err }
	t.Cleanup(func() { confirmedBundleProductFloor = previous })
}

// A device that takes signed bundles refuses a rollback below the release
// the confirmed bundle requires, even a deliberate one; without trust
// anchors the rollback stays the administrator's choice.
func TestRollbackBelowTheConfirmedBundleFloorIsRefused(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			useConfirmedProductFloor(t, "1.0.3", nil)
			writeBundleAnchors(t, h)
			requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), AllowDowngrade: true}), codeProductFloor)
			if record, _ := h.env.loadDeployment(); record.ProductVersion != "1.0.3" {
				t.Fatalf("refused rollback changed the record: %s", record.ProductVersion)
			}
			useConfirmedProductFloor(t, "", errors.New("state unreadable"))
			requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), AllowDowngrade: true}), codeProductFloor)

			// A bundle signed with a lower floor lets the rollback through.
			useConfirmedProductFloor(t, "1.0.2", nil)
			r := h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.2"), AllowDowngrade: true})
			requireOK(t, r)
			if r.InstalledVersion != "1.0.2" {
				t.Fatalf("rollback to the floor installed %q", r.InstalledVersion)
			}
		})
	}
}

// A --keep-state uninstall removes the deployment record but keeps the trust
// anchors and the confirmed bundle; a reinstall below that bundle's floor is
// refused, one at the floor goes through.
func TestKeepStateReinstallBelowTheConfirmedBundleFloorIsRefused(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			writeBundleAnchors(t, h)
			anchors := h.env.bundleAnchorsPath()
			requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
			if record, _ := h.env.loadDeployment(); record != nil {
				t.Fatalf("--keep-state uninstall kept the deployment record: %+v", record)
			}
			if _, err := os.Lstat(anchors); err != nil {
				t.Fatalf("--keep-state uninstall removed the trust anchors: %v", err)
			}
			useConfirmedProductFloor(t, "1.0.3", nil)
			requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.2")}), codeProductFloor)
			if record, _ := h.env.loadDeployment(); record != nil {
				t.Fatalf("refused reinstall wrote a deployment record: %+v", record)
			}
			r := h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")})
			requireOK(t, r)
			if r.InstalledVersion != "1.0.3" {
				t.Fatalf("reinstall at the floor installed %q", r.InstalledVersion)
			}
		})
	}
}

func writeBundleAnchors(t *testing.T, h *testHost) {
	t.Helper()
	anchors := h.env.bundleAnchorsPath()
	if err := os.MkdirAll(filepath.Dir(anchors), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(anchors, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The floor places a candidate version as the bundle verifier does: a
// version that is not a release never meets a floor. Before, the
// lifecycle's own order put dev (and 1.0.4.1, 1.0.x) above 1.0.4, so a dev
// build passed a 1.0.4 floor.
func TestBundleProductFloorRefusesVersionsThatAreNotReleases(t *testing.T) {
	h := newTestHost(t, "linux")
	writeBundleAnchors(t, h)
	useConfirmedProductFloor(t, "1.0.4", nil)
	for version, refused := range map[string]bool{
		"dev": true, "1.0.4.1": true, "1.0.x": true, "1.0.4abc": true, "01.0.4": true, "": true, "1.0": true,
		"1.0.3": true, "1.0.4-rc.1": true, "0.8.10": true,
		"1.0.4": false, "v1.0.4": false, " 1.0.4 ": false, "1.0.4+build.7": false, "1.0.10": false, "2.0.0-rc.1": false,
	} {
		err := h.env.BundleProductFloorRefusal(version)
		if refused && (err == nil || errorCode(err, "") != codeProductFloor) {
			t.Errorf("%q: %v; want %s", version, err, codeProductFloor)
		}
		if !refused && err != nil {
			t.Errorf("%q: %v; want it to meet the floor", version, err)
		}
	}
	if err := h.env.BundleProductFloorRefusal("dev"); err == nil || !strings.Contains(err.Error(), "not a release version") {
		t.Fatalf("dev refusal does not say why: %v", err)
	}
}

// Every install or version change passes the confirmed floor, and so does
// every run of a version that is not a release. Before, only a downgrade
// (by the lifecycle's order) or an install without a record was checked,
// so a staged dev payload, which orders above 1.0.4, replaced a 1.0.4
// deployment under a 1.0.4 floor; a deployment recorded as dev also took
// another dev payload, since the version did not change.
func TestEveryPayloadIsCheckedAgainstTheConfirmedBundleFloor(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
			writeBundleAnchors(t, h)
			useConfirmedProductFloor(t, "1.0.5", nil)
			for _, action := range []string{ActionEnsure, ActionRepair} {
				requireError(t, h.run(Options{Action: action}), codeProductFloor)
			}
			useConfirmedProductFloor(t, "1.0.4", nil)
			for _, opts := range []Options{
				{Action: ActionEnsure, PayloadDir: h.payload("dev")},
				{Action: ActionUpgrade, PayloadDir: h.payload("dev")},
				{Action: ActionRepair, PayloadDir: h.payload("dev")},
				{Action: ActionEnsure, PayloadDir: h.payload("1.0.4.1")},
				{Action: ActionEnsure, PayloadDir: h.payload("dev"), AllowDowngrade: true},
			} {
				requireError(t, h.run(opts), codeProductFloor)
				if record, _ := h.env.loadDeployment(); record.ProductVersion != "1.0.4" {
					t.Fatalf("a refused %s changed the record to %s", opts.Action, record.ProductVersion)
				}
			}
			// An upgrade to a release above the floor and a run that keeps a
			// release go on.
			requireOK(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.5")}))
			requireOK(t, h.run(Options{Action: ActionEnsure}))
			// An upgrade is checked too: a floor that cannot be read refuses it.
			useConfirmedProductFloor(t, "", errors.New("state unreadable"))
			requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.6")}), codeProductFloor)
		})
	}
	t.Run("recorded dev", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("dev")}))
		writeBundleAnchors(t, h)
		useConfirmedProductFloor(t, "1.0.4", nil)
		requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("dev")}), codeProductFloor)
		requireOK(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.4"), AllowDowngrade: true}))
	})
	t.Run("keep-state reinstall", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
		writeBundleAnchors(t, h)
		requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
		useConfirmedProductFloor(t, "1.0.4", nil)
		requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("dev")}), codeProductFloor)
		if record, _ := h.env.loadDeployment(); record != nil {
			t.Fatalf("refused dev reinstall wrote a deployment record: %+v", record)
		}
	})
}

// A run that keeps the recorded release does not check the floor again (the
// bundle was checked against that release when it was applied), so neither a
// floor above it nor a floor that cannot be read stops a repair or a
// same-version ensure. The release-floor reference documents this exception;
// a version change under the same floors is still refused.
func TestSameReleaseRunDoesNotRecheckTheConfirmedBundleFloor(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.4")}))
			writeBundleAnchors(t, h)
			for _, floor := range []struct {
				version string
				err     error
			}{{"1.0.9", nil}, {"", errors.New("state unreadable")}} {
				useConfirmedProductFloor(t, floor.version, floor.err)
				for _, opts := range []Options{
					{Action: ActionEnsure},
					{Action: ActionRepair},
					{Action: ActionEnsure, PayloadDir: h.payload("1.0.4")},
				} {
					requireOK(t, h.run(opts))
				}
				requireError(t, h.run(Options{Action: ActionEnsure, PayloadDir: h.payload("1.0.6")}), codeProductFloor)
				if record, _ := h.env.loadDeployment(); record.ProductVersion != "1.0.4" {
					t.Fatalf("a refused upgrade changed the record to %s", record.ProductVersion)
				}
			}
		})
	}
}

func TestBundleProductFloorNeedsTrustAnchors(t *testing.T) {
	h := newTestHost(t, "linux")
	useConfirmedProductFloor(t, "9.9.9", nil)
	if err := h.env.BundleProductFloorRefusal("1.0.0"); err != nil {
		t.Fatalf("no trust anchors: %v; want no floor", err)
	}
}

// requirePackageFloorCheckScoped fails an operator message that promises a
// package floor check without saying it is in the 1.0.4 and later package
// scripts only: a package older than 1.0.4 runs plain ensure, which has no
// floor check, so it can complete below the floor (rpm, dnf, dpkg -i, the
// macOS Installer).
func requirePackageFloorCheckScoped(t *testing.T, message string) {
	t.Helper()
	for _, want := range []string{"1.0.4 or later package", "a package older than 1.0.4 has no floor check and can complete below the floor"} {
		if !strings.Contains(message, want) {
			t.Fatalf("%q does not say %q", message, want)
		}
	}
	for _, unscoped := range []string{"a package below that floor is refused", "the package scripts run"} {
		if strings.Contains(message, unscoped) {
			t.Fatalf("%q promises the floor check for every package (%q)", message, unscoped)
		}
	}
}

// A non-purge uninstall on a device with bundle trust anchors keeps a
// root-only copy of the deployed gateway, so the package scripts can run
// floor-check once the installed gateway is gone; a committed reinstall
// removes it. No anchors, a purge, or a gateway that is not the recorded
// binary keep none.
func TestNonPurgeUninstallKeepsTheFloorCheckerForThePackageScripts(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			installed := h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway))
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			writeBundleAnchors(t, h)
			r := h.run(Options{Action: ActionUninstall, KeepState: true})
			requireOK(t, r)
			if hasWarning(r, codeFloorCheckerNotKept) {
				t.Fatalf("keep-state uninstall did not keep the floor checker: %+v", r.Warnings)
			}
			kept := ""
			for _, line := range r.Changes {
				if strings.Contains(line, filepath.Join(h.env.Layout.LifecycleDir, floorCheckerDir)) {
					kept = line
				}
			}
			if kept == "" {
				t.Fatalf("the uninstall summary does not name the kept floor checker: %q", r.Changes)
			}
			requirePackageFloorCheckScoped(t, kept)
			if _, err := os.Lstat(installed); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("the installed gateway is still there (%v); the case needs it gone", err)
			}
			checker := h.env.floorCheckerPath()
			got, err := os.ReadFile(checker)
			if err != nil {
				t.Fatalf("no floor checker after a keep-state uninstall: %v", err)
			}
			if string(got) != binGateway+" 1.0.3\n" {
				t.Fatalf("floor checker holds %q, not the deployed gateway", got)
			}
			for path, mode := range map[string]os.FileMode{checker: 0o700, filepath.Dir(checker): 0o700} {
				info, err := os.Lstat(path)
				if err != nil {
					t.Fatal(err)
				}
				if info.Mode().Perm() != mode {
					t.Fatalf("%s mode %v, want %v", path, info.Mode().Perm(), mode)
				}
				if owner, ok := h.owners[path]; ok && owner != [2]int{0, 0} {
					t.Fatalf("%s owned by %v, want root", path, owner)
				}
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
			if _, err := os.Lstat(filepath.Dir(checker)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a committed reinstall kept the floor checker: %v", err)
			}
		})
	}
	t.Run("no anchors", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
		requireOK(t, h.run(Options{Action: ActionUninstall, KeepState: true}))
		if _, err := os.Lstat(h.env.floorCheckerPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("kept a floor checker without trust anchors: %v", err)
		}
	})
	t.Run("purge", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
		writeBundleAnchors(t, h)
		requireOK(t, h.run(Options{Action: ActionUninstall, Purge: true}))
		if _, err := os.Lstat(h.env.floorCheckerPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a purge kept the floor checker: %v", err)
		}
	})
	t.Run("not the recorded gateway", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.3")}))
		writeBundleAnchors(t, h)
		if err := os.WriteFile(h.env.P(filepath.Join(h.env.Layout.BinDir, binGateway)), []byte("replaced\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		r := h.run(Options{Action: ActionUninstall, KeepState: true})
		if !hasWarning(r, codeFloorCheckerNotKept) {
			t.Fatalf("no %s warning for a replaced gateway: %+v", codeFloorCheckerNotKept, r.Warnings)
		}
		for _, w := range r.Warnings {
			if w.Code == codeFloorCheckerNotKept {
				requirePackageFloorCheckScoped(t, w.Message)
				if !strings.Contains(w.Message, "refused only by its postinstall, after its files are in place") {
					t.Fatalf("the %s warning does not say when a 1.0.4 or later package is refused: %q", codeFloorCheckerNotKept, w.Message)
				}
			}
		}
		if _, err := os.Lstat(h.env.floorCheckerPath()); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("kept a gateway the record does not name: %v", err)
		}
	})
}
