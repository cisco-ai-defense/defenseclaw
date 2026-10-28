// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
)

// codeProductFloor refuses a downgrade below the release the confirmed
// signed policy bundle requires (its min_product_version).
const codeProductFloor = "product_floor_refused"

// codeFloorCheckerNotKept warns that a non-purge uninstall could not keep
// the floor checker (keepFloorChecker).
const codeFloorCheckerNotKept = "floor_checker_not_kept"

// floorCheckerDir holds the root-only copy of the gateway that answers the
// package scripts' floor-check once the installed gateway is gone.
const floorCheckerDir = "floor-check"

// confirmedBundleProductFloor reads the confirmed bundle's release floor
// (tests replace it).
var confirmedBundleProductFloor = func(s *enterprisebundle.Store) (string, error) { return s.ConfirmedProductFloor() }

// BundleProductFloorRefusal refuses installing DefenseClaw version on a
// device that takes signed bundles (its trust anchors are installed) when
// the confirmed bundle needs a later release, or when that floor cannot be
// read. It places the version as the bundle verifier does
// (enterprisebundle.CheckProductVersion): a version that is not a release
// (dev, 1.0.4.1, 1.0.x) never meets a floor, though the lifecycle's own
// order puts dev above every release. The administrator's rollback marker
// and --allow-downgrade do not lift it: a bundle signed with a lower
// --min-product-version does.
func (e *Env) BundleProductFloorRefusal(version string) error {
	if _, err := os.Lstat(e.bundleAnchorsPath()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return &codedError{code: codeProductFloor, err: fmt.Errorf("cannot check the bundle trust anchors, so the release floor of the confirmed policy bundle is unknown: %w; run `defenseclaw-gateway enterprise bundle anchors install --file <approved-bundle-anchors.json> --json` before retrying", err)}
	}
	floor, err := confirmedBundleProductFloor(e.bundleStore())
	if err != nil {
		return &codedError{code: codeProductFloor, err: fmt.Errorf("cannot read the release floor of the confirmed policy bundle: %w; run `%s --json` with a new signed bundle to replace it before retrying", err, bundleApplyCommand)}
	}
	return bundleProductFloorRefusal(version, floor)
}

// bundleProductFloorRefusal compares a candidate with a proven floor: either
// the readable confirmed bundle or a new bundle verified by this apply run.
func bundleProductFloorRefusal(version, floor string) error {
	if floor == "" {
		return nil
	}
	candidate := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if !enterprisebundle.IsReleaseVersion(candidate) {
		if len(candidate) > 64 {
			candidate = candidate[:64] + "..."
		}
		return &codedError{code: codeProductFloor, err: fmt.Errorf("the signed policy bundle needs DefenseClaw %s or later, and %q is not a release version, so it cannot meet that floor; install a release at or above %s, or deliver a bundle signed without --min-product-version first", floor, candidate, floor)}
	}
	if enterprisebundle.CheckProductVersion(floor, candidate) != nil {
		return &codedError{code: codeProductFloor, err: fmt.Errorf("the signed policy bundle needs DefenseClaw %s or later, and this is %s; to go back, deliver a bundle signed with a lower --min-product-version first", floor, candidate)}
	}
	return nil
}

// floorCheckerPath is the root-only copy of the deployed gateway a non-purge
// uninstall keeps in the lifecycle directory. The Linux and macOS package
// scripts run its floor-check when the installed gateway is gone (after
// uninstall --keep-state, or an uninstall that failed after it removed the
// binaries), so a package below the confirmed bundle's floor is refused
// before its files land. It keeps the gateway's own name: the binary picks
// its command tree by that name (launcher.go).
func (e *Env) floorCheckerPath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), floorCheckerDir, binGateway)
}

// keepFloorChecker copies the deployed gateway to floorCheckerPath while the
// bundle trust anchors are installed (an unreadable anchors path counts as
// installed, as in BundleProductFloorRefusal) and reports whether it did.
// Only the binary the deployment record names is kept.
func (e *Env) keepFloorChecker(record *Deployment) (bool, error) {
	if _, err := os.Lstat(e.bundleAnchorsPath()); errors.Is(err, fs.ErrNotExist) {
		return false, e.removeFloorChecker()
	}
	installed := filepath.Join(e.Layout.BinDir, binGateway)
	src := e.P(installed)
	if record != nil {
		if want := record.Files[installed]; want != "" {
			got, err := sha256File(src)
			if err != nil {
				return false, err
			}
			if got != want {
				return false, fmt.Errorf("%s is not the gateway binary the deployment record names", installed)
			}
		}
	}
	if err := e.ensureDir(filepath.Dir(e.floorCheckerPath()), 0o700, rootOwner()); err != nil {
		return false, err
	}
	if err := e.copyFileAtomic(src, e.floorCheckerPath(), 0o700, rootOwner()); err != nil {
		return false, err
	}
	return true, nil
}

// removeFloorChecker removes the kept floor checker; a committed deployment
// has its installed gateway again.
func (e *Env) removeFloorChecker() error {
	return os.RemoveAll(filepath.Dir(e.floorCheckerPath()))
}
